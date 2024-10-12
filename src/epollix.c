#include "../include/epollix.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <solidc/cstr.h>
#include <solidc/filepath.h>
#include <solidc/thread.h>
#include <solidc/threadpool.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <unistd.h>

#define MAX_READ_TASKS (MAXEVENTS * 2)

typedef struct read_task {
    int epoll_fd;    // Epoll file descriptor
    int client_fd;   // Client file descriptor
    int index;       // Index of the task in the tasks array. -1 means task if free.
    request_t* req;  // Request object
} read_task;

// ===================================================================================
static cleanup_func user_cleanup_func = NULL;       // User-defined cleanup function
int epoll_fd = -1;                                  // epoll file descriptor
int server_fd = -1;                                 // server file descriptor
ThreadPool* pool = NULL;                            // Thread pool for handling requests
static read_task read_tasks[MAX_READ_TASKS] = {0};  // Pool of read tasks
pthread_mutex_t read_tasks_mutex = PTHREAD_MUTEX_INITIALIZER;
// ===================================================================================

// Sends an error message to the client before the request is parsed.
void http_error(int client_fd, http_status status, const char* message) {
    char* reply = NULL;
    const char* status_str = http_status_text(status);
    char* fmt = "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n";

    int ret = asprintf(&reply, fmt, status, status_str, strlen(message), message);
    if (ret == -1) {
        LOG_ERROR(ERR_MEMORY_ALLOC_FAILED);
        return;
    }

    sendall(client_fd, reply, strlen(reply));
    free(reply);
}

void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
    client_fd = -1;
}

void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        LOG_INFO("Received signal %s\n", strsignal(sig));
        exit(EXIT_FAILURE);
    }
}

static void install_signal_handler(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // See man 2 sigaction for more information.
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        LOG_FATAL("unable to call sigaction\n");
    };

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
}

bool set_header(context_t* ctx, const char* name, const char* value) {
    // Check if this header already exists
    int index = find_header_index(ctx->headers, ctx->header_count, name);
    if (index == -1) {
        header_t* header = header_new(name, value);
        if (header == NULL) {
            LOG_ERROR("header_new() failed");
            return false;
        }
        ctx->headers[ctx->header_count++] = header;
    } else {
        // Replace header value
        header_t* h = ctx->headers[index];

        // Copy the new value to the header
        strncpy(h->value, value, MAX_HEADER_VALUE - 1);
        h->value[MAX_HEADER_VALUE - 1] = '\0';
    }
    return true;
}

const Route* get_current_route(context_t* ctx) {
    return ctx->request->route;
}

void set_status(context_t* ctx, http_status status) {
    ctx->status = status;
}

const char* get_param(context_t* ctx, const char* name) {
    return get_path_param(ctx->request->route->params, name);
}

// Get response status code.
http_status get_status(context_t* ctx) {
    return ctx->status;
}

const char* get_content_type(context_t* ctx) {
    return find_header(ctx->request->headers, ctx->request->header_count, CONTENT_TYPE_HEADER);
}

// Convert a header to a string, appending CRLF after the value.
// Returns a dynamically allocated string that the caller must free.
char* header_tostring(const header_t* h) {
    size_t len = strlen(h->name) + strlen(h->value) + 5;  // 5 is for ": " and "\r\n" and null terminator
    char* buf = (char*)malloc(len);
    if (buf == NULL) {
        LOG_ERROR("malloc failed");
        return NULL;
    }
    snprintf(buf, len, "%s: %s\r\n", h->name, h->value);
    buf[len - 1] = '\0';
    return buf;
}

// Headers and request itself are allocated from the memory pool.
static void reset_request(request_t* req) {
    close_connection(req->client_fd, req->epoll_fd);

    // Free memory for the request path
    if (req->path) {
        free(req->path);
        req->path = NULL;
    }

    // Free memory for the request body
    if (req->body) {
        free(req->body);
        req->body = NULL;
    }

    // Free the query parameters
    if (req->query_params) {
        map_destroy(req->query_params, true);
    }
}

// Free epollix context resources.
void free_context(context_t* ctx) {
    if (!ctx) {
        return;
    }

    // Free the response headers
    if (ctx->headers) {
        for (size_t i = 0; i < ctx->header_count; i++) {
            free(ctx->headers[i]);
        }

        free(ctx->headers);
        ctx->headers = NULL;
    }

    // free the request
    reset_request(ctx->request);

    // Free the locals map
    if (ctx->locals) {
        map_destroy(ctx->locals, true);
        ctx->locals = NULL;
    }
}

// Add a value to the context. This is useful for sharing data between middleware.
void set_context_value(context_t* ctx, const char* key, void* value) {
    char* k = strdup(key);
    if (!k) {
        LOG_ERROR("unable to allocate memory for key: %s", key);
        return;
    }
    map_set(ctx->locals, k, value);
}

// Get a value from the context. Returns NULL if the key does not exist.
void* get_context_value(context_t* ctx, const char* key) {
    return map_get(ctx->locals, (char*)key);
}

// Allocate response headers.
bool allocate_headers(context_t* ctx) {
    ctx->headers = (header_t**)malloc(MAX_RES_HEADERS * sizeof(header_t*));
    if (ctx->headers == NULL) {
        LOG_ERROR("malloc headers failed");
        return false;
    }
    memset(ctx->headers, 0, MAX_RES_HEADERS * sizeof(header_t*));
    ctx->header_count = 0;
    ctx->headers_sent = false;
    return true;
}

static void handle_write(request_t* req) {
    // Initialize response
    context_t ctx = {};
    ctx.request = req;
    ctx.status = StatusOK;
    ctx.headers_sent = false;
    ctx.chunked = false;

    Route* route = req->route;

    // Initialize response headers
    if (!allocate_headers(&ctx)) {
        http_error(req->client_fd, StatusInternalServerError, "error allocating response headers");
        reset_request(req);
        return;
    }

    // Initialize locals map with a capacity of 8
    ctx.locals = map_create(8, key_compare_char_ptr);
    if (!ctx.locals) {
        LOG_ERROR("unable to create map for locals");
        http_error(req->client_fd, StatusInternalServerError, "error creating locals map");
        reset_request(req);
        return;
    }

    // Define middleware context
    MiddlewareContext mw_ctx = {0};
    uint8_t combined_count = 0;
    ctx.mw_ctx = &mw_ctx;

    // Combine global and route specific middleware
    Middleware* cmw = apply_middleware(route, &mw_ctx, &combined_count);
    if (cmw == NULL) {
        http_error(req->client_fd, StatusInternalServerError, "error allocating middleware");
        reset_request(req);
        return;
    }

    // Execute middleware chain
    execute_middleware(&ctx, cmw, combined_count, 0, route->handler);

    // Free combined middleware
    free(cmw);

    free_context(&ctx);
}

ssize_t sendall(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    size_t remaining = n;
    const char* data = (const char*)buf;

    // Send data in 4K chunks
    while (remaining > 0) {
        size_t chunk_size = remaining < 4096 ? remaining : 4096;

        ssize_t bytes_sent = send(fd, data + sent, chunk_size, MSG_NOSIGNAL);
        if (bytes_sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry after a short delay (consider using poll or epoll for efficiency)
                usleep(100);  // 100 microseconds
                continue;
            } else {
                return -1;
            }
        }
        sent += (size_t)bytes_sent;
        remaining -= (size_t)bytes_sent;
    }
    return sent;
}

static void write_headers(context_t* ctx) {
    if (ctx->headers_sent)
        return;

    // Set default status code
    if (ctx->status == 0) {
        ctx->status = StatusOK;
    }

    char header_res[MAX_RES_HEADER_SIZE];
    size_t remaining = sizeof(header_res);
    char* current = header_res;

    // Write status line
    int ret = snprintf(current, remaining, "HTTP/1.1 %u %s\r\n", ctx->status, http_status_text(ctx->status));
    if (ret < 0 || (size_t)ret >= remaining) {
        LOG_ERROR("Status line truncated or error occurred");
        return;
    }
    current += ret;
    remaining -= ret;

    // Add headers
    for (size_t i = 0; i < ctx->header_count; i++) {
        ret = snprintf(current, remaining, "%s: %s\r\n", ctx->headers[i]->name, ctx->headers[i]->value);
        if (ret < 0 || (size_t)ret >= remaining) {
            LOG_ERROR("Header truncated or error occurred");
            return;
        }
        current += ret;
        remaining -= ret;
    }

    // Append the end of the headers
    if (remaining < 3) {
        LOG_ERROR("No space for final CRLF");
        return;
    }
    memcpy(current, "\r\n", 2);
    current += 2;
    *current = '\0';

    // Send the response headers
    int nbytes_sent = sendall(ctx->request->client_fd, header_res, strlen(header_res));
    if (nbytes_sent == -1) {
        if (errno == EBADF) {
            // Can happend if the client closes the connection before the response is sent.
            // we can safely ignore this error.
        } else {
            LOG_ERROR("%s, fd: %d", strerror(errno), ctx->request->client_fd);
        }
    }
    ctx->headers_sent = nbytes_sent != -1;
}

// Send the response to the client.
// Returns the number of bytes sent or -1 on error.
int send_response(context_t* ctx, const char* data, size_t len) {
    char content_len[24];
    int ret = snprintf(content_len, sizeof(content_len), "%ld", len);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        LOG_ERROR("Warning: send_response(): truncation of content_len");
    }

    set_header(ctx, "Content-Length", content_len);
    write_headers(ctx);
    return sendall(ctx->request->client_fd, data, len);
}

int send_json(context_t* ctx, const char* data, size_t len) {
    set_header(ctx, CONTENT_TYPE_HEADER, "application/json");
    return send_response(ctx, data, len);
}

// Send null-terminated JSON string.
int send_json_string(context_t* ctx, const char* data) {
    return send_json(ctx, data, strlen(data));
}

int send_string(context_t* ctx, const char* data) {
    return send_response(ctx, data, strlen(data));
}

__attribute__((format(printf, 2, 3))) int send_string_f(context_t* ctx, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char* buffer = NULL;

    // Determine the required buffer size
    // See man vsnprintf for more information
    int len = vsnprintf(buffer, 0, fmt, args);
    va_end(args);

    if (len < 0) {
        // there was an error in formatting the string
        return -1;
    }

    // Allocate a buffer of the required size
    buffer = (char*)malloc(len + 1);  // +1 for the null terminator
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    // Format the string into the allocated buffer
    va_start(args, fmt);
    vsnprintf(buffer, len + 1, fmt, args);
    va_end(args);

    // Send the response
    int result = send_response(ctx, buffer, len);

    // Free the allocated buffer
    free(buffer);
    return result;
}

// Writes chunked data to the client.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
int response_send_chunk(context_t* ctx, const char* data, size_t len) {
    if (!ctx->headers_sent) {
        ctx->status = StatusOK;
        set_header(ctx, "Transfer-Encoding", "chunked");
        write_headers(ctx);
    }

    // Send the chunked header
    char chunked_header[32] = {0};
    int ret = snprintf(chunked_header, sizeof(chunked_header), "%zx\r\n", len);
    if (ret >= (int)sizeof(chunked_header)) {
        LOG_ERROR("chunked header truncated");
        // end the chunked response
        response_end(ctx);
        return -1;
    }

    int nbytes_sent = send(ctx->request->client_fd, chunked_header, strlen(chunked_header), MSG_NOSIGNAL);
    if (nbytes_sent == -1) {
        perror("error sending chunked header");
        response_end(ctx);
        return -1;
    }

    // Send the chunked data
    nbytes_sent = sendall(ctx->request->client_fd, data, len);
    if (nbytes_sent == -1) {
        perror("error sending chunked data");
        response_end(ctx);
        return -1;
    }

    // Send end of chunk: Send the chunk's CRLF (carriage return and line feed)
    if (send(ctx->request->client_fd, "\r\n", 2, MSG_NOSIGNAL) == -1) {
        perror("error send end of chunk sentinel");
        response_end(ctx);
        return false;
    };
    return nbytes_sent;
}

// End the chunked response. Must be called after all chunks have been sent.
int response_end(context_t* ctx) {
    int nbytes_sent = sendall(ctx->request->client_fd, "0\r\n\r\n", 5);
    if (nbytes_sent == -1) {
        perror("error sending end of chunked response");
        return -1;
    }
    return nbytes_sent;
}

// redirect to the given url with a 302 status code
void response_redirect(context_t* ctx, const char* url) {
    if (ctx->status < StatusMovedPermanently || ctx->status > StatusPermanentRedirect) {
        ctx->status = StatusSeeOther;
    }

    set_header(ctx, "Location", url);
    write_headers(ctx);
}

// Write headers for the Content-Range and Accept-Ranges.
// Also sets the status code for partial content.
static void send_range_headers(context_t* ctx, ssize_t start, ssize_t end, off64_t file_size) {
    int ret;
    char content_len[24];
    ret = snprintf(content_len, sizeof(content_len), "%ld", end - start + 1);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        LOG_FATAL("send_range_headers(): truncation of content_len\n");
    }

    set_header(ctx, "Accept-Ranges", "bytes");
    set_header(ctx, "Content-Length", content_len);

    char content_range_str[128];
    ret = snprintf(content_range_str, sizeof(content_range_str), "bytes %ld-%ld/%ld", start, end, file_size);
    // This invariant must be respected.
    if (ret >= (int)sizeof(content_range_str)) {
        LOG_FATAL("send_range_headers(): truncation of content_range_str\n");
    }

    set_header(ctx, "Content-Range", content_range_str);
    ctx->status = StatusPartialContent;
}

// serve a file with support for partial content specified by the "Range" header.
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
int http_servefile(context_t* ctx, const char* filename) {
    // Guess content-type if not already set
    if (find_header(ctx->headers, ctx->header_count, CONTENT_TYPE_HEADER) == NULL) {
        set_header(ctx, CONTENT_TYPE_HEADER, get_mimetype((char*)filename));
    }

    ssize_t start = 0, end = 0;
    const char* range_header = NULL;
    bool is_range_request = false;
    bool has_end_range = false;

    range_header = find_header(ctx->request->headers, ctx->request->header_count, "Range");
    if (range_header) {
        if (strstr(range_header, "bytes=") != NULL) {
            if (sscanf(range_header, "bytes=%ld-%ld", &start, &end) == 2) {
                is_range_request = true;
                has_end_range = true;
            } else if (sscanf(range_header, "bytes=%ld-", &start) == 1) {
                is_range_request = true;
                has_end_range = false;
            };
        }
    }

    // Open the file with fopen64 to support large files
    FILE* file = fopen64(filename, "rb");
    if (file == NULL) {
        LOG_ERROR("Unable to open file: %s", filename);
        ctx->status = StatusInternalServerError;
        write_headers(ctx);
        return -1;
    }

    // Get the file size
    fseeko64(file, 0, SEEK_END);
    off64_t file_size = ftello64(file);
    fseeko64(file, 0, SEEK_SET);

    // Set appropriate headers for partial content
    if (is_range_request) {
        if (start >= file_size) {
            ctx->status = StatusRequestedRangeNotSatisfiable;
            fclose(file);
            write_headers(ctx);
            return -1;
        }

        // Send the requested range in chunks of 4MB
        ssize_t byteRangeSize = (4 * 1024 * 1024) - 1;
        if (!has_end_range && start >= 0) {
            end = start + byteRangeSize;
        } else if (start < 0) {
            // Http range requests can be negative :) Wieird but true
            // I had to read the RFC to understand this, who would have thought?
            // https://datatracker.ietf.org/doc/html/rfc7233
            start = file_size + start;    // subtract from the file size
            end = start + byteRangeSize;  // send the next 4MB if not more than the file size
        } else if (end < 0) {
            // Even the end range can be negative. Deal with it!
            end = file_size + end;
        }

        // Ensure the end of the range doesn't exceed the file size
        if (end >= file_size) {
            end = file_size - 1;
        }

        // Ensure the start and end range are within the file size
        if (start < 0 || end < 0 || end >= file_size) {
            ctx->status = StatusRequestedRangeNotSatisfiable;
            fclose(file);
            write_headers(ctx);
            return -1;
        }

        send_range_headers(ctx, start, end, file_size);

        // Move file position to the start of the requested range
        if (fseeko64(file, start, SEEK_SET) != 0) {
            ctx->status = StatusRequestedRangeNotSatisfiable;
            perror("fseeko64");
            fclose(file);
            return -1;
        }
    } else {
        // Set the content length header for the non-range request
        char content_len_str[32];
        if (snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size) < 0) {
            perror("snprintf");
            fclose(file);
            return -1;
        }

        // Set the content length header if it's not a range request
        set_header(ctx, "Content-Length", content_len_str);
    }

    if (!is_range_request) {
        // Set content disposition
        char content_disposition[512] = {0};
        char base_name[256] = {0};
        filepath_basename(filename, base_name, sizeof(base_name));
        snprintf(content_disposition, sizeof(content_disposition), "inline; filename=\"%s\"", base_name);
        set_header(ctx, "Content-Disposition", content_disposition);
    }

    write_headers(ctx);

    ssize_t total_bytes_sent = 0;   // Total bytes sent to the client
    off64_t buffer_size = 2 << 20;  // 2MB buffer size

    if (is_range_request) {
        // Ensure the buffer size doesn't exceed the remaining bytes in the requested range
        off64_t remaining_bytes = (end - start + 1);  // +1 to include the end byte

        //Adjust the buffer size to the remaining bytes if it's less than the buffer size
        buffer_size = remaining_bytes < buffer_size ? remaining_bytes : buffer_size;
    } else {
        // Set the buffer size to the file size if it's less than the buffer size
        buffer_size = file_size < buffer_size ? file_size : buffer_size;
    }

    // Offset to start reading the file from
    off_t offset = start;
    ssize_t sent_bytes = -1;
    int file_fd = fileno(file);
    int max_range = end - start + 1;

    // Enbale TCP_CORK to avoid sending small packets
    int flag = 1;
    setsockopt(ctx->request->client_fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));

    // Send the file using sendfile to avoid copying data from the kernel to user space
    // This is more efficient than read/write
    // See man sendfile(2) for more information
    while (total_bytes_sent < file_size || (is_range_request && total_bytes_sent < max_range)) {
        sent_bytes = sendfile(ctx->request->client_fd, file_fd, &offset, buffer_size);
        if (sent_bytes > 0) {
            total_bytes_sent += sent_bytes;

            // If it's a range request, and we've sent the requested range, break out of
            // the loop
            if (is_range_request && total_bytes_sent >= max_range) {
                break;
            }

            // Update the remaining bytes based on the data sent to the client.
            if (is_range_request) {
                off64_t remaining_bytes = max_range - total_bytes_sent;

                // Adjust the buffer size to the remaining bytes if it's less than the buffer size
                buffer_size = remaining_bytes < buffer_size ? remaining_bytes : buffer_size;
            }
        } else if (sent_bytes == -1) {
            // Handle potential sendfile errors
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry sendfile after a short delay
                usleep(1000);  // 1ms delay

                // Continue the loop and retry sending the current buffer
                continue;
            } else {
                if (errno == EPIPE) {
                    // client disconnected. Nothing to report
                } else {
                    perror("sendfile");
                }
                fclose(file);
                return -1;
            }
        }
    }

    if (sent_bytes == -1) {
        if (errno == EPIPE) {
            // client disconnected. Nothing to report
        } else {
            perror("sendfile");
        }

        fclose(file);
        return -1;
    }

    fclose(file);
    return total_bytes_sent;
}

static int set_nonblocking(int sfd) {
    int flags, s;

    flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sfd, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

static int setup_server_socket(const char* port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        LOG_ERROR("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        // Allow reuse of the port.
        int enable = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror("setsockopt");
            LOG_FATAL("setsockopt(): new_tcpserver failed\n");
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        LOG_ERROR("Could not bind");
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}

// ================== End middleware logic ==============

void set_content_type(context_t* ctx, const char* content_type) {
    set_header(ctx, CONTENT_TYPE_HEADER, content_type);
}

// ============= route group ==============

// Create a new RouteGroup.
RouteGroup* route_group(const char* pattern) {
    RouteGroup* group = (RouteGroup*)malloc(sizeof(RouteGroup));
    if (!group) {
        LOG_FATAL("Failed to allocate memory for RouteGroup\n");
    }

    group->prefix = strdup(pattern);
    if (!group->prefix) {
        LOG_FATAL("Failed to allocate memory for RouteGroup prefix\n");
    }

    group->middleware_count = 0;
    group->count = 0;
    group->middleware = NULL;
    group->middleware_count = 0;
    group->routes = NULL;
    return group;
}

void route_group_free(RouteGroup* group) {
    // Free the group prefix
    free(group->prefix);
    if (group->middleware) {
        free(group->middleware);
    }

    if (group->routes) {
        // The individual routes are freed in free_static_routes
        free(group->routes);
        group->routes = NULL;
    }
    free(group);
}

// Attach route group middleware.
void use_group_middleware(RouteGroup* group, int count, ...) {
    if (count <= 0) {
        return;
    }

    uint8_t new_count = group->middleware_count + (uint8_t)count;
    Middleware* new_middleware = (Middleware*)realloc(group->middleware, sizeof(Middleware) * (size_t)new_count);
    if (!new_middleware) {
        LOG_FATAL("Failed to allocate memory for group middleware\n");
    }

    group->middleware = new_middleware;

    va_list args;
    va_start(args, count);
    for (size_t i = group->middleware_count; i < new_count; i++) {
        ((Middleware*)(group->middleware))[i] = va_arg(args, Middleware);
    }
    group->middleware_count = new_count;
    va_end(args);
}

//=======================================

// format_file_size returns a human-readable string representation of the file size.
// The function returns a pointer to a static buffer that is overwritten on each call.
// This means that it is not thread-safe.
const char* format_file_size(off_t size) {
    static char buf[32];
    char units[][3] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    int i = 0;
    double s = size;

    while (s >= 1024 && i < 8) {
        s /= 1024;
        i++;
    }

    if (i == 0) {
        snprintf(buf, sizeof(buf), "%ld %s", (long)size, units[i]);
    } else {
        snprintf(buf, sizeof(buf), "%.0f %s", s, units[i]);
    }
    return buf;
}

static void enable_keepalive(int sockfd) {
    int keepalive = 1;  // Enable keepalive
    int keepidle = 60;  // 60 seconds before sending keepalive probes
    int keepintvl = 5;  // 5 seconds interval between keepalive probes
    int keepcnt = 3;    // 3 keepalive probes before closing the connection

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }
}

char* get_ip_address(context_t* ctx) {
    // try the forwarded header
    const char* ip_addr = find_header(ctx->request->headers, ctx->request->header_count, "X-Forwarded-For");
    if (!ip_addr) {
        // try the real ip address
        ip_addr = find_header(ctx->request->headers, ctx->request->header_count, "X-Real-IP");
    }

    if (!ip_addr) {
        // use peer address
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        getpeername(ctx->request->client_fd, (struct sockaddr*)&addr, &len);

        char ipstr[INET6_ADDRSTRLEN];
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in* s = (struct sockaddr_in*)&addr;
            inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
        } else {  // AF_INET6
            struct sockaddr_in6* s = (struct sockaddr_in6*)&addr;
            inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
        }

        return strdup(ipstr);
    }
    return strdup(ip_addr);
}

static void init_read_tasks(void) {
    for (size_t i = 0; i < MAX_READ_TASKS; i++) {
        memset(&read_tasks[i], -1, sizeof(read_task));
        // init request object
        read_tasks[i].req = (request_t*)malloc(sizeof(request_t));
        if (!read_tasks[i].req) {
            LOG_FATAL("Failed to allocate memory for request object\n");
        }

        memset(read_tasks[i].req, 0, sizeof(request_t));

        // Allocate memory for the request headers
        read_tasks[i].req->headers = (header_t**)malloc(sizeof(header_t*) * MAX_REQ_HEADERS);
        if (!read_tasks[i].req->headers) {
            LOG_FATAL("Failed to allocate memory for request headers\n");
        }

        // Pre-allocate all the headers.
        for (size_t j = 0; j < MAX_REQ_HEADERS; j++) {
            read_tasks[i].req->headers[j] = (header_t*)malloc(sizeof(header_t));
            if (!read_tasks[i].req->headers[j]) {
                LOG_FATAL("Failed to allocate memory for request header\n");
            }
        }
    }
}

void free_read_tasks(void) {
    for (size_t i = 0; i < MAX_READ_TASKS; i++) {
        if (read_tasks[i].req) {
            for (size_t j = 0; j < MAX_REQ_HEADERS; j++) {
                if (read_tasks[i].req->headers[j]) {
                    free(read_tasks[i].req->headers[j]);
                }
            }
            free(read_tasks[i].req->headers);
            free(read_tasks[i].req);
        }
    }
}

static read_task* get_read_task(void) {
    pthread_mutex_lock(&read_tasks_mutex);
    for (size_t i = 0; i < MAX_READ_TASKS; i++) {
        if (read_tasks[i].index == -1) {
            read_tasks[i].index = i;
            pthread_mutex_unlock(&read_tasks_mutex);
            return &read_tasks[i];
        }
    }
    pthread_mutex_unlock(&read_tasks_mutex);
    return NULL;
}

// Put the read task back in the pool without freeing the request object.
static void put_read_task(read_task* task) {
    pthread_mutex_lock(&read_tasks_mutex);

    // Reset header count.
    task->req->header_count = 0;

    task->client_fd = -1;
    task->epoll_fd = -1;
    task->index = -1;
    pthread_mutex_unlock(&read_tasks_mutex);
}

static void submit_read_task(void* arg) {
    read_task* task = (read_task*)arg;
    task->req->client_fd = task->client_fd;
    task->req->epoll_fd = task->epoll_fd;
    handle_request(task->req);

    if (task->req->route != NULL && task->client_fd != -1) {
        handle_write(task->req);
    }

    // Put the task back in the pool
    put_read_task(task);
}

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_threads is 0, we use the num_cpus on the target machine.
int listen_and_serve(const char* port, size_t num_workers, cleanup_func cf) {
    LOG_ASSERT(port != NULL, "port is NULL but expected to be a valid port number");

    init_read_tasks();
    user_cleanup_func = cf;

    int ret;
    struct epoll_event event = {0}, events[MAXEVENTS] = {0};

    server_fd = setup_server_socket(port);
    if (server_fd == -1) {
        LOG_FATAL("Failed to setup server socket\n");
    }

    enable_keepalive(server_fd);

    ret = set_nonblocking(server_fd);
    if (ret == -1) {
        LOG_FATAL("Failed to set non-blocking on server socket\n");
    }

    ret = listen(server_fd, MAXEVENTS);
    if (ret == -1) {
        perror("listen");
        LOG_FATAL("Failed to listen on server socket\n");
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create");
        LOG_FATAL("Failed to create epoll instance\n");
    }

    event.data.fd = server_fd;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        LOG_FATAL("Failed to add server socket to epoll\n");
    }

    int nworkers = get_ncpus();
    if (num_workers > 0) {
        nworkers = num_workers;
    }

    printf("[PID: %d]\n", get_gid());
    printf("[Server listening on port http://0.0.0.0:%s with %d threads]\n", port, nworkers);

    // log max allowed file descriptors for the process

    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd == -1) {
        perror("sysconf");
    } else {
        printf("[Max file descriptors allowed: %ld]\n", maxfd);
    }

    // Create a threadpool with n threads
    pool = threadpool_create(nworkers);
    LOG_ASSERT(pool, "Failed to create threadpool\n");

    /* The event loop */
    while (true) {
        int nfds = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (server_fd == events[i].data.fd) {
                while (1) {
                    struct sockaddr internetAddress;
                    socklen_t client_len;
                    int client_fd;
                    client_len = sizeof internetAddress;
                    client_fd = accept(server_fd, &internetAddress, &client_len);
                    if (client_fd == -1) {
                        if (errno == EINTR) {
                            return -1;  // Interrupted by signal
                        }

                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;  // No more incoming connections
                        }

                        perror("accept");
                        break;
                    }

                    ret = set_nonblocking(client_fd);
                    if (ret == -1) {
                        LOG_ERROR("Failed to set non-blocking on client socket\n");
                        continue;
                    }

                    event.data.fd = client_fd;
                    event.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR | EPOLLONESHOT;
                    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
                    if (ret == -1) {
                        perror("epoll_ctl");
                        LOG_ERROR("epoll_ctl failed");
                        continue;
                    }

                    // Disable Nagle's algorithm for the client socket
                    int flag = 1;
                    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

                    // Enable keepalive for the client socket
                    enable_keepalive(client_fd);

                    struct timeval timeout;
                    timeout.tv_sec = 5;  // 5 seconds timeout
                    timeout.tv_usec = 0;
                    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
                }
            } else {
                // client socket is ready for reading
                if (events[i].events & EPOLLIN) {
                    read_task* task = get_read_task();  // Get a free read task from the pool
                    if (!task) {
                        LOG_ERROR("Failed to get a free task from the pool");
                        http_error(events[i].data.fd, StatusInternalServerError, "Internal server error");
                        close_connection(events[i].data.fd, epoll_fd);
                        continue;
                    }

                    task->client_fd = events[i].data.fd;
                    task->epoll_fd = epoll_fd;
                    threadpool_add_task(pool, submit_read_task, task);
                } else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                    close_connection(events[i].data.fd, epoll_fd);
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

// Constructor attribute for gcc and clang.
__attribute__((constructor())) void init(void) {
    middleware_init();
    install_signal_handler();
}

// Destructor extension for gcc and clang.
// This is automatically called at exit.
__attribute__((destructor)) void epollix_cleanup(void) {
    routes_cleanup();
    free_read_tasks();
    middleware_cleanup();

    if (pool)
        threadpool_destroy(pool);

    if (epoll_fd != -1)
        close(epoll_fd);

    if (server_fd != -1)
        close(server_fd);

    if (user_cleanup_func)
        user_cleanup_func();
}
