#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 200809L

#include "../include/response.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <solidc/filepath.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../include/request.h"

// Create a new response object.
Response* allocate_response(int client_fd) {
    Response* res = calloc(1, sizeof(Response));
    if (res) {
        res->client_fd = client_fd;
        res->status = StatusOK;
        res->data = NULL;
        res->headers = (header_t**)calloc(MAX_RES_HEADERS, sizeof(header_t*));
        if (res->headers) {
            res->header_count = 0;
            res->headers_sent = false;
        } else {
            perror("calloc");
            free(res);
        }
    }
    return res;
}

// Free response obj
void free_reponse(Response* res) {
    if (!res)
        return;

    for (size_t i = 0; i < res->header_count; ++i) {
        free(res->headers[i]);
    }

    free(res->headers);
    free(res);
    res = NULL;
}

bool set_response_header(Response* res, const char* name, const char* value) {
    // Check if this header already exists
    int index = find_header_index(res->headers, res->header_count, name);
    if (index == -1) {
        header_t* header = header_new(name, value);
        if (header == NULL) {
            LOG_ERROR("header_new() failed");
            return false;
        }
        res->headers[res->header_count++] = header;
    } else {
        // Replace header value
        header_t* h = res->headers[index];

        // Copy the new value to the header
        strncpy(h->value, value, MAX_HEADER_VALUE - 1);
        h->value[MAX_HEADER_VALUE - 1] = '\0';
    }

    if (strcasecmp(name, CONTENT_TYPE_HEADER) == 0) {
        res->content_type_set = true;
    }
    return true;
}

void process_response(Request* req) {
    context_t ctx = {.request = req,
                     .locals = map_create(8, key_compare_char_ptr),
                     .response = allocate_response(req->client_fd)};
    LOG_ASSERT(ctx.locals && ctx.response, "locals or response is NULL");

    Route* route = req->route;

    // If no middleware is defined, execute the handler directly
    size_t globalCount = get_global_middleware_count();
    if (route->middleware_count == 0 && globalCount == 0) {
        route->handler(&ctx);
        free_context(&ctx);
        return;
    }

    // Define middleware context
    MiddlewareContext mw_ctx = {
        .count = 0,
        .index = 0,
        .handler = route->handler,
        .middleware = NULL,
    };

    ctx.mw_ctx = &mw_ctx;

    // if both global and route middleware are defined, combine them
    if (route->middleware_count > 0 && get_global_middleware_count() > 0) {
        // Allocate memory for the combined middleware
        mw_ctx.middleware = merge_middleware(route, &mw_ctx);
        if (mw_ctx.middleware == NULL) {
            LOG_ERROR("error combining middleware");
            http_error(req->client_fd, StatusInternalServerError, "error allocating middleware");
            free_context(&ctx);
            return;
        }

        // Execute middleware chain
        execute_middleware(&ctx, mw_ctx.middleware, mw_ctx.count, 0, route->handler);

        // Free the combined middleware
        free(mw_ctx.middleware);
        free_context(&ctx);
        return;
    } else if (route->middleware_count > 0) {
        mw_ctx.middleware = (Middleware*)route->middleware;
        mw_ctx.count = route->middleware_count;
    } else if (globalCount > 0) {
        mw_ctx.middleware = get_global_middleware();
        mw_ctx.count = globalCount;
    }

    // Execute middleware chain and handler
    execute_middleware(&ctx, mw_ctx.middleware, mw_ctx.count, 0, route->handler);

    // free the context
    free_context(&ctx);
}

static void write_headers(Response* res) {
    if (res->headers_sent)
        return;

    // Set default status code
    if (res->status == 0) {
        res->status = StatusOK;
    }

    char header_res[MAX_RES_HEADER_SIZE];
    size_t remaining = sizeof(header_res);
    char* current = header_res;

    // Write status line
    int ret = snprintf(current, remaining, "HTTP/1.1 %u %s\r\n", res->status, http_status_text(res->status));
    if (ret < 0 || (size_t)ret >= remaining) {
        LOG_ERROR("Status line truncated or error occurred");
        return;
    }
    current += ret;
    remaining -= ret;

    // Add headers
    for (size_t i = 0; i < res->header_count; i++) {
        ret = snprintf(current, remaining, "%s: %s\r\n", res->headers[i]->name, res->headers[i]->value);
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
    int nbytes_sent = sendall(res->client_fd, header_res, strlen(header_res));
    if (nbytes_sent == -1) {
        if (errno == EBADF) {
            // Can happend if the client closes the connection before the response is sent.
            // we can safely ignore this error.
        } else {
            LOG_ERROR("%s, fd: %d", strerror(errno), res->client_fd);
        }
    }
    res->headers_sent = nbytes_sent != -1;
}

void send_status(Response* res, http_status code) {
    res->status = code;
    write_headers(res);
}

// Send the response to the client.
// Returns the number of bytes sent or -1 on error.
int send_response(Response* res, const char* data, size_t len) {
    char content_len[24];
    int ret = snprintf(content_len, sizeof(content_len), "%ld", len);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        LOG_ERROR("Warning: send_response(): truncation of content_len");
    }

    set_response_header(res, "Content-Length", content_len);
    write_headers(res);
    return sendall(res->client_fd, data, len);
}

int send_json(Response* res, const char* data, size_t len) {
    set_response_header(res, CONTENT_TYPE_HEADER, "application/json");
    return send_response(res, data, len);
}

// Send null-terminated JSON string.
int send_json_string(Response* res, const char* data) {
    return send_json(res, data, strlen(data));
}

int send_string(Response* res, const char* data) {
    return send_response(res, data, strlen(data));
}

__attribute__((format(printf, 2, 3))) int send_string_f(Response* res, const char* fmt, ...) {
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
    int result = send_response(res, buffer, len);

    // Free the allocated buffer
    free(buffer);
    return result;
}

// Writes chunked data to the client.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
int response_send_chunk(Response* res, const char* data, size_t len) {
    if (!res->headers_sent) {
        res->status = StatusOK;
        set_response_header(res, "Transfer-Encoding", "chunked");
        write_headers(res);
    }

    // Send the chunked header
    char chunked_header[32] = {0};
    int ret = snprintf(chunked_header, sizeof(chunked_header), "%zx\r\n", len);
    if (ret >= (int)sizeof(chunked_header)) {
        LOG_ERROR("chunked header truncated");
        // end the chunked response
        response_end(res);
        return -1;
    }

    int nbytes_sent = send(res->client_fd, chunked_header, strlen(chunked_header), MSG_NOSIGNAL);
    if (nbytes_sent == -1) {
        perror("error sending chunked header");
        response_end(res);
        return -1;
    }

    // Send the chunked data
    nbytes_sent = sendall(res->client_fd, data, len);
    if (nbytes_sent == -1) {
        perror("error sending chunked data");
        response_end(res);
        return -1;
    }

    // Send end of chunk: Send the chunk's CRLF (carriage return and line feed)
    if (send(res->client_fd, "\r\n", 2, MSG_NOSIGNAL) == -1) {
        perror("error send end of chunk sentinel");
        response_end(res);
        return false;
    };
    return nbytes_sent;
}

// End the chunked response. Must be called after all chunks have been sent.
int response_end(Response* res) {
    int nbytes_sent = sendall(res->client_fd, "0\r\n\r\n", 5);
    if (nbytes_sent == -1) {
        perror("error sending end of chunked response");
        return -1;
    }
    return nbytes_sent;
}

// redirect to the given url with a 302 status code
void response_redirect(Response* res, const char* url) {
    if (res->status < StatusMovedPermanently || res->status > StatusPermanentRedirect) {
        res->status = StatusSeeOther;
    }

    set_response_header(res, "Location", url);
    write_headers(res);
}

// Write headers for the Content-Range and Accept-Ranges.
// Also sets the status code for partial content.
static void send_range_headers(Response* res, ssize_t start, ssize_t end, off64_t file_size) {
    int ret;
    char content_len[24];
    ret = snprintf(content_len, sizeof(content_len), "%ld", end - start + 1);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        LOG_FATAL("send_range_headers(): truncation of content_len\n");
    }

    set_response_header(res, "Accept-Ranges", "bytes");
    set_response_header(res, "Content-Length", content_len);

    char content_range_str[128];
    ret = snprintf(content_range_str, sizeof(content_range_str), "bytes %ld-%ld/%ld", start, end, file_size);
    // This invariant must be respected.
    if (ret >= (int)sizeof(content_range_str)) {
        LOG_FATAL("send_range_headers(): truncation of content_range_str\n");
    }

    set_response_header(res, "Content-Range", content_range_str);
    res->status = StatusPartialContent;
}

// ==================== sendfile =============================
// Helper function prototypes
bool parse_range(const char* range_header, ssize_t* start, ssize_t* end, bool* has_end_range);
bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size);
ssize_t send_file_content(int client_fd, FILE* file, ssize_t start, ssize_t end, bool is_range_request);
void set_content_disposition(Response* res, const char* filename);

// Main function to serve a file
int servefile(context_t* ctx, const char* filename) {
    Response* res = ctx->response;
    Request* req = ctx->request;

    // Guess content-type if not already set
    if (!res->content_type_set) {
        set_response_header(res, CONTENT_TYPE_HEADER, get_mimetype((char*)filename));
    }

    // Open the file with fopen64 to support large files
    FILE* file = fopen64(filename, "rb");
    if (!file) {
        LOG_ERROR("Unable to open file: %s", filename);
        res->status = StatusInternalServerError;
        write_headers(res);
        return -1;
    }

    // Get the file size
    fseeko64(file, 0, SEEK_END);
    off64_t file_size = ftello64(file);
    if (file_size == -1) {
        perror("ftello64");
        LOG_ERROR("Unable to get file size: %s", filename);
        res->status = StatusInternalServerError;
        write_headers(res);
        return -1;
    }
    fseeko64(file, 0, SEEK_SET);

    // Handle range requests
    ssize_t start = 0, end = 0;
    bool has_end_range = false, range_valid = false;
    const char* range_header = find_header(req->headers, req->header_count, "Range");

    if (range_header && parse_range(range_header, &start, &end, &has_end_range)) {
        range_valid = validate_range(has_end_range, &start, &end, file_size);
        if (!range_valid) {
            fclose(file);
            res->status = StatusRequestedRangeNotSatisfiable;
            write_headers(res);
            return -1;
        }
        send_range_headers(res, start, end, file_size);
    } else {
        // Set content length for non-range requests
        char content_len_str[32];
        snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size);
        set_response_header(res, "Content-Length", content_len_str);
        set_content_disposition(res, filename);
    }

    write_headers(res);
    ssize_t total_bytes_sent = send_file_content(res->client_fd, file, start, end, range_valid);

    fclose(file);
    return total_bytes_sent;
}

// Serve an already opened file.
// This is useful when the file is already opened by the caller and its not efficient to read
// the contents of the file again.
// The file is not closed by this function.
int serve_open_file(context_t* ctx, FILE* file, size_t file_size, const char* filename) {
    Response* res = ctx->response;
    Request* req = ctx->request;

    // Guess content-type if not already set
    if (!res->content_type_set) {
        set_response_header(res, CONTENT_TYPE_HEADER, get_mimetype((char*)filename));
    }

    // Handle range requests
    ssize_t start = 0, end = 0;
    bool has_end_range = false, range_valid = false;
    const char* range_header = find_header(req->headers, req->header_count, "Range");

    if (range_header && parse_range(range_header, &start, &end, &has_end_range)) {
        range_valid = validate_range(has_end_range, &start, &end, file_size);
        if (!range_valid) {
            fclose(file);
            res->status = StatusRequestedRangeNotSatisfiable;
            write_headers(res);
            return -1;
        }
        send_range_headers(res, start, end, file_size);
    } else {
        // Set content length for non-range requests
        char content_len_str[32];
        snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size);
        set_response_header(res, "Content-Length", content_len_str);
        set_content_disposition(res, filename);
    }

    write_headers(res);
    ssize_t total_bytes_sent = send_file_content(res->client_fd, file, start, end, range_valid);
    return total_bytes_sent;
}

// Parses the Range header and extracts start and end values
bool parse_range(const char* range_header, ssize_t* start, ssize_t* end, bool* has_end_range) {
    if (strstr(range_header, "bytes=") != NULL) {
        if (sscanf(range_header, "bytes=%ld-%ld", start, end) == 2) {
            *has_end_range = true;
            return true;
        } else if (sscanf(range_header, "bytes=%ld-", start) == 1) {
            *has_end_range = false;
            return true;
        }
    }
    return false;
}

// Validates the requested range against the file size
bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size) {
    ssize_t startByte = *start, endByte = *end;

    // Send the requested range in chunks of 4MB
    ssize_t byteRangeSize = (4 * 1024 * 1024) - 1;
    if (!has_end_range && startByte >= 0) {
        endByte = startByte + byteRangeSize;
    } else if (startByte < 0) {
        // Http range requests can be negative :) Wieird but true
        // I had to read the RFC to understand this, who would have thought?
        // https://datatracker.ietf.org/doc/html/rfc7233
        startByte = file_size + startByte;    // subtract from the file size
        endByte = startByte + byteRangeSize;  // send the next 4MB if not more than the file size
    } else if (endByte < 0) {
        // Even the end range can be negative. Deal with it!
        endByte = file_size + endByte;
    }

    // Ensure the end of the range doesn't exceed the file size
    if (endByte >= file_size) {
        endByte = file_size - 1;
    }

    // Ensure the start and end range are within the file size
    if (startByte < 0 || endByte < 0 || endByte >= file_size) {
        return false;
    }

    *start = startByte;
    *end = endByte;

    return true;
}

// Sends the file content, handling both full and partial responses
ssize_t send_file_content(int client_fd, FILE* file, ssize_t start, ssize_t end, bool is_range_request) {
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = 4 << 20;  // 2MB buffer
    int file_fd = fileno(file);
    off_t offset = start;
    ssize_t max_range = end - start + 1;

    if (is_range_request) {
        buffer_size = max_range < buffer_size ? max_range : buffer_size;
    } else {
        fseeko64(file, 0, SEEK_SET);
    }

    // Enable TCP_CORK to avoid small packets
    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));

    while (total_bytes_sent < max_range) {
        ssize_t sent_bytes = sendfile(client_fd, file_fd, &offset, buffer_size);
        if (sent_bytes > 0) {
            total_bytes_sent += sent_bytes;
            if (is_range_request && total_bytes_sent >= max_range)
                break;
            buffer_size = (max_range - total_bytes_sent) < buffer_size ? (max_range - total_bytes_sent) : buffer_size;
        } else if (sent_bytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(5000);  // 5ms delay
                continue;
            } else if (errno != EPIPE) {
                perror("sendfile");
            }
            break;
        }
    }

    // Disable TCP_CORK
    flag = 0;
    setsockopt(client_fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));

    return total_bytes_sent;
}

// Sets the Content-Disposition header for the response
void set_content_disposition(Response* res, const char* filename) {
    char content_disposition[512];
    char base_name[256];
    filepath_basename(filename, base_name, sizeof(base_name));
    snprintf(content_disposition, sizeof(content_disposition), "inline; filename=\"%s\"", base_name);
    set_response_header(res, "Content-Disposition", content_disposition);
}

void set_content_type(Response* res, const char* content_type) {
    set_response_header(res, CONTENT_TYPE_HEADER, content_type);
}
