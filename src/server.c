#include "../include/server.h"
#include "../include/mime.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <solidc/filepath.h>
#include <solidc/thread.h>
#include <solidc/threadpool.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MEMORY_ALLOC_FAILED "Memory allocation failed\n"
#define TOO_MANY_HEADERS "Too many headers\n"
#define HEADER_NAME_TOO_LONG "Header name too long\n"
#define HEADER_VALUE_TOO_LONG "Header name too long\n"
#define REQUEST_BODY_TOO_LONG "Request body too long\n"
#define INVALID_STATUS_LINE "Invalid http status line\n"
#define METHOD_NOT_ALLOWED "Method not allowed\n"

static Route routeTable[MAX_ROUTES] = {0};
static size_t numRoutes = 0;

volatile sig_atomic_t running = 1;

static Route* notFoundRoute = NULL;

// =================== STATIC DECLARATIONS ================================================
static void file_basename(const char* path, char* basename, size_t size);
static bool parse_url_query_params(char* query, map* query_params);
static void staticFileHandler(response_t* res);

// ==================== END =================================================================

// Send error back to client as html with a status code.
void http_error(int client_fd, http_status status, const char* message) {
    assert(status >= StatusBadRequest && status <= StatusNetworkAuthenticationRequired);

    char* reply = NULL;
    int ret = asprintf(&reply, "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n", status,
                       http_status_text(status), strlen(message), message);
    if (ret == -1) {
        fprintf(stderr, MEMORY_ALLOC_FAILED);
        return;
    }

    sendall(client_fd, reply, strlen(reply));
    free(reply);
}

void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
}

void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
        printf("Caught signal %s, exiting...\n", strsignal(sig));
    }
}

// Get the base name of path
void file_basename(const char* path, char* basename, size_t size) {
    const char* base = strrchr(path, '/');  // Unix
    if (!base) {
        base = strrchr(path, '\\');  // Windows
    }

    if (!base) {
        base = path;
    } else {
        base++;  // Skip the slash
    }

    strncpy(basename, base, size - 1);
    basename[size - 1] = '\0';
}

void decode_uri(const char* src, char* dst, size_t dst_size) {
    char a, b;
    // Track the number of characters written to dst
    size_t written = 0;

    while (*src && written + 1 < dst_size) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= 'A' - 10;
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= 'A' - 10;
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
            written++;
        } else {
            *dst++ = *src++;
            written++;
        }
    }

    // Null-terminate the destination buffer
    *dst = '\0';
}

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str) {
    // Since each character can be encoded as "%XX" (3 characters),
    // we multiply the length of the input string by 3 and add 1 for the null
    // terminator.
    size_t src_len = strlen(str);
    size_t capacity = src_len * 3 + 1;
    char* encoded_str = malloc(capacity);
    if (encoded_str == NULL) {
        perror("memory allocation failed");
        return NULL;
    }

    const char* hex = "0123456789ABCDEF";  // hexadecimal digits for percent-encoding
    size_t index = 0;                      // position in the encoded string

    // Iterate through each character in the input string
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = str[i];

        // Check if the character is safe and doesn't need encoding
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            encoded_str[index++] = c;
        } else {
            // If the character needs encoding, add '%' to the encoded string
            encoded_str[index++] = '%';

            // Convert the character to its hexadecimal
            encoded_str[index++] = hex[(c >> 4) & 0xF];  // High nibble
            encoded_str[index++] = hex[c & 0xF];         // Low nibble
        }
    }

    encoded_str[index] = '\0';
    return encoded_str;
}

static void install_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // See man 2 sigaction for more information.
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "unable to call sigaction\n");
        exit(EXIT_FAILURE);
    };

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
}

typedef enum { STATE_HEADER_NAME, STATE_HEADER_VALUE, STATE_HEADER_END } HeaderState;

typedef enum {
    http_ok,
    http_max_headers_exceeded,
    http_max_header_name_exceeded,
    http_max_header_value_exceeded,
    http_memory_alloc_failed,
} http_error_t;

const char* http_error_string(http_error_t code) {
    switch (code) {
        case http_ok:
            return "success";
        case http_max_header_name_exceeded:
            return HEADER_NAME_TOO_LONG;
        case http_max_header_value_exceeded:
            return HEADER_VALUE_TOO_LONG;
        case http_max_headers_exceeded:
            return TOO_MANY_HEADERS;
        case http_memory_alloc_failed:
            return MEMORY_ALLOC_FAILED;
    }

    return "success";
}

http_error_t parse_request_headers(request_t* req, const char* header_text, size_t length) {
    HeaderState state = STATE_HEADER_NAME;
    const char* ptr = header_text;
    size_t start_pos = 0, endpos = length;

    size_t header_name_idx = 0;
    size_t header_value_idx = 0;

    char header_name[MAX_HEADER_NAME] = {0};
    char header_value[MAX_HEADER_VALUE] = {0};

    for (size_t i = start_pos; i <= endpos; i++) {
        if (req->header_count >= MAX_REQ_HEADERS) {
            fprintf(stderr, "header_idx is too large. Max headers is %d\n", MAX_REQ_HEADERS);
            return http_max_headers_exceeded;
        }

        switch (state) {
            case STATE_HEADER_NAME:
                if (header_name_idx >= MAX_HEADER_NAME) {
                    fprintf(stderr, "header name: %.*s is too long. Max length is %d\n", (int)header_name_idx,
                            header_name, MAX_HEADER_NAME);
                    return http_max_header_name_exceeded;
                }

                if (ptr[i] == ':') {
                    header_name[header_name_idx] = '\0';
                    header_name_idx = 0;

                    while (ptr[++i] == ' ' && i < endpos)
                        ;

                    i--;  // Move back to the first character of the value

                    state = STATE_HEADER_VALUE;
                } else {
                    header_name[header_name_idx++] = ptr[i];
                }
                break;

            case STATE_HEADER_VALUE:
                if (header_value_idx >= MAX_HEADER_VALUE) {
                    fprintf(stderr, "header value %.*s is too long. Max length is %d\n", (int)header_value_idx,
                            header_value, MAX_HEADER_VALUE);
                    return http_max_header_value_exceeded;
                }

                // Check for CRLF
                if (ptr[i] == '\r' && i + 1 < endpos && ptr[i + 1] == '\n') {
                    header_value[header_value_idx] = '\0';
                    header_value_idx = 0;

                    header_t h = {0};
                    strncpy(h.name, header_name, MAX_HEADER_NAME);
                    strncpy(h.value, header_value, MAX_HEADER_VALUE);

                    req->headers[req->header_count++] = h;
                    state = STATE_HEADER_END;

                    // assert(*(ptr + i) == '\r');
                    // assert(*(ptr + i + 1) == '\n');
                } else {
                    header_value[header_value_idx++] = ptr[i];
                }
                break;

            case STATE_HEADER_END:
                if (ptr[i] == '\n') {
                    state = STATE_HEADER_NAME;
                }
                break;
        }
    }
    return http_ok;
}

const char* find_header(const header_t* headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(headers[i].name, name) == 0) {
            return headers[i].value;
        }
    }
    return NULL;
}

int find_header_index(header_t* headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(headers[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

bool set_header(response_t* res, const char* name, const char* value) {
    if (res->header_count >= MAX_RES_HEADERS) {
        fprintf(stderr, "Exceeded max response headers: %d\n", MAX_RES_HEADERS);
        return false;
    }

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    if (name_len >= MAX_HEADER_NAME || value_len >= MAX_HEADER_VALUE) {
        fprintf(stderr, "Header name or value exceeds max lengths: (%d, %d)\n", MAX_HEADER_NAME, MAX_HEADER_VALUE);
        return false;
    }

    // Check if this header already exists
    int index = find_header_index(res->headers, res->header_count, name);
    if (index == -1) {
        header_t header = {0};
        snprintf(header.name, MAX_HEADER_NAME, "%s", name);
        snprintf(header.value, MAX_HEADER_VALUE, "%s", value);
        res->headers[res->header_count++] = header;
    } else {
        // Replace header value
        snprintf(res->headers[index].value, MAX_HEADER_VALUE, "%s", value);
    }
    return true;
}

const char* get_content_type(request_t* request) {
    return find_header(request->headers, request->header_count, "Content-Type");
}

bool header_valid(const header_t* h) {
    return h->name[0] != '\0';
}

void print_headers(header_t* headers, size_t n) {
    printf("============ HEADERS ===================\n");
    for (size_t i = 0; i < n; i++) {
        printf("%s: %s\n", headers[i].name, headers[i].value);
    }
    printf("========================================\n");
}

// Create a header into buffer.
void header_tostring(const header_t* h, char* buffer, size_t buffer_size) {
    int ret = snprintf(buffer, buffer_size, "%s: %s", h->name, h->value);
    if (ret >= (int)buffer_size) {
        fprintf(stderr, "buffer too small to fit header, \"%s: %s\". header has been trucated\n", h->name, h->value);
    }
}

header_t header_fromstring(const char* str) {
    size_t n = 0;

    // find the index the first colon in the string.
    while (str[n] != ':' && str[n] != '\0') {
        n++;
    }

    // if the string is empty or the colon is the last character, return an empty header.
    // verify that the header is empty by checking if the name is empty.
    // i.e header.name[0] == '\0'
    if (str[n] == '\0' || n == 0 || n >= MAX_HEADER_NAME) {
        fprintf(stderr, "header name too long: %s\n", str);
        return (header_t){0};
    }

    header_t header = {0};

    // this will copy the name of the header. This will truncate the name if it is too long.
    snprintf(header.name, MAX_HEADER_NAME, "%s", str);
    header.name[n] = '\0';

    // skip the colon and any leading spaces.
    n++;
    while (str[n] == ' ') {
        n++;
    }

    snprintf(header.value, MAX_HEADER_VALUE, "%s", str + n);
    header.value[MAX_HEADER_VALUE - 1] = '\0';

    // We can return local header because it will be copied since its size is known.
    return header;
}

static void handle_write(request_t* req, Route* route) {
    // Initialise response
    response_t res = {0};
    res.content_length = 0;
    res.header_count = 0;
    memset(res.headers, 0, sizeof(res.headers));
    res.status = StatusOK;
    res.request = req;

    route->handler(&res);

    // Close the connection after sending the response
    close(req->client_fd);

    // Free memory for the request body
    if (req->body) {
        free(req->body);
        req->body = NULL;
    }

    if (req->query_params) {
        map_destroy(req->query_params, true);
    }

    // Free the request
    free(req);
}

/* We have data on the fd waiting to be read. Read and display it. We must read whatever data is available
completely, as we are running in edge-triggered mode and won't get a notification again for the same data. */
static void handle_read(int client_fd, int epoll_fd, RouteMatcher matcher) {
    // Read headers
    char headers[4096] = {0};
    char method[16] = {0};
    char uri[1024] = {0};  // undecoded path, query.
    char http_version[16];

    // Read the headers to get the content length
    ssize_t inital_size = recv(client_fd, headers, sizeof(headers), MSG_WAITALL);
    if (inital_size <= 0) {
        close_connection(client_fd, epoll_fd);
        return;
    }
    headers[inital_size] = '\0';

    // extract http method, path(uri) and http version.
    int count = sscanf(headers, "%15s %1023s %15s", method, uri, http_version);
    if (count != 3) {
        http_error(client_fd, StatusBadRequest, INVALID_STATUS_LINE);
        close_connection(client_fd, epoll_fd);
        return;
    }

    // Convert method string to an enum.
    HttpMethod httpMethod = method_fromstring(method);
    if (httpMethod == M_INVALID) {
        http_error(client_fd, StatusBadRequest, INVALID_STATUS_LINE);
        close_connection(client_fd, epoll_fd);
        return;
    }

    // Get the content-length from headers.
    char content_length[128] = {0};
    char* clptr = strcasestr(headers, "content-length: ");
    if (clptr) {
        size_t header_len = 16;
        char* ptr = clptr + header_len;
        while (*ptr != '\r' && *(ptr + 1) != '\n') {
            ptr++;
        }

        size_t length = ptr - clptr - header_len;
        strncpy(content_length, clptr + header_len, sizeof(content_length) - 1);
        assert(length + 1 <= sizeof(content_length));
        content_length[length] = '\0';
    }

    size_t total_read = 0;
    size_t body_size = atoi(content_length);

    // Bas64 decode the path and query parameters
    char decoded_uri[1024] = {0};
    decode_uri(uri, decoded_uri, sizeof(decoded_uri));

    // Split path and query
    char* query = NULL;
    map* query_params = NULL;
    char path[1024] = {0};

    // If there are query parameters, extract them
    if (strstr(decoded_uri, "?") && strstr(decoded_uri, "=")) {
        char* query_start = strstr(decoded_uri, "?");
        size_t query_len = 0;
        char* ptr = query_start + 1;  // skip ?
        while (*ptr != '\0' && *ptr != '#' && *ptr != ' ') {
            query_len++;
            ptr++;
        }

        size_t path_len = query_start - decoded_uri;
        query = malloc(query_len + 1);
        if (query == NULL) {
            perror("malloc");
            http_error(client_fd, StatusInternalServerError, "error parsing query params");
            close_connection(client_fd, epoll_fd);
            return;
        }

        strncpy(query, (char*)decoded_uri + path_len + 1, query_len);
        query[query_len] = '\0';

        if (path_len + 1 >= sizeof(path)) {
            free(query);
            http_error(client_fd, StatusInternalServerError, "URL is too long!");
            close_connection(client_fd, epoll_fd);
            return;
        }

        strncpy(path, decoded_uri, path_len + 1);
        path[path_len] = '\0';

        // Parse the query params
        query_params = map_create(0, key_compare_char_ptr);
        if (!query_params) {
            free(query);
            fprintf(stderr, "unable to create map for query params\n");
            http_error(client_fd, StatusInternalServerError, "error parsing query params");
            close_connection(client_fd, epoll_fd);
            return;
        }

        bool ok = parse_url_query_params(query, query_params);
        if (!ok) {
            fprintf(stderr, "parse_url_query_params() failed\n");
            free(query);
            map_destroy(query_params, true);
            http_error(client_fd, StatusInternalServerError, "error parsing query params");
            close_connection(client_fd, epoll_fd);
            return;
        }
    } else {
        // Everything is a path
        strncpy(path, decoded_uri, sizeof(path));
    }

    // Matches the route, populating path params that are part of the route if they exist
    Route* route = matcher(httpMethod, path);
    if (route == NULL) {
        if (notFoundRoute != NULL) {
            route = notFoundRoute;
        } else {
            http_error(client_fd, StatusNotFound, "Not Found");
            close_connection(client_fd, epoll_fd);
            return;
        }
    }

    // Find end of status line
    char* header_start = (char*)memmem(headers, inital_size, "\r\n", 2);
    assert(header_start);

    // Find the end of headers
    char* end_of_headers = (char*)memmem(headers, inital_size, "\r\n\r\n", 4);
    if (!end_of_headers) {
        fprintf(stderr, "Could not find the end of headers\n");
        close_connection(client_fd, epoll_fd);
        return;
    }

    // If the method is safe, then set the idle timeout to 0. We expect to read headers in one go.
    int idle_timeout = is_safe_method(httpMethod) ? 0 : IDLE_TIMEOUT;

    // By default the body is NULL.
    uint8_t* body = NULL;

    // Calculate the size of the headers and status line
    size_t header_capacity = end_of_headers - headers + 4;  // 4 is the size of "\r\n\r\n"

    // Initial body read(if any)
    size_t body_read = inital_size - header_capacity;

    if (!is_safe_method(httpMethod) && body_size != 0) {
        body = malloc(body_size + 1);
        assert(body);

        // If part of body was read, copy it to body.
        memcpy(body, headers + header_capacity, body_read);

        // update total read
        total_read += body_read;
    }

    // Read the remaining body if at all
    if (!is_safe_method(httpMethod) && body != NULL) {
        // Initialize last_read_time
        struct timespec last_read_time;
        clock_gettime(CLOCK_MONOTONIC, &last_read_time);

        char buf[READ_BUFFER_SIZE] = {0};
        ssize_t count;
        while (total_read < body_size) {
            memset(buf, 0, sizeof buf);
            count = recv(client_fd, buf, sizeof buf, 0);
            if (count == -1) {
                if (errno == EAGAIN) {
                    struct timespec current_time;
                    clock_gettime(CLOCK_MONOTONIC, &current_time);

                    // Check if idle timeout has been reached
                    if (current_time.tv_sec - last_read_time.tv_sec >= idle_timeout) {
                        http_error(client_fd, StatusInternalServerError, "Idle timeout\n");
                        if (body) {
                            free(body);
                        }
                        close_connection(client_fd, epoll_fd);
                        return;
                    }

                    usleep(1000);
                    continue;
                } else {
                    break;
                }
            } else if (count == 0) {
                /* End of file. The remote has closed the connection. */
                break;
            }

            // Reset idle interval
            clock_gettime(CLOCK_MONOTONIC, &last_read_time);

            memcpy(body + total_read, buf, count);
            total_read += count;
        }

        // Add a null terminator to the request data just in case
        body[total_read] = '\0';
    }

    request_t* req = malloc(sizeof(request_t));
    if (!req) {
        perror("malloc");
        http_error(client_fd, StatusInternalServerError, http_error_string(http_memory_alloc_failed));
        close_connection(client_fd, epoll_fd);
        if (body != NULL) {
            free(body);
        }
        return;
    }

    // Init request
    req->client_fd = client_fd;
    req->epoll_fd = epoll_fd;
    req->body = body;
    req->content_length = total_read;
    req->query_params = query_params;
    req->route = route;

    strncpy(req->method_str, method, sizeof req->method_str);
    req->method_str[strlen(method)] = '\0';

    req->method = httpMethod;

    strncpy(req->http_version, http_version, sizeof(req->http_version));
    req->http_version[strlen(method)] = '\0';

    strncpy(req->path, path, sizeof req->path);
    req->path[strlen(path)] = '\0';

    // Initialize request headers
    req->header_count = 0;
    memset(req->headers, 0, sizeof req->headers);

    http_error_t code = http_ok;

    // Parse headers and add them to request, skipping status line and \r\n
    code = parse_request_headers(req, header_start + 2, header_capacity - 4);
    if (code != http_ok) {
        http_error(client_fd, StatusRequestHeaderFieldsTooLarge, http_error_string(code));
        close_connection(client_fd, epoll_fd);
        if (body != NULL) {
            free(body);
        }

        if (req->query_params) {
            map_destroy(req->query_params, true);
        }

        free(req);
        return;
    }

    handle_write(req, route);
}

// Like send(2) but sends the request in chunks if larger than 4K.
// Uses MSG_NOSIGNAL as the flags.
ssize_t sendall(int fd, const void* buf, size_t n) {
    if (n <= 64)
        return send(fd, buf, n, MSG_NOSIGNAL);

    size_t sent = 0, remaining = n;
    size_t chunk_size = 4096;
    char* data = (char*)buf;

    while (remaining > 0) {
        char buffer[4096] = {0};

        // Make sure we don't overflow the buffer
        if (remaining < chunk_size) {
            chunk_size = remaining;
        }

        memcpy(buffer, data + sent, chunk_size);
        int bytes_sent = send(fd, buffer, chunk_size, MSG_NOSIGNAL);
        if (bytes_sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry send after a short delay
                usleep(1000);  // 1ms delay
                continue;
            } else {
                perror("send");
                return -1;
            }
        }

        sent += (size_t)bytes_sent;
        remaining -= bytes_sent;
    }
    return sent;
}

static void write_headers(response_t* res) {
    if (res->headers_sent)
        return;

    // Set default status code
    if (res->status == 0) {
        res->status = StatusOK;
    }

    size_t written = 0;
    char status_line[128] = {0};
    char header_res[MAX_RES_HEADER_SIZE] = {0};
    int ret;

    ret = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u %s\r\n", res->status, http_status_text(res->status));
    if (ret > (int)sizeof(status_line)) {
        fprintf(stderr, "status line truncated. Aborted!!\n");
        return;
    }

    // Write the status line to the header
    snprintf(header_res, sizeof(header_res), "%s", status_line);
    written += strlen(status_line);

    // Add headers
    for (size_t i = 0; i < res->header_count; i++) {
        char header[MAX_HEADER_NAME + MAX_HEADER_VALUE + 4] = {0};
        header_tostring(&res->headers[i], header, sizeof(header));

        // append \r\n to the end of header
        strncat(header, "\r\n", sizeof(header) - strlen(header) - 1);

        size_t header_len = strlen(header);
        if (written + header_len >= MAX_RES_HEADER_SIZE - 4) {  // 4 is for the \r\n\r\n
            fprintf(stderr, "Exceeded max header size: %d\n", MAX_RES_HEADER_SIZE);
            return;
        }

        // Append the header to the response headers
        strncat(header_res, header, sizeof(header_res) - written);
        written += header_len;
    }

    // Append the end of the headers
    strncat(header_res, "\r\n", sizeof(header_res) - written);
    written += 2;
    header_res[written] = '\0';

    // Send the response headers
    // MSG_NOSIGNAL: Do not generate a SIGPIPE signal if the peer
    // on a stream-oriented socket has closed the connection.
    int nbytes_sent = sendall(res->request->client_fd, header_res, strlen(header_res));
    if (nbytes_sent == -1) {
        perror("write_headers() failed");
    }

    res->headers_sent = true;
}

// Perform a partial write of data to response.
// Does not flush. Call response_flush to end the response.
int response_write(response_t* res, char* data, size_t len) {
    write_headers(res);
    int sent = sendall(res->request->client_fd, data, len);
    if (sent != -1) {
        res->content_length += sent;
    }

    if (sent != (int)len) {
        fprintf(stderr, "partial write of %d / %ld", sent, len);
        return -1;
    }
    return sent;
}

// Signal the end of the response with a zero-size chunk.
// Should return 4 as len of bytes sent(\r\n\r\n)
int response_flush(response_t* res) {
    int sent;
    if ((sent = send(res->request->client_fd, "\r\n\r\n", 4, MSG_NOSIGNAL)) == -1) {
        perror("error sending end of response sentinel");
        return -1;
    };
    return sent;
}

// Write and flush, signalling end of request.
// Returns number of bytes sent or -1 on error.
int response_writeall(response_t* res, char* data, size_t len) {
    write_headers(res);

    int sent;
    if ((sent = response_write(res, data, len))) {
        int ret = response_flush(res);
        if (ret != 4) {
            return -1;
        }
    }
    return sent;
}

// redirect to the given url with a 302 status code
void response_redirect(response_t* res, const char* url) {
    if (res->status < StatusMovedPermanently || res->status > StatusPermanentRedirect) {
        res->status = StatusSeeOther;
    }

    set_header(res, "Location", url);
    write_headers(res);
}

// Write headers for the Content-Range and Accept-Ranges.
// Also sets the status code for partial content.
static void send_range_headers(response_t* res, ssize_t start, ssize_t end, off64_t file_size) {
    int ret;
    char content_len[24];
    ret = snprintf(content_len, sizeof(content_len), "%ld", end - start + 1);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        fprintf(stderr, "send_range_headers(): truncation of content_len\n");
        exit(EXIT_FAILURE);
    }

    set_header(res, "Accept-Ranges", "bytes");
    set_header(res, "Content-Length", content_len);

    char content_range_str[128];
    ret = snprintf(content_range_str, sizeof(content_range_str), "bytes %ld-%ld/%ld", start, end, file_size);
    // This invariant must be respected.
    if (ret >= (int)sizeof(content_range_str)) {
        fprintf(stderr, "send_range_headers(): truncation of content_range_str\n");
        exit(EXIT_FAILURE);
    }

    set_header(res, "Content-Range", content_range_str);
    res->status = StatusPartialContent;
}

// serve a file with support for partial content specified by the "Range" header.
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
int http_serve_file(response_t* res, const char* filename) {
    assert(res);
    assert(res->request);

    // Guess content-type if not already set
    if (find_header(res->headers, res->header_count, "Content-Type") == NULL) {
        set_header(res, "Content-Type", get_mimetype((char*)filename));
    }

    ssize_t start = 0, end = 0;
    const char* range_header = NULL;
    bool is_range_request = false;
    bool has_end_range = false;

    range_header = find_header(res->request->headers, res->request->header_count, "Range");
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
        perror("fopen64");
        res->status = StatusInternalServerError;
        write_headers(res);
        return -1;
    }

    // Get the file size
    fseeko64(file, 0, SEEK_END);
    off64_t file_size = ftello64(file);
    fseeko64(file, 0, SEEK_SET);

    // Set appropriate headers for partial content
    if (is_range_request) {
        if (start >= file_size) {
            res->status = StatusRequestedRangeNotSatisfiable;
            fclose(file);
            write_headers(res);
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
            res->status = StatusRequestedRangeNotSatisfiable;
            fclose(file);
            write_headers(res);
            return -1;
        }

        send_range_headers(res, start, end, file_size);

        // Move file position to the start of the requested range
        if (fseeko64(file, start, SEEK_SET) != 0) {
            res->status = StatusRequestedRangeNotSatisfiable;
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
        set_header(res, "Content-Length", content_len_str);
    }

    // Set content disposition
    char content_disposition[128] = {0};
    char base_name[108] = {0};
    file_basename(filename, base_name, sizeof(base_name));
    snprintf(content_disposition, 128, "filename=%s", base_name);
    set_header(res, "Content-Disposition", content_disposition);

    // Write the headers to the client
    write_headers(res);

    ssize_t total_bytes_sent = 0;  // Total bytes sent to the client
    off64_t buffer_size = 4096;    // 4K buffer size

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

    // Send the file using sendfile to avoid copying data from the kernel to user space
    // This is more efficient than read/write
    // See man sendfile(2) for more information
    while (total_bytes_sent < file_size || (is_range_request && total_bytes_sent < max_range)) {
        sent_bytes = sendfile(res->request->client_fd, file_fd, &offset, buffer_size);
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

static int setup_server_socket(char* port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        // Allow reuse of the port.
        int enable = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror("setsockopt(): new_tcpserver failed");
            exit(EXIT_FAILURE);
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        fprintf(stderr, "Could not bind\n");
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}

// ================== Main program ===========================
typedef struct read_task {
    int epoll_fd;
    int client_fd;
    RouteMatcher matcher;
} read_task;

static void submit_read_task(struct read_task* task) {
    handle_read(task->client_fd, task->epoll_fd, task->matcher);
    free(task);
}

// Default route matcher.
Route* default_route_matcher(HttpMethod method, const char* path) {
    Route* bestMatch = NULL;
    bool matches = false;

    for (size_t i = 0; i < numRoutes; i++) {
        if (method != routeTable[i].method) {
            continue;
        }

        if (routeTable[i].type == StaticRoute) {
            // For static routes, we match only the prefix as an exact match.
            if (strncmp(routeTable[i].pattern, path, strlen(routeTable[i].pattern)) == 0) {
                bestMatch = &routeTable[i];
                break;
            }
        } else {
            matches = match_path_parameters(routeTable[i].pattern, path, routeTable[i].params);
            if (matches) {
                bestMatch = &routeTable[i];
                break;
            }
        }
    }
    return bestMatch;
}

bool parse_url_query_params(char* query, map* query_params) {
    map* queryParams = map_create(0, key_compare_char_ptr);
    if (!queryParams) {
        fprintf(stderr, "Unable to allocate queryParams\n");
        return false;
    }

    char* key = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;
    bool success = true;

    char* token = strtok_r(query, "&", &save_ptr);
    while (token != NULL) {
        key = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* queryName = strdup(key);
            if (queryName == NULL) {
                perror("strdup");
                success = false;
                break;
            }

            char* queryValue = strdup(value);
            if (queryValue == NULL) {
                free(queryName);
                perror("strdup");
                success = false;
                break;
            }

            map_set(query_params, queryName, queryValue);
        }
        token = strtok_r(NULL, "&", &save_ptr);
    }
    return success;
}

// ============ Registering routes ==========================
// Helper function to register a new route
static Route* registerRoute(HttpMethod method, const char* pattern, Handler handler, RouteType type) {
    if (numRoutes >= (size_t)MAX_ROUTES) {
        fprintf(stderr, "Number of routes %ld exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
        exit(EXIT_FAILURE);
    }

    Route* route = &routeTable[numRoutes];
    route->method = method;
    route->handler = handler;
    route->type = type;
    memset(route->dirname, 0, sizeof(route->dirname));
    route->pattern = strdup(pattern);
    assert(route->pattern);

    route->params = malloc(sizeof(PathParams));
    assert(route->params);
    route->params->match_count = 0;
    memset(route->params->params, 0, sizeof(route->params->params));

    if ((strstr("{", pattern) && !strstr("}", pattern)) || (strstr("}", pattern) && !strstr("{", pattern))) {
        fprintf(stderr, "Invalid path parameter in pattern: %s\n", pattern);
        exit(EXIT_FAILURE);
    }

    numRoutes++;
    return route;
}

static void free_static_routes() {
    for (size_t i = 0; i < numRoutes; i++) {
        Route route = routeTable[i];
        free(route.pattern);
        if (route.params) {
            free(route.params);
        }
    }
}

// url_query_param returns the value associated with a query parameter.
// Returns NULL if the parameter is not found.
const char* url_query_param(request_t* req, const char* name) {
    return map_get(req->query_params, (char*)name);
}

// url_path_param returns the value associated with a path parameter.
// Returns NULL if the parameter is not found.
const char* url_path_param(request_t* req, const char* name) {
    return get_path_param(req->route->params, name);
}

void OPTIONS_ROUTE(const char* pattern, Handler handler) {
    registerRoute(M_OPTIONS, pattern, handler, NormalRoute);
}

void GET_ROUTE(const char* pattern, Handler handler) {
    registerRoute(M_GET, pattern, handler, NormalRoute);
}

void POST_ROUTE(const char* pattern, Handler handler) {
    registerRoute(M_POST, pattern, handler, NormalRoute);
}

void PUT_ROUTE(const char* pattern, Handler handler) {
    registerRoute(M_PUT, pattern, handler, NormalRoute);
}

void PATCH_ROUTE(const char* pattern, Handler handler) {
    registerRoute(M_PATCH, pattern, handler, NormalRoute);
}

void DELETE_ROUTE(const char* pattern, Handler handler) {
    registerRoute(M_DELETE, pattern, handler, NormalRoute);
}

void STATIC_DIR(const char* pattern, char* dir) {
    assert(MAX_DIRNAME > strlen(dir) + 1);

    char* dirname = strdup(dir);
    assert(dirname != NULL);

    if (strstr(dirname, "~")) {
        free(dirname);
        dirname = filepath_expanduser(dir);
        assert(dirname != NULL);
    }

    // Check that dirname exists
    if (access(dirname, F_OK) == -1) {
        fprintf(stderr, "STATIC_DIR: Directory \"%s\"does not exist\n", dirname);
        free(dirname);
        exit(EXIT_FAILURE);
        return;
    }

    size_t dirlen = strlen(dirname);
    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = registerRoute(M_GET, pattern, staticFileHandler, StaticRoute);
    assert(route != NULL);

    route->type = StaticRoute;
    snprintf(route->dirname, MAX_DIRNAME, "%s", dirname);
    free(dirname);
}

bool not_found_registered = false;
void NOT_FOUND_ROUTE(const char* pattern, Handler h) {
    if (not_found_registered) {
        fprintf(stderr, "registration of more than one 404 handler\n");
        exit(EXIT_FAILURE);
    }

    notFoundRoute = registerRoute(M_GET, pattern, h, NormalRoute);
    not_found_registered = true;
}

static void staticFileHandler(response_t* res) {
    request_t* req = res->request;
    Route* route = req->route;

    const char* dirname = route->dirname;

    // Trim the static pattern from the path
    const char* static_path = req->path + strlen(route->pattern);

    // Concatenate the dirname and the static path
    char fullpath[MAX_PATH_LEN] = {0};

    int n = snprintf(fullpath, MAX_PATH_LEN, "%s%s", dirname, static_path);
    if (n < 0 || n >= MAX_PATH_LEN) {
        char errmsg[256];
        snprintf(errmsg, 256, "%s %d", "The path exceeds the maximum path size of", MAX_PATH_LEN);
        set_header(res, "Content-Type", "text/html");
        res->status = StatusRequestURITooLong;
        response_writeall(res, errmsg, strlen(errmsg));
        return;
    }

    // Base64 decode the path such that it can be used to access the file system
    // decoding the path is necessary to handle special characters in the path
    // The buffer is large enough to hold the decoded path.
    char filepath[MAX_PATH_LEN] = {0};
    decode_uri(fullpath, filepath, sizeof(filepath));

    // In: solidc/filepath.h
    if (is_dir(filepath)) {
        size_t filepath_len = strlen(filepath);
        // remove the trailing slash
        if (filepath_len > 1 && filepath[filepath_len - 1] == '/') {
            filepath[filepath_len - 1] = '\0';
        }

        // Append /index.html to the path
        strncat(filepath, "/index.html", sizeof(filepath) - filepath_len - 1);
    }

    if (path_exists(filepath)) {
        const char* web_ct = get_mimetype(filepath);
        set_header(res, "Content-Type", web_ct);
        printf("content_type:%s %s\n", filepath, web_ct);
        http_serve_file(res, filepath);
        return;
    }

    // Send a 404 response if the file is not found
    char* response = "File Not Found\n";
    set_header(res, "Content-Type", "text/html");
    res->status = StatusNotFound;
    response_writeall(res, response, strlen(response));
}

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_threads is 0, we use the num_cpus on the target machine.
int listen_and_serve(char* port, RouteMatcher route_matcher, size_t num_threads) {
    assert(port);

    int epoll_fd, server_fd, ret;
    struct epoll_event event = {0}, events[MAXEVENTS] = {0};
    server_fd = setup_server_socket(port);
    if (server_fd == -1)
        exit(EXIT_FAILURE);

    ret = set_nonblocking(server_fd);
    if (ret == -1)
        exit(EXIT_FAILURE);

    ret = listen(server_fd, MAXEVENTS);
    if (ret == -1) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create");
        exit(EXIT_FAILURE);
    }

    event.data.fd = server_fd;
    event.events = EPOLLIN | EPOLLET;
    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        exit(EXIT_FAILURE);
    }

    /* The event loop */
    install_signal_handler();
    init_mime_hashtable();

    int nworkers = get_ncpus();
    if (num_threads > 0) {
        nworkers = num_threads;
    }

    printf("Server listening on port %s with %d threads\n", port, nworkers);
    printf("PID: %d\n", get_gid());

    // Create a threadpool with n threads
    ThreadPool pool = threadpool_create(nworkers);
    assert(pool);

    while (running) {
        int nfds = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (server_fd == events[i].data.fd) {
                /* We have a notification on the listening socket, which
                 means one or more incoming connections. */
                while (1) {
                    struct sockaddr internetAddress;
                    socklen_t client_len;
                    int client_fd;
                    char hostbuf[NI_MAXHOST], portbuf[NI_MAXSERV];

                    client_len = sizeof internetAddress;
                    client_fd = accept(server_fd, &internetAddress, &client_len);

                    if (client_fd == -1) {
                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                            /* We have processed all incoming connections. */
                            break;
                        } else {
                            perror("accept");
                            break;
                        }
                    }

                    ret = getnameinfo(&internetAddress, client_len, hostbuf, sizeof hostbuf, portbuf, sizeof portbuf,
                                      NI_NUMERICHOST | NI_NUMERICSERV);
                    if (ret == 0) {
                        printf("new connection on fd %d (host=%s, port=%s)\n", client_fd, hostbuf, portbuf);
                    }

                    ret = set_nonblocking(client_fd);
                    if (ret == -1) {
                        fprintf(stderr, "Failed to set non-blocking\n");
                        exit(EXIT_FAILURE);
                    }

                    event.data.fd = client_fd;
                    event.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR | EPOLLONESHOT;
                    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
                    if (ret == -1) {
                        perror("epoll_ctl");
                        exit(EXIT_FAILURE);
                    }
                }
            } else {
                if (events[i].events & EPOLLIN) {
                    // read event
                    // handle_read(events[i].data.fd, epoll_fd, &events[i]);
                    read_task* task = malloc(sizeof(read_task));
                    if (!task) {
                        http_error(events[i].data.fd, StatusInternalServerError, MEMORY_ALLOC_FAILED);
                        close_connection(events[i].data.fd, epoll_fd);
                        continue;
                    }

                    task->client_fd = events[i].data.fd;
                    task->epoll_fd = epoll_fd;
                    task->matcher = route_matcher;
                    threadpool_add_task(pool, (void (*)(void*))submit_read_task, task);

                } else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                    fprintf(stderr, "error on fd %d\n", events[i].data.fd);
                    close(events[i].data.fd);
                }
            }
        }
    }

    // Clean up
    threadpool_wait(pool);
    threadpool_destroy(pool);
    close(server_fd);
    free_static_routes();
    destroy_mime_hashtable();
    return EXIT_SUCCESS;
}
