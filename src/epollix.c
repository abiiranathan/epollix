#include "../include/epollix.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <pthread.h>
#include <signal.h>
#include <solidc/filepath.h>
#include <solidc/map.h>
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

static const char* CONTENT_TYPE_HEADER = "Content-Type";

typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

typedef struct header {
    char name[MAX_HEADER_NAME];    // Header key
    char value[MAX_HEADER_VALUE];  // Header value
} header_t;

typedef struct request {
    int client_fd;        // Peer connection file descriptor
    int epoll_fd;         // epoll file descriptor.
    HttpMethod method;    // Http request method as an integer enum;
    char method_str[16];  // Http request method

    char path[1024];        // Request path and query string
    char http_version[16];  // Http version

    size_t header_count;                // Number of headers
    header_t headers[MAX_REQ_HEADERS];  // Request headers

    size_t content_length;  // Content length or size of body
    uint8_t* body;          // Body of the request.
    map* query_params;      // Query parameters

    struct Route* route;  // Matching route
} request_t;

// epollix context containing response primitives and request state.
typedef struct ep_context {
    http_status status;                 // Status code
    uint8_t* data;                      // Response data as bytes.
    size_t content_length;              // Content-Length
    size_t header_count;                // Number of headers set.
    header_t headers[MAX_RES_HEADERS];  // Response headers

    request_t* request;  // Pointer to the request
    bool headers_sent;   // Headers already sent
    bool chunked;        // Is a chunked transfer

    struct MiddlewareContext* mw_ctx;  // Middleware context
} context_t;

typedef struct MiddlewareContext {
    Middleware* middleware;
    size_t count;
    size_t index;
    void (*handler)(context_t* ctx);
} MiddlewareContext;

typedef struct Route {
    HttpMethod method;          // HTTP Method.
    RouteType type;             // Type of Route (Normal or Static)
    char* pattern;              // Pattern to match
    Handler handler;            // Handler for the route
    char dirname[MAX_DIRNAME];  // Dirname for static route.
    PathParams* params;         // Parameters extracted from the URL

    Middleware middleware[MAX_ROUTE_MIDDLEWARE];  // Array of middleware functions
    size_t middleware_count;                      // Number of middleware functions
} Route;

// =================== STATIC DECLARATIONS ================================================
static Route routeTable[MAX_ROUTES] = {0};
static size_t numRoutes = 0;
static Middleware global_middleware[MAX_GLOBAL_MIDDLEWARE];
static size_t global_middleware_count = 0;
volatile sig_atomic_t running = 1;
static Route* notFoundRoute = NULL;

// To be cleaned up on exit
int epoll_fd = -1;
int server_fd = -1;
volatile sig_atomic_t cleanup_done = false;

ThreadPool pool = NULL;
pthread_mutex_t cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t shutdown_thread = 0;

// ============ GLOBALS ==================================================================

// =================== STATIC DECLARATIONS ================================================
static void file_basename(const char* path, char* basename, size_t size);
static bool parse_url_query_params(char* query, map* query_params);
static void staticFileHandler(context_t* ctx);
static void execute_middleware(context_t* ctx, Middleware* middleware, size_t count, size_t index, Handler next);
static void middleware_next(context_t* ctx);
static void epollix_cleanup(void);

// Like send(2) but sends the data on connected socket fd in chunks if larger than 4K.
// Adds MSG_NOSIGNAL to send flags to ignore sigpipe.
ssize_t sendall(int fd, const void* buf, size_t n);

// ==================== END =================================================================

// Send error back to client as html with a status code.
void http_error(int client_fd, http_status status, const char* message) {
    assert(status >= StatusBadRequest && status <= StatusNetworkAuthenticationRequired);

    char* reply = NULL;
    int ret = asprintf(&reply, "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n", status,
                       http_status_text(status), strlen(message), message);
    if (ret == -1) {
        LOG_ERROR(MEMORY_ALLOC_FAILED);
        return;
    }

    sendall(client_fd, reply, strlen(reply));
    free(reply);
}

void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
}

static void* exit_timer_thread(void* arg) {
    UNUSED(arg);

    int tick = 0;
    while (!cleanup_done) {
        sleep(1);
        tick++;
        if (tick >= SHUTDOWN_TIMEOUT) {
            break;
        }
    }

    if (!cleanup_done) {
        epollix_cleanup();
    }
    return NULL;
}

void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        running = 0;
        printf("Caught signal %s, exiting within %d seconds\n", strsignal(sig), SHUTDOWN_TIMEOUT);

        // Schedule a thread to cleanup resources after SHUTDOWN_TIMEOUT seconds
        pthread_create(&shutdown_thread, NULL, exit_timer_thread, NULL);

        // Configure the thread for cancellation
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
        pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
        pthread_detach(shutdown_thread);
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
        LOG_FATAL("unable to call sigaction\n");
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
            LOG_ERROR("header_idx is too large. Max headers is %d\n", MAX_REQ_HEADERS);
            return http_max_headers_exceeded;
        }

        switch (state) {
            case STATE_HEADER_NAME:
                if (header_name_idx >= MAX_HEADER_NAME) {
                    LOG_ERROR("header name: %.*s is too long. Max length is %d\n", (int)header_name_idx, header_name,
                              MAX_HEADER_NAME);
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
                    LOG_ERROR("header value %.*s is too long. Max length is %d\n", (int)header_value_idx, header_value,
                              MAX_HEADER_VALUE);
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

bool set_header(context_t* ctx, const char* name, const char* value) {
    if (ctx->header_count >= MAX_RES_HEADERS) {
        LOG_ERROR("Exceeded max response headers: %d\n", MAX_RES_HEADERS);
        return false;
    }

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    if (name_len >= MAX_HEADER_NAME || value_len >= MAX_HEADER_VALUE) {
        LOG_ERROR("Header name or value exceeds max lengths: (%d, %d)\n", MAX_HEADER_NAME, MAX_HEADER_VALUE);
        return false;
    }

    // Check if this header already exists
    int index = find_header_index(ctx->headers, ctx->header_count, name);
    if (index == -1) {
        header_t header = {0};
        snprintf(header.name, MAX_HEADER_NAME, "%s", name);
        snprintf(header.value, MAX_HEADER_VALUE, "%s", value);
        ctx->headers[ctx->header_count++] = header;
    } else {
        // Replace header value
        snprintf(ctx->headers[index].value, MAX_HEADER_VALUE, "%s", value);
    }
    return true;
}

const Route* get_current_route(context_t* ctx) {
    return ctx->request->route;
}

const char* route_pattern(Route* route) {
    return route->pattern;
}

void set_status(context_t* ctx, http_status status) {
    ctx->status = status;
}

const char* get_content_type(context_t* ctx) {
    return find_header(ctx->request->headers, ctx->request->header_count, CONTENT_TYPE_HEADER);
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
        LOG_ERROR("buffer too small to fit header, \"%s: %s\". header has been trucated\n", h->name, h->value);
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
        LOG_ERROR("header name too long: %s\n", str);
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
    // Initialize response
    context_t res = {0};
    res.request = req;
    res.status = StatusOK;
    res.headers_sent = false;
    res.chunked = false;

    // Define middleware context
    MiddlewareContext mw_ctx = {0};
    res.mw_ctx = &mw_ctx;

    // Combine global and route-specific middleware
    Middleware combined_middleware[MAX_GLOBAL_MIDDLEWARE + MAX_ROUTE_MIDDLEWARE] = {0};
    size_t combined_count = 0;

    if (global_middleware_count > 0) {
        memcpy(combined_middleware, global_middleware, sizeof(Middleware) * global_middleware_count);
        combined_count += global_middleware_count;
    }

    if (route->middleware_count > 0) {
        memcpy(combined_middleware + combined_count, route->middleware, sizeof(Middleware) * route->middleware_count);
        combined_count += route->middleware_count;
    }

    mw_ctx.middleware = combined_middleware;
    mw_ctx.count = combined_count;
    mw_ctx.index = 0;
    mw_ctx.handler = route->handler;

    // Execute middleware chain
    execute_middleware(&res, combined_middleware, combined_count, 0, route->handler);

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
            LOG_ERROR("unable to create map for query params\n");
            http_error(client_fd, StatusInternalServerError, "error parsing query params");
            close_connection(client_fd, epoll_fd);
            return;
        }

        bool ok = parse_url_query_params(query, query_params);
        if (!ok) {
            LOG_ERROR("parse_url_query_params() failed\n");
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
        LOG_ERROR("Could not find the end of headers\n");
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
    // Enable TCP_NODELAY to disable Nagle's algorithm
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    if (n <= 64)
        return send(fd, buf, n, MSG_NOSIGNAL);

    size_t sent = 0, remaining = n;
    size_t chunk_size = 4096;
    char* data = (char*)buf;

    while (remaining > 0 && running) {
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

static void write_headers(context_t* ctx) {
    if (ctx->headers_sent)
        return;

    // Set default status code
    if (ctx->status == 0) {
        ctx->status = StatusOK;
    }

    size_t written = 0;
    char status_line[128] = {0};
    char header_res[MAX_RES_HEADER_SIZE] = {0};
    int ret;

    ret = snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u %s\r\n", ctx->status, http_status_text(ctx->status));
    if (ret > (int)sizeof(status_line)) {
        LOG_ERROR("status line truncated. Aborted!!\n");
        return;
    }

    // Write the status line to the header
    snprintf(header_res, sizeof(header_res), "%s", status_line);
    written += strlen(status_line);

    // Add headers
    for (size_t i = 0; i < ctx->header_count; i++) {
        char header[MAX_HEADER_NAME + MAX_HEADER_VALUE + 4] = {0};
        header_tostring(&ctx->headers[i], header, sizeof(header));

        // append \r\n to the end of header
        strncat(header, "\r\n", sizeof(header) - strlen(header) - 1);

        size_t header_len = strlen(header);
        if (written + header_len >= MAX_RES_HEADER_SIZE - 4) {  // 4 is for the \r\n\r\n
            LOG_ERROR("Exceeded max header size: %d\n", MAX_RES_HEADER_SIZE);
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
    int nbytes_sent = sendall(ctx->request->client_fd, header_res, strlen(header_res));
    if (nbytes_sent == -1) {
        perror("write_headers() failed");
    }

    ctx->headers_sent = true;
}

// Send the response to the client.
// Returns the number of bytes sent.
int send_response(context_t* ctx, char* data, size_t len) {
    char content_len[24];
    int ret = snprintf(content_len, sizeof(content_len), "%ld", len);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        LOG_ERROR("Warning: send_response(): truncation of content_len\n");
    }

    set_header(ctx, "Content-Length", content_len);
    write_headers(ctx);
    return sendall(ctx->request->client_fd, data, len);
}

int send_json(context_t* ctx, char* data, size_t len) {
    set_header(ctx, CONTENT_TYPE_HEADER, "application/json");
    return send_response(ctx, data, len);
}

int send_raw_string(context_t* ctx, char* data, size_t len) {
    set_header(ctx, CONTENT_TYPE_HEADER, "plain/text");
    return send_response(ctx, data, len);
}

// Writes chunked data to the client.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
int response_send_chunk(context_t* ctx, char* data, size_t len) {
    if (!ctx->headers_sent) {
        ctx->status = StatusOK;
        set_header(ctx, "Transfer-Encoding", "chunked");
        write_headers(ctx);
    }

    // Send the chunked header
    char chunked_header[32] = {0};
    int ret = snprintf(chunked_header, sizeof(chunked_header), "%zx\r\n", len);
    if (ret >= (int)sizeof(chunked_header)) {
        LOG_ERROR("chunked header truncated\n");
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
int http_serve_file(context_t* ctx, const char* filename) {
    assert(ctx);
    assert(ctx->request);

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
        perror("fopen64");
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

    // Set content disposition
    char content_disposition[128] = {0};
    char base_name[108] = {0};
    file_basename(filename, base_name, sizeof(base_name));
    snprintf(content_disposition, 128, "filename=%s", base_name);
    set_header(ctx, "Content-Disposition", content_disposition);

    // Write the headers to the client
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
        if (!running) {
            break;
        }

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
        LOG_ERROR("getaddrinfo: %s\n", gai_strerror(s));
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
        LOG_ERROR("Could not bind\n");
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
        LOG_ERROR("Unable to allocate queryParams\n");
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
        LOG_FATAL("Number of routes %ld exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
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
        LOG_FATAL("Invalid path parameter in pattern: %s\n", pattern);
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

// ================ Middleware logic ==================
void use_global_middleware(Middleware middleware) {
    if (global_middleware_count < MAX_GLOBAL_MIDDLEWARE) {
        global_middleware[global_middleware_count++] = middleware;
    } else {
        LOG_FATAL("Exceeded maximum global middleware count\n");
    }
}

void use_route_middleware(Route* route, Middleware middleware) {
    if (route->middleware_count < MAX_ROUTE_MIDDLEWARE) {
        route->middleware[route->middleware_count++] = middleware;
    } else {
        LOG_FATAL("Exceeded maximum middleware count for route\n");
    }
}

static void middleware_next(context_t* ctx) {
    MiddlewareContext* mw_ctx = (MiddlewareContext*)ctx->mw_ctx;
    execute_middleware(ctx, mw_ctx->middleware, mw_ctx->count, ++mw_ctx->index, mw_ctx->handler);
}

static void execute_middleware(context_t* ctx, Middleware* middleware, size_t count, size_t index, Handler handler) {
    if (index < count) {
        // Execute the next middleware in the chain
        middleware[index](ctx, middleware_next);
    } else if (handler) {
        // Call the handler if all middleware have been executed
        handler(ctx);
    }
}

// ================== End middleware logic ==============

const char* get_query(context_t* ctx, const char* name) {
    return map_get(ctx->request->query_params, (char*)name);
}

const char* get_param(context_t* ctx, const char* name) {
    return get_path_param(ctx->request->route->params, name);
}

char* get_body(context_t* ctx) {
    return (char*)ctx->request->body;
}

size_t get_body_length(context_t* ctx) {
    return ctx->request->content_length;
}

const char* get_path(context_t* ctx) {
    return ctx->request->path;
}

const char* get_header(context_t* ctx, const char* name) {
    return find_header(ctx->request->headers, ctx->request->header_count, name);
}

const char* get_response_header(context_t* ctx, const char* name) {
    return find_header(ctx->headers, ctx->header_count, name);
}

const char* get_method_str(context_t* ctx) {
    return ctx->request->method_str;
}

HttpMethod get_method(context_t* ctx) {
    return ctx->request->method;
}

void set_content_type(context_t* ctx, const char* content_type) {
    set_header(ctx, CONTENT_TYPE_HEADER, content_type);
}

Route* OPTIONS_ROUTE(const char* pattern, Handler handler) {
    return registerRoute(M_OPTIONS, pattern, handler, NormalRoute);
}

Route* GET_ROUTE(const char* pattern, Handler handler) {
    return registerRoute(M_GET, pattern, handler, NormalRoute);
}

Route* POST_ROUTE(const char* pattern, Handler handler) {
    return registerRoute(M_POST, pattern, handler, NormalRoute);
}

Route* PUT_ROUTE(const char* pattern, Handler handler) {
    return registerRoute(M_PUT, pattern, handler, NormalRoute);
}

Route* PATCH_ROUTE(const char* pattern, Handler handler) {
    return registerRoute(M_PATCH, pattern, handler, NormalRoute);
}

Route* DELETE_ROUTE(const char* pattern, Handler handler) {
    return registerRoute(M_DELETE, pattern, handler, NormalRoute);
}

Route* STATIC_DIR(const char* pattern, char* dir) {
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
        LOG_ERROR("STATIC_DIR: Directory \"%s\"does not exist\n", dirname);
        free(dirname);
        exit(EXIT_FAILURE);
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

    return route;
}

bool not_found_registered = false;
Route* NOT_FOUND_ROUTE(const char* pattern, Handler h) {
    if (not_found_registered) {
        LOG_FATAL("registration of more than one 404 handler\n");
    }

    notFoundRoute = registerRoute(M_GET, pattern, h, NormalRoute);
    not_found_registered = true;
    return notFoundRoute;
}

static void staticFileHandler(context_t* ctx) {
    request_t* req = ctx->request;
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
        set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->status = StatusRequestURITooLong;
        send_response(ctx, errmsg, strlen(errmsg));
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
        set_header(ctx, CONTENT_TYPE_HEADER, web_ct);
        http_serve_file(ctx, filepath);
        return;
    }

    // Send a 404 response if the file is not found
    char* response = "File Not Found\n";
    set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->status = StatusNotFound;
    send_response(ctx, response, strlen(response));
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

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_threads is 0, we use the num_cpus on the target machine.
int listen_and_serve(char* port, RouteMatcher route_matcher, size_t num_threads) {
    assert(port);

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

    /* The event loop */
    install_signal_handler();
    init_mime_hashtable();

    int nworkers = get_ncpus();
    if (num_threads > 0) {
        nworkers = num_threads;
    }

    printf("[PID: %d]\n", get_gid());
    printf("[Server listening on port %s with %d threads]\n", port, nworkers);

    // Create a threadpool with n threads
    pool = threadpool_create(nworkers);
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
                        if (errno == EINTR && running == false) {
                            return -1;  // Interrupted by signal
                        }

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
                        LOG_FATAL("Failed to set non-blocking\n");
                    }

                    event.data.fd = client_fd;
                    event.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR | EPOLLONESHOT;
                    ret = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
                    if (ret == -1) {
                        perror("epoll_ctl");
                        LOG_FATAL("Failed to add client socket to epoll\n");
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
                    LOG_ERROR("error on fd %d\n", events[i].data.fd);
                    close(events[i].data.fd);
                }
            }
        }
    }

    epollix_cleanup();
    return EXIT_SUCCESS;
}

static void epollix_cleanup() {
    if (cleanup_done) {
        return;
    }

    cleanup_done = true;
    pthread_mutex_lock(&cleanup_mutex);
    threadpool_wait(pool);
    threadpool_destroy(pool);
    close(epoll_fd);
    close(server_fd);

    free_static_routes();
    destroy_mime_hashtable();
    pthread_mutex_unlock(&cleanup_mutex);
}