
#ifdef __cplusplus
extern "C" {
#endif

#include "../include/epollix.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <pthread.h>
#include <signal.h>
#include <solidc/cstr.h>
#include <solidc/filepath.h>
#include <solidc/map.h>
#include <solidc/thread.h>
#include <solidc/threadpool.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "../include/logging.h"
#include "../include/method.h"

#ifdef __cplusplus
}
#endif

typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

typedef struct header {
    char name[MAX_HEADER_NAME];    // header name
    char value[MAX_HEADER_VALUE];  // header value
} header_t;

typedef struct request {
    int client_fd;          // Peer connection file descriptor
    int epoll_fd;           // epoll file descriptor
    char* path;             // Request path and query string (dynamically allocated)
    HttpMethod method;      // Http request method as an integer enum
    struct Route* route;    // Matching route
    size_t content_length;  // Content length or size of body
    uint8_t* body;          // Body of the request (dynamically allocated)
    char http_version[12];  // Http version (e.g., "HTTP/1.1")
    uint8_t header_count;   // Number of headers
    header_t** headers;     // Request headers (dynamically allocated)
    map* query_params;      // Query parameters (consider replacing with a more efficient structure)
} request_t;

// epollix context containing response primitives and request state.
typedef struct epollix_context {
    http_status status;     // Status code
    uint8_t* data;          // Response data as bytes.
    size_t content_length;  // Content-Length

    request_t* request;  // Pointer to the request
    bool headers_sent;   // Headers already sent
    bool chunked;        // Is a chunked transfer

    size_t header_count;  // Number of headers set.
    header_t** headers;   // Response headers

    struct MiddlewareContext* mw_ctx;  // Middleware context
    map* locals;                       // user-data key-value store the context.
} context_t;

// Context for middleware functions.
typedef struct MiddlewareContext {
    uint8_t count;                    // Number of middleware functions
    uint8_t index;                    // Current index in the middleware array
    Middleware* middleware;           // Array of middleware functions
    void (*handler)(context_t* ctx);  // Handler function
} MiddlewareContext;

// Route is a struct that contains the route pattern, handler, and middleware.
typedef struct Route {
    HttpMethod method;         // HTTP Method.
    RouteType type;            // Type of Route (Normal or Static)
    char* pattern;             // Pattern to match
    Handler handler;           // Handler for the route
    PathParams* params;        // Parameters extracted from the URL
    char* dirname;             // Dirname for static route(dynamic memory)
    Middleware* middleware;    // Array of middleware functions(allocated dynamically)
    uint8_t middleware_count;  // Number of middleware functions
    void* mw_data;             // Middleware data. This is set by the user.
} Route;

// Route group is a collection of routes that share the same prefix.
typedef struct RouteGroup {
    char* prefix;              // Prefix for the group
    Route** routes;            // Array of routes(dynamic memory)
    uint8_t count;             // Number of routes in the group
    Middleware* middleware;    // Middleware for the group
    uint8_t middleware_count;  // Number of middleware functions
} RouteGroup;

typedef struct read_result {
    request_t* req;  // Request object
    Route* route;    // Matched route
} read_result;

// =================== STATIC GLOBALS ================================================
static Route routeTable[MAX_ROUTES] = {0};                   // static Route table
static size_t numRoutes = 0;                                 // number of routes in the route table
static Middleware global_middleware[MAX_GLOBAL_MIDDLEWARE];  // Global middleware
static size_t global_middleware_count = 0;                   // Number of global middleware functions
volatile sig_atomic_t running = 1;                           // Flag to indicate if the server is running
static Route* notFoundRoute = NULL;                          // Route to use when a route is not found
static map* global_middleware_context = NULL;                // Global middleware context

static const char* CONTENT_TYPE_HEADER = "Content-Type";  // Content-Type header name
static cleanup_func user_cleanup_func = NULL;             // User-defined cleanup function

// ======================================================================================
// These are global variables that need to be cleaned up on exit.
int epoll_fd = -1;                                          // epoll file descriptor
int server_fd = -1;                                         // server file descriptor
volatile sig_atomic_t cleanup_done = false;                 // atomic flag to indicate cleanup is done
ThreadPool pool = NULL;                                     // Thread pool for handling requests
pthread_mutex_t cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;  // Mutex for cleanup
pthread_t shutdown_thread = 0;                              // Thread for cleanup

// =================== STATIC DECLARATIONS ================================================

// parse the query parameters from the query string.
static bool parse_url_query_params(char* query, map* query_params);

// Default handler for all static routes.
static void staticFileHandler(context_t* ctx);

// Helper function to execute the middleware in a chain.
static void execute_middleware(context_t* ctx, Middleware* middleware, size_t count, size_t index, Handler next);

// Advance to the next middleware in the chain.
static void middleware_next(context_t* ctx);

static Route* default_route_matcher(HttpMethod method, const char* path);

// Like send(2) but sends the data on connected socket fd in chunks if larger than 4K.
// Adds MSG_NOSIGNAL to send flags to ignore sigpipe.
ssize_t sendall(int fd, const void* buf, size_t n);

// Send error back to client as html with a status code.
void http_error(int client_fd, http_status status, const char* message) {
    char* reply = NULL;
    int ret = asprintf(&reply, "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n", status,
                       http_status_text(status), strlen(message), message);
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
        running = 0;

        // Its okay to call exit because epollix_cleanup will be called
        // automatically when the program exits.
        exit(EXIT_FAILURE);
    }
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
            return ERR_HEADER_NAME_TOO_LONG;
        case http_max_header_value_exceeded:
            return ERR_HEADER_VALUE_TOO_LONG;
        case http_max_headers_exceeded:
            return ERR_TOO_MANY_HEADERS;
        case http_memory_alloc_failed:
            return ERR_MEMORY_ALLOC_FAILED;
    }

    return "success";
}

header_t* header_new(const char* name, const char* value) {
    header_t* header = malloc(sizeof(header_t));
    LOG_ASSERT(header, "malloc failed");

    strncpy(header->name, name, MAX_HEADER_NAME - 1);
    header->name[MAX_HEADER_NAME - 1] = '\0';

    strncpy(header->value, value, MAX_HEADER_VALUE - 1);
    header->value[MAX_HEADER_VALUE - 1] = '\0';
    return header;
}

header_t* header_fromstring(const char* str) {
    size_t n = 0;

    // find the index the first colon in the string.
    while (str[n] != ':' && str[n] != '\0') {
        n++;
    }

    // if the string is empty or the colon is the last character, return an empty header.
    // verify that the header is empty by checking if the name is empty.
    // i.e header.name[0] == '\0'
    if (str[n] == '\0' || n == 0) {
        LOG_ERROR("Header name is empty");
        return NULL;
    }

    header_t* header = malloc(sizeof(header_t));
    if (header == NULL) {
        LOG_ERROR("malloc header_t failed");
        return NULL;
    }

    // Copy header name
    if (n >= MAX_HEADER_NAME) {
        LOG_ERROR("header name is too long. Max length is %d", MAX_HEADER_NAME);
        free(header);
        return NULL;
    }

    strncpy(header->name, str, MAX_HEADER_NAME - 1);
    header->name[n] = '\0';

    // skip the colon and any leading spaces.
    n++;
    while (str[n] == ' ') {
        n++;
    }

    // copy header value
    if (strlen(str + n) >= MAX_HEADER_VALUE) {
        LOG_ERROR("header value is too long. Max length is %d", MAX_HEADER_VALUE);
        free(header);
        return NULL;
    }

    strncpy(header->value, str + n, MAX_HEADER_VALUE - 1);
    header->value[strlen(str + n)] = '\0';
    return header;
}

http_error_t parse_request_headers(request_t* req, const char* header_text, size_t length) {
    const char* ptr = header_text;
    const char* end = ptr + length;

    char* name_ptr = req->headers[0]->name;
    char* value_ptr = req->headers[0]->value;

    while (ptr < end) {
        if (req->header_count >= MAX_REQ_HEADERS) {
            return http_max_headers_exceeded;
        }

        // Parse header name
        const char* colon = memchr(ptr, ':', end - ptr);
        if (!colon)
            break;

        size_t name_len = colon - ptr;
        if (name_len >= MAX_HEADER_NAME) {
            return http_max_header_name_exceeded;
        }
        memcpy(name_ptr, ptr, name_len);
        name_ptr[name_len] = '\0';

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n')
            break;

        size_t value_len = eol - ptr;
        if (value_len >= MAX_HEADER_VALUE) {
            return http_max_header_value_exceeded;
        }

        memcpy(value_ptr, ptr, value_len);
        value_ptr[value_len] = '\0';

        req->header_count++;
        name_ptr = req->headers[req->header_count]->name;
        value_ptr = req->headers[req->header_count]->value;

        ptr = eol + 2;  // Skip CRLF
    }

    return http_ok;
}

char* find_header(header_t** headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(headers[i]->name, name) == 0) {
            return headers[i]->value;
        }
    }
    return NULL;
}

int find_header_index(header_t** headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; i++) {
        if (strcasecmp(headers[i]->name, name) == 0) {
            return i;
        }
    }
    return -1;
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

// Set route middleware context or userdata.
void set_middleware_context(Route* route, void* userdata) {
    route->mw_data = userdata;
}

void* get_route_middleware_context(context_t* ctx) {
    return ctx->request->route->mw_data;
}

// Set route middleware context or userdata.
void set_global_mw_context(const char* key, void* userdata) {
    if (global_middleware_context == NULL) {
        global_middleware_context = map_create(8, key_compare_char_ptr);
        if (global_middleware_context == NULL) {
            LOG_ERROR("unable to create map for global middleware context");
            return;
        }
    }

    char* k = strdup(key);
    if (!k) {
        LOG_ERROR("unable to allocate memory for key: %s", key);
        return;
    }
    map_set(global_middleware_context, k, userdata);
}

void* get_global_middleware_context(const char* key) {
    if (global_middleware_context == NULL) {
        return NULL;
    }
    return map_get(global_middleware_context, (char*)key);
}

const char* get_route_pattern(Route* route) {
    return route->pattern;
}

void set_status(context_t* ctx, http_status status) {
    ctx->status = status;
}

// Get response status code.
http_status get_status(context_t* ctx) {
    return ctx->status;
}

const char* get_content_type(context_t* ctx) {
    return find_header(ctx->request->headers, ctx->request->header_count, CONTENT_TYPE_HEADER);
}

bool header_valid(const header_t* h) {
    return h->name[0] != '\0';
}

// Convert a header to a string, appending CRLF after the value.
// Returns a dynamically allocated string that the caller must free.
char* header_tostring(const header_t* h) {
    size_t len = strlen(h->name) + strlen(h->value) + 5;  // 5 is for ": " and "\r\n" and null terminator
    char* buf = malloc(len);
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
    // Close the connection after sending the response
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
    context_t ctx = {0};
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
    ctx.mw_ctx = &mw_ctx;

    // Combine global and route-specific middleware
    Middleware* combined_middleware = malloc(sizeof(Middleware) * (global_middleware_count + route->middleware_count));
    if (combined_middleware == NULL) {
        LOG_ERROR("malloc failed");
        http_error(req->client_fd, StatusInternalServerError, "error allocating middleware");
        reset_request(req);
        return;
    }

    // Combine global and route-specific middleware
    uint8_t combined_count = 0;
    for (size_t i = 0; i < (size_t)global_middleware_count; i++) {
        combined_middleware[combined_count++] = global_middleware[i];
    }

    for (size_t i = 0; i < (size_t)route->middleware_count; i++) {
        combined_middleware[combined_count++] = route->middleware[i];
    }

    mw_ctx.middleware = combined_middleware;
    mw_ctx.count = combined_count;
    mw_ctx.index = 0;
    mw_ctx.handler = route->handler;

    // Execute middleware chain
    execute_middleware(&ctx, combined_middleware, combined_count, 0, route->handler);

    // Free combined middleware
    free(combined_middleware);

    free_context(&ctx);
}

// Parse the request line (first line of the HTTP request)
bool parse_request_line(char* headers, char** method, char** uri, char** http_version, char** header_start) {
    *method = headers;
    *uri = strchr(headers, ' ');
    if (!*uri)
        return false;
    **uri = '\0';
    (*uri)++;

    *http_version = strchr(*uri, ' ');
    if (!*http_version)
        return false;
    **http_version = '\0';
    (*http_version)++;

    *header_start = strstr(*http_version, "\r\n");
    if (!*header_start)
        return false;
    **header_start = '\0';
    *header_start += 2;

    return true;
}

// Parse the Content-Length header
size_t parse_content_length(const char* header_start, const char* end_of_headers) {
    const char* content_length_header = strcasestr(header_start, "content-length:");
    if (!content_length_header || content_length_header >= end_of_headers) {
        return 0;
    }
    return strtoul(content_length_header + 15, NULL, 10);
}

// Parse the URI, extracting path and query parameters
bool parse_uri(const char* decoded_uri, char** path, char** query, map** query_params) {
    *path = strdup(decoded_uri);
    if (!*path)
        return false;

    *query = strchr(*path, '?');
    if (*query) {
        **query = '\0';
        (*query)++;

        *query_params = map_create(0, key_compare_char_ptr);
        if (!*query_params) {
            free(*path);
            return false;
        }

        if (!parse_url_query_params(*query, *query_params)) {
            free(*path);
            map_destroy(*query_params, true);
            return false;
        }
    } else {
        *query_params = NULL;
    }

    return true;
}

// Handle the case when a route is not found
bool handle_not_found(request_t* req, const char* method, const char* http_version, const char* path) {
    if (notFoundRoute) {
        req->route = notFoundRoute;
        LOG_ERROR("Route not found: %s\n", path);
        LOG_ERROR("Using not found route\n");
        return true;
    } else {
        fprintf(stderr, "%s - %s %s 404 Not Found\n", method, http_version, path);
        http_error(req->client_fd, StatusNotFound, "Not Found\n");
        return false;
    }
}

// Allocate memory for the body and read it from the socket
bool allocate_and_read_body(int client_fd, uint8_t** body, size_t body_size, size_t initial_read,
                            const char* initial_body) {
    *body = (uint8_t*)malloc(body_size + 1);
    if (!*body)
        return false;

    // copy the initial body read if any
    if (initial_read > 0) {
        memcpy(*body, initial_body, initial_read);
    }

    size_t total_read = initial_read;

    while (total_read < body_size) {
        ssize_t count = recv(client_fd, *body + total_read, body_size - total_read, 0);
        if (count == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            } else {
                perror("recv");
                free(*body);
                *body = NULL;
                return false;
            }
        } else if (count == 0) {
            break;  // EOF
        }

        total_read += count;
    }

    (*body)[total_read] = '\0';
    return true;
}

// Initialize the request structure with parsed data
void initialize_request(request_t* req, int client_fd, int epoll_fd, uint8_t* body, size_t content_length,
                        map* query_params, HttpMethod httpMethod, const char* http_version, const char* path) {
    req->client_fd = client_fd;
    req->epoll_fd = epoll_fd;
    req->body = body;
    req->content_length = content_length;
    req->query_params = query_params;
    req->header_count = 0;
    req->method = httpMethod;

    strncpy(req->http_version, http_version, sizeof(req->http_version) - 1);
    req->http_version[sizeof(req->http_version) - 1] = '\0';

    req->path = strdup(path);
    LOG_ASSERT(req->path != NULL, "malloc failed to allocate request path");
}

// Clean up resources allocated for the request
void cleanup_request(request_t* req) {
    if (req->body) {
        free(req->body);
    }
    if (req->query_params) {
        map_destroy(req->query_params, true);
    }
    if (req->path) {
        free(req->path);
    }
}

static void handle_read(request_t* req, int client_fd, int epoll_fd) {
    char headers[4096];
    ssize_t inital_size = recv(client_fd, headers, sizeof(headers) - 1, MSG_WAITALL);
    if (inital_size <= 0) {
        close_connection(client_fd, epoll_fd);
        return;
    }
    headers[inital_size] = '\0';

    char *method, *uri, *http_version, *header_start, *end_of_headers;
    if (!parse_request_line(headers, &method, &uri, &http_version, &header_start)) {
        http_error(client_fd, StatusBadRequest, ERR_INVALID_STATUS_LINE);
        close_connection(client_fd, epoll_fd);
        return;
    }

    HttpMethod httpMethod = method_fromstring(method);
    if (httpMethod == M_INVALID) {
        http_error(client_fd, StatusBadRequest, ERR_INVALID_STATUS_LINE);
        close_connection(client_fd, epoll_fd);
        return;
    }

    // Find the end of the headers
    // Can't use strstr because the headers may contain null bytes.
    end_of_headers = (char*)memmem(headers, inital_size, "\r\n\r\n", 4);
    if (!end_of_headers) {
        http_error(client_fd, StatusBadRequest, "Invalid Http Payload");
        close_connection(client_fd, epoll_fd);
        return;
    }

    // +4 to include the \r\n\r\n at the end of the headers
    size_t header_capacity = end_of_headers - headers + 4;

    size_t body_size = parse_content_length(header_start, end_of_headers);

    char decoded_uri[1024];
    decode_uri(uri, decoded_uri, sizeof(decoded_uri));

    char *path, *query;
    map* query_params = NULL;
    if (!parse_uri(decoded_uri, &path, &query, &query_params)) {
        http_error(client_fd, StatusInternalServerError, "error parsing query params");
        close_connection(client_fd, epoll_fd);
        return;
    }

    req->route = default_route_matcher(httpMethod, path);
    if (req->route == NULL && !handle_not_found(req, method, http_version, path)) {
        close_connection(client_fd, epoll_fd);
        return;
    }

    uint8_t* body = NULL;
    // Initial body read(if any)
    size_t total_read = inital_size - header_capacity;
    if (!is_safe_method(httpMethod) && body_size > 0) {
        if (!allocate_and_read_body(client_fd, &body, body_size, total_read, headers + header_capacity)) {
            http_error(client_fd, StatusInternalServerError, "Failed to read request body");
            close_connection(client_fd, epoll_fd);
            return;
        }
    }

    initialize_request(req, client_fd, epoll_fd, body, body_size, query_params, httpMethod, http_version, path);

    http_error_t code = parse_request_headers(req, header_start, header_capacity - 4);
    if (code != http_ok) {
        http_error(client_fd, StatusRequestHeaderFieldsTooLarge, http_error_string(code));
        cleanup_request(req);
        close_connection(client_fd, epoll_fd);
    }
}

// Like send(2) but sends the request in chunks if larger than 4K.
// Uses MSG_NOSIGNAL as the flags.
ssize_t sendall(int fd, const void* buf, size_t n) {
    // Enable TCP_NODELAY to disable Nagle's algorithm
    int flag = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

    // If the data is less than 64 bytes, send it in one go
    if (n <= 64) {
        return send(fd, buf, n, MSG_NOSIGNAL);
    }

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
        LOG_ERROR("status line truncated. Aborted!!");
        return;
    }

    // Write the status line to the header
    snprintf(header_res, sizeof(header_res), "%s", status_line);
    written += strlen(status_line);

    // Add headers
    for (size_t i = 0; i < ctx->header_count; i++) {
        // Convert the header to a string with \r\n at the end
        char* header = header_tostring(ctx->headers[i]);
        if (header == NULL) {
            LOG_ERROR("header_tostring() failed");
            return;
        }

        // Append the header to the response headers
        strncat(header_res, header, sizeof(header_res) - written);
        written += strlen(header);
        free(header);
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

// ================== Main program ===========================
typedef struct read_task {
    int epoll_fd;    // Epoll file descriptor
    int client_fd;   // Client file descriptor
    int index;       // Index of the task in the tasks array. -1 means task if free.
    request_t* req;  // Request object
} read_task;

// Default route matcher.
static Route* default_route_matcher(HttpMethod method, const char* path) {
    bool matches = false;

    for (size_t i = 0; i < numRoutes; i++) {
        if (method != routeTable[i].method) {
            continue;
        }

        if (routeTable[i].type == NormalRoute) {
            matches = match_path_parameters(routeTable[i].pattern, path, routeTable[i].params);
            if (matches) {
                return &routeTable[i];
            }
        } else {
            // For static routes, we match only the prefix as an exact match.
            if (strncmp(routeTable[i].pattern, path, strlen(routeTable[i].pattern)) == 0) {
                return &routeTable[i];
            }
        }
    }
    return NULL;
}

bool parse_url_query_params(char* query, map* query_params) {
    map* queryParams = map_create(0, key_compare_char_ptr);
    if (!queryParams) {
        LOG_ERROR("Unable to allocate queryParams");
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
    route->mw_data = NULL;
    route->middleware_count = 0;
    route->middleware = NULL;

    route->pattern = strdup(pattern);
    route->params = (PathParams*)malloc(sizeof(PathParams));
    LOG_ASSERT(route->pattern, "strdup failed");
    LOG_ASSERT(route->params, "malloc failed");

    route->params->match_count = 0;
    memset(route->params->params, 0, sizeof(route->params->params));

    if ((strstr("{", pattern) && !strstr("}", pattern)) || (strstr("}", pattern) && !strstr("{", pattern))) {
        LOG_FATAL("Invalid path parameter in pattern: %s\n", pattern);
    }

    numRoutes++;
    return route;
}

void free_static_routes(void) {
    for (size_t i = 0; i < numRoutes; i++) {
        Route route = routeTable[i];
        free(route.pattern);

        if (route.params) {
            free(route.params);
        }

        // Free the middleware data if it exists
        if (route.mw_data) {
            free(route.mw_data);
        }

        // Free the middleware array
        if (route.middleware) {
            free(route.middleware);
        }

        // Free the dirname for static routes
        if (route.dirname) {
            free(route.dirname);
        }
    }
}

// ================ Middleware logic ==================
void use_global_middleware(int count, ...) {
    if (global_middleware_count + count > MAX_GLOBAL_MIDDLEWARE) {
        LOG_FATAL("Exceeded maximum global middleware count\n");
    }

    va_list args;
    va_start(args, count);
    for (int i = 0; i < count && global_middleware_count < MAX_GLOBAL_MIDDLEWARE; i++) {
        global_middleware[global_middleware_count++] = va_arg(args, Middleware);
    }

    va_end(args);
}

// Register middleware for a route
void use_route_middleware(Route* route, int count, ...) {
    if (count <= 0) {
        return;
    }

    size_t new_count = route->middleware_count + count;
    Middleware* new_middleware = realloc(route->middleware, sizeof(Middleware) * new_count);
    if (!new_middleware) {
        perror("realloc");
        LOG_FATAL("Failed to allocate memory for route middleware\n");
    }

    // Update the route middleware
    route->middleware = new_middleware;

    va_list args;
    va_start(args, count);

    // Append the new middleware to the route middleware
    for (size_t i = route->middleware_count; i < new_count; i++) {
        route->middleware[i] = va_arg(args, Middleware);
    }
    route->middleware_count = new_count;
    va_end(args);
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
    // No queries present.
    if (ctx->request->query_params == NULL) {
        return NULL;
    }

    return map_get(ctx->request->query_params, (char*)name);
}

const char* get_param(context_t* ctx, const char* name) {
    return get_path_param(ctx->request->route->params, name);
}

char* get_body(context_t* ctx) {
    return (char*)ctx->request->body;
}

size_t get_body_size(context_t* ctx) {
    return ctx->request->content_length;
}

const char* get_path(context_t* ctx) {
    return ctx->request->path;
}

const char* get_header(context_t* ctx, const char* name) {
    return find_header(ctx->request->headers, ctx->request->header_count, name);
}

const char* get_response_header(context_t* ctx, const char* name) {
    return (const char*)find_header(ctx->headers, ctx->header_count, name);
}

const char* get_method_str(context_t* ctx) {
    return method_tostring(ctx->request->method);
}

HttpMethod get_method(context_t* ctx) {
    return ctx->request->method;
}

void set_content_type(context_t* ctx, const char* content_type) {
    set_header(ctx, CONTENT_TYPE_HEADER, content_type);
}

Route* route_options(const char* pattern, Handler handler) {
    return registerRoute(M_OPTIONS, pattern, handler, NormalRoute);
}

Route* route_get(const char* pattern, Handler handler) {
    return registerRoute(M_GET, pattern, handler, NormalRoute);
}

Route* route_post(const char* pattern, Handler handler) {
    return registerRoute(M_POST, pattern, handler, NormalRoute);
}

Route* route_put(const char* pattern, Handler handler) {
    return registerRoute(M_PUT, pattern, handler, NormalRoute);
}

Route* route_patch(const char* pattern, Handler handler) {
    return registerRoute(M_PATCH, pattern, handler, NormalRoute);
}

Route* route_delete(const char* pattern, Handler handler) {
    return registerRoute(M_DELETE, pattern, handler, NormalRoute);
}

Route* route_static(const char* pattern, const char* dir) {
    LOG_ASSERT(MAX_DIRNAME > strlen(dir) + 1, "dir name too long");

    char* dirname = strdup(dir);
    LOG_ASSERT(dirname, "strdup failed");

    if (strstr(dirname, "~")) {
        free(dirname);
        dirname = filepath_expanduser(dir);
        LOG_ASSERT(dirname, "filepath_expanduser failed");
    }

    // Check that dirname exists
    if (access(dirname, F_OK) == -1) {
        LOG_ERROR("STATIC_DIR: Directory \"%s\"does not exist", dirname);
        free(dirname);
        exit(EXIT_FAILURE);
    }

    size_t dirlen = strlen(dirname);
    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = registerRoute(M_GET, pattern, staticFileHandler, StaticRoute);
    LOG_ASSERT(route, "registerRoute failed");

    route->type = StaticRoute;
    route->dirname = dirname;
    return route;
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
    Middleware* new_middleware = realloc(group->middleware, sizeof(Middleware) * (size_t)new_count);
    if (!new_middleware) {
        LOG_FATAL("Failed to allocate memory for group middleware\n");
    }

    group->middleware = new_middleware;

    va_list args;
    va_start(args, count);
    for (size_t i = group->middleware_count; i < new_count; i++) {
        group->middleware[i] = va_arg(args, Middleware);
    }
    group->middleware_count = new_count;
    va_end(args);
}

static Route* registerGroupRoute(RouteGroup* group, HttpMethod method, const char* pattern, Handler handler,
                                 RouteType type) {
    char* route_pattern = (char*)malloc(strlen(group->prefix) + strlen(pattern) + 1);
    if (!route_pattern) {
        LOG_FATAL("Failed to allocate memory for route pattern\n");
    }

    int ret = snprintf(route_pattern, strlen(group->prefix) + strlen(pattern) + 1, "%s%s", group->prefix, pattern);
    if (ret < 0 || ret >= (int)(strlen(group->prefix) + strlen(pattern) + 1)) {
        LOG_FATAL("Failed to concatenate route pattern\n");
    }

    // realloc the routes array, may be null if this is the first route
    Route** new_routes = realloc(group->routes, sizeof(Route*) * (group->count + 1));
    if (!new_routes) {
        LOG_FATAL("Failed to allocate memory for group routes\n");
    }

    // Update the routes array
    group->routes = new_routes;

    // This is allocated in static memory. Freed when the server exits.
    // Should not be freed in route_group_free.
    Route* route = registerRoute(method, route_pattern, handler, type);
    group->routes[group->count++] = route;

    free(route_pattern);
    return route;
}

// Register an OPTIONS route.
Route* route_group_options(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_OPTIONS, pattern, handler, NormalRoute);
}

// Register a GET route.
Route* route_group_get(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_GET, pattern, handler, NormalRoute);
}

// Register a POST route.
Route* route_group_post(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_POST, pattern, handler, NormalRoute);
}

// Register a PUT route.
Route* route_group_put(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_PUT, pattern, handler, NormalRoute);
}

// Register a PATCH route.
Route* route_group_patch(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_PATCH, pattern, handler, NormalRoute);
}

// Register a DELETE route.
Route* route_group_delete(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_DELETE, pattern, handler, NormalRoute);
}

// Serve static directory at dirname.
// e.g   STATIC_GROUP_DIR(group, "/web", "/var/www/html");
Route* route_group_static(RouteGroup* group, const char* pattern, char* dirname) {
    LOG_ASSERT(MAX_DIRNAME > strlen(dirname) + 1, "dirname is too long");

    char* fullpath = strdup(dirname);
    LOG_ASSERT(fullpath != NULL, "strdup failed");

    if (strstr(fullpath, "~")) {
        free(fullpath);
        fullpath = filepath_expanduser(dirname);
        LOG_ASSERT(fullpath != NULL, "filepath_expanduser failed");
    }

    // Check that dirname exists
    if (access(fullpath, F_OK) == -1) {
        LOG_ERROR("STATIC_GROUP_DIR: Directory \"%s\"does not exist", fullpath);
        free(fullpath);
        exit(EXIT_FAILURE);
    }

    size_t dirlen = strlen(fullpath);
    if (fullpath[dirlen - 1] == '/') {
        fullpath[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = registerGroupRoute(group, M_GET, pattern, staticFileHandler, StaticRoute);
    LOG_ASSERT(route != NULL, "registerGroupRoute failed");

    route->type = StaticRoute;
    route->dirname = fullpath;
    return route;
}

//=======================================

bool not_found_registered = false;
Route* route_notfound(Handler h) {
    if (not_found_registered) {
        LOG_FATAL("registration of more than one 404 handler\n");
    }

    notFoundRoute = registerRoute(M_GET, "__notfound__", h, NormalRoute);
    not_found_registered = true;
    return notFoundRoute;
}

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

static void send_error_page(context_t* ctx, int status) {
    const char* status_str = http_status_text(status);
    char* error_page = NULL;
    int ret = asprintf(&error_page, "<html><head><title>%d %s</title></head><body><h1>%d %s</h1></body></html>", status,
                       status_str, status, status_str);
    if (ret == -1) {
        LOG_ERROR("Failed to allocate memory for error page\n");
        return;
    }

    set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->status = status;
    send_string(ctx, error_page);
    free(error_page);
}

static inline void append_or_error(context_t* ctx, Arena* arena, cstr* response, const char* str) {
    if (!cstr_append(arena, response, str)) {
        LOG_ERROR("Failed to append to response\n");
        send_error_page(ctx, StatusInternalServerError);
        return;
    }
}

static void serve_directory_listing(context_t* ctx, const char* dirname, const char* base_prefix) {
    DIR* dir;
    struct dirent* ent;
    Arena* arena = arena_create(0);
    if (!arena) {
        LOG_ERROR("Failed to create arena\n");
        send_error_page(ctx, StatusInternalServerError);
        return;
    }

    cstr* html_response = cstr_from(arena,
                                    "<html>"
                                    "<head>"
                                    "<style>"
                                    "body { font-family: Arial, sans-serif; padding: 1rem; }"
                                    "h1 { color: #333; }"
                                    "table { width: 100%; border-collapse: collapse; }"
                                    "th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }"
                                    "th { background-color: #f2f2f2; }"
                                    "a { text-decoration: none; color: #0066cc; }"
                                    "a:hover { text-decoration: underline; }"
                                    ".breadcrumbs { margin-bottom: 20px; }"
                                    ".breadcrumbs a { color: #0066cc; text-decoration: none; }"
                                    ".breadcrumbs a:hover { text-decoration: underline; }"
                                    "</style>"
                                    "</head>"
                                    "<body>"
                                    "<h1>Directory Listing</h1>");

    if (!html_response) {
        LOG_ERROR("Failed to create cstr\n");
        send_error_page(ctx, StatusInternalServerError);
        arena_destroy(arena);
        return;
    }

    // Create breadcrumbs
    append_or_error(ctx, arena, html_response, "<div class=\"breadcrumbs\">");
    append_or_error(ctx, arena, html_response, "<a href=\"/\">Home</a>");

    char* path = strdup(base_prefix);
    if (!path) {
        LOG_ERROR("Failed to allocate memory for path\n");
        set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->status = StatusInternalServerError;
        send_string(ctx, "Failed to allocate memory for path");
        arena_destroy(arena);
        return;
    }

    char* token = strtok(path, "/");
    char breadcrumb_path[MAX_PATH_LEN] = {0};

    while (token) {
        strcat(breadcrumb_path, "/");
        strcat(breadcrumb_path, token);
        append_or_error(ctx, arena, html_response, " / <a href=\"");
        append_or_error(ctx, arena, html_response, breadcrumb_path);
        append_or_error(ctx, arena, html_response, "\">");
        append_or_error(ctx, arena, html_response, token);
        append_or_error(ctx, arena, html_response, "</a>");
        token = strtok(NULL, "/");
    }
    free(path);

    append_or_error(ctx, arena, html_response, "</div>");

    append_or_error(ctx, arena, html_response,
                    "<table>"
                    "<tr><th>Name</th><th>Size</th></tr>");

    if ((dir = opendir(dirname)) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
                append_or_error(ctx, arena, html_response, "<tr><td><a target=\"_blank\" rel=\"noreferer\" href=\"");
                // Add base prefix if we are not using / as static prefix.
                if (strcmp(base_prefix, "/") != 0) {
                    append_or_error(ctx, arena, html_response, base_prefix);
                }

                append_or_error(ctx, arena, html_response, "/");
                append_or_error(ctx, arena, html_response, ent->d_name);
                append_or_error(ctx, arena, html_response, "\">");
                append_or_error(ctx, arena, html_response, ent->d_name);
                append_or_error(ctx, arena, html_response, "</a></td>");

                char filepath[MAX_PATH_LEN] = {0};
                snprintf(filepath, MAX_PATH_LEN, "%s/%s", dirname, ent->d_name);

                struct stat st;
                if (stat(filepath, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) {
                        append_or_error(ctx, arena, html_response, "<td>Directory</td>");
                    } else {
                        append_or_error(ctx, arena, html_response, "<td>");
                        append_or_error(ctx, arena, html_response, format_file_size(st.st_size));
                        append_or_error(ctx, arena, html_response, "</td>");
                    }
                } else {
                    append_or_error(ctx, arena, html_response, "<td>Unknown</td>");
                }
                append_or_error(ctx, arena, html_response, "</tr>");
            }
        }
        closedir(dir);
    } else {
        // Could not open directory
        set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->status = StatusInternalServerError;
        send_string(ctx, "Unable to open directory");
        arena_destroy(arena);
        return;
    }

    append_or_error(ctx, arena, html_response, "</table></body></html>");
    set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->status = StatusOK;
    send_string(ctx, html_response->data);
    arena_destroy(arena);
}

// Flag to enable or disable directory browsing.
static bool browse_enabled = false;

// Enable or disable directory browsing for the server.
// If the requested path is a directory, the server will list the files in the directory.
void enable_directory_browsing(bool enable) {
    browse_enabled = enable;
}

static void staticFileHandler(context_t* ctx) {
    request_t* req = ctx->request;
    Route* route = req->route;

    char* dirname = route->dirname;

    // Replace . and .. with ./ and ../
    if (strcmp(dirname, ".") == 0) {
        dirname = "./";
    } else if (strcmp(dirname, "..") == 0) {
        dirname = "../";
    }

    // Trim the static pattern from the path
    const char* static_path = req->path + strlen(route->pattern);

    // Concatenate the dirname and the static path
    char fullpath[MAX_PATH_LEN] = {0};
    int n;
    if (dirname[strlen(dirname) - 1] == '/') {
        n = snprintf(fullpath, MAX_PATH_LEN, "%s%s", dirname, static_path);
    } else {
        n = snprintf(fullpath, MAX_PATH_LEN, "%s/%s", dirname, static_path);
    }

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

        char index_file[MAX_PATH_LEN + 16] = {0};
        snprintf(index_file, MAX_PATH_LEN + 16, "%s/index.html", filepath);

        if (!path_exists(index_file)) {
            if (browse_enabled) {
                char prefix[MAX_PATH_LEN] = {0};
                snprintf(prefix, MAX_PATH_LEN, "%s%s", route->pattern, static_path);
                serve_directory_listing(ctx, filepath, prefix);
            } else {
                set_header(ctx, CONTENT_TYPE_HEADER, "text/html");
                ctx->status = StatusForbidden;
                send_string(ctx, "<h1>Directory listing is disabled</h1>");
            }
            return;
        } else {
            // Append /index.html to the path
            strncat(filepath, "/index.html", sizeof(filepath) - filepath_len - 1);
        }
    }

    if (path_exists(filepath)) {
        const char* web_ct = get_mimetype(filepath);
        set_header(ctx, CONTENT_TYPE_HEADER, web_ct);
        http_servefile(ctx, filepath);
        return;
    }

    if (notFoundRoute) {
        notFoundRoute->handler(ctx);
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

char* get_ip_address(context_t* ctx) {
    // try the forwarded header
    const char* ip_addr = get_header(ctx, "X-Forwarded-For");
    if (!ip_addr) {
        // try the real ip address
        ip_addr = get_header(ctx, "X-Real-IP");
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

// Pool of read tasks to avoid malloc/free overhead
#define MAX_READ_TASKS (MAXEVENTS * 2)
static read_task read_tasks[MAX_READ_TASKS] = {0};
pthread_mutex_t read_tasks_mutex = PTHREAD_MUTEX_INITIALIZER;

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
    handle_read(task->req, task->client_fd, task->epoll_fd);
    if (task->req->route != NULL && task->client_fd != -1) {
        handle_write(task->req);
    }

    // Put the task back in the pool
    put_read_task(task);
}

__attribute__((constructor())) void init(void) {
    global_middleware_context = map_create(10, key_compare_char_ptr);
    if (!global_middleware_context) {
        LOG_FATAL("Failed to create global_middleware_context\n");
    }

    install_signal_handler();
    init_mime_hashtable();
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
    while (running) {
        // Block indefinitely until we have ready events (-1)
        int nfds = epoll_wait(epoll_fd, events, MAXEVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (server_fd == events[i].data.fd) {
                /* We have a notification on the listening socket, which
                 means one or more incoming connections. */
                while (1) {
                    struct sockaddr internetAddress;
                    socklen_t client_len;
                    int client_fd;

                    client_len = sizeof internetAddress;
                    client_fd = accept(server_fd, &internetAddress, &client_len);

                    if (client_fd == -1) {
                        if (errno == EINTR && running == false) {
                            return -1;  // Interrupted by signal
                        }

                        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                            /* We have processed all incoming connections. */
                            break;
                        } else if (errno == EMFILE) {
                            LOG_ERROR("Too many open file descriptors\n");
                            break;
                            sleep(1);
                        } else {
                            perror("accept");
                            break;
                        }
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
                    // Get a free read task from the pool
                    read_task* task = get_read_task();
                    if (!task) {
                        http_error(events[i].data.fd, StatusInternalServerError,
                                   "Failed to allocate memory for read task");
                        close_connection(events[i].data.fd, epoll_fd);
                        continue;
                    }

                    task->client_fd = events[i].data.fd;
                    task->epoll_fd = epoll_fd;
                    threadpool_add_task(pool, submit_read_task, task);

                } else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                    LOG_ERROR("error on fd %d", events[i].data.fd);
                    close(events[i].data.fd);
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

__attribute__((destructor)) static void epollix_cleanup(void) {
    if (pool) {
        threadpool_wait(pool);
        threadpool_destroy(pool);
    }

    free_static_routes();
    destroy_mime_hashtable();

    if (global_middleware_context) {
        map_destroy(global_middleware_context, true);
    }

    if (epoll_fd != -1)
        close(epoll_fd);

    if (server_fd != -1)
        close(server_fd);

    if (user_cleanup_func) {
        user_cleanup_func();
    }
}
