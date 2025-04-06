#include "../include/request.h"
#include "../include/route.h"

#include <cpuid.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

// Not found route.
Route* notFoundRoute = NULL;

typedef enum { STATE_HEADER_NAME, STATE_HEADER_VALUE, STATE_HEADER_END } HeaderState;

extern void http_error(int client_fd, http_status status, const char* message);

// Create a new request object.
void request_init(Request* req, int client_fd, int epoll_fd) {
    req->client_fd      = client_fd;
    req->epoll_fd       = epoll_fd;
    req->path           = NULL;
    req->method         = M_INVALID;
    req->route          = NULL;
    req->content_length = 0;
    req->body           = NULL;
    req->query_params   = NULL;
    req->headers        = NULL;
}

// Get the content type of the request.
const char* get_content_type(Request* req) {
    return headers_value(req->headers, CONTENT_TYPE_HEADER);
}

const char* get_param(Request* req, const char* name) {
    if (!req->route->params) {
        return NULL;
    }
    return get_path_param(req->route->params, name);
}

// Get the value of a query parameter by name.
const char* get_query_param(Request* req, const char* name) {
    if (!req->query_params) {
        return NULL;
    }

    return map_get(req->query_params, (void*)name);
}

Headers parse_request_headers(const char* header_text, size_t length) {
    Headers headers = headers_new(32);
    if (!headers) {
        LOG_ERROR("Failed to create headers");
        return NULL;
    }

    const char* ptr = header_text;
    const char* end = ptr + length;

    char name[MAX_HEADER_NAME_LEN];
    char value[2048];

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon) break;

        size_t name_len = colon - ptr;
        if (name_len + 1 > sizeof(name)) {
            LOG_ERROR("Header name is too long\n");
            headers_free(headers);
            return NULL;
        }

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        size_t value_len = eol - ptr;
        if (value_len + 1 > sizeof(value)) {
            headers_free(headers);
            LOG_ERROR("Header value is too long");
            return NULL;
        }

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';

        // Add header to the map
        headers_append(headers, name, value);
        ptr = eol + 2;  // Skip CRLF
    }

    return headers;
}

// Parse the request line (first line of the HTTP request)
static bool parse_request_line(char* headers, char** method, char** uri, char** http_version, char** header_start) {
    *method = headers;
    *uri    = strchr(headers, ' ');
    if (!*uri) return false;
    **uri = '\0';
    (*uri)++;

    *http_version = strchr(*uri, ' ');
    if (!*http_version) return false;
    **http_version = '\0';
    (*http_version)++;

    *header_start = strstr(*http_version, "\r\n");
    if (!*header_start) return false;
    **header_start = '\0';
    *header_start += 2;

    return true;
}

// Parse the Content-Length header
static size_t parse_content_length(const char* header_start, const char* end_of_headers) {
    const char* content_length_header = strcasestr(header_start, "content-length:");
    if (!content_length_header || content_length_header >= end_of_headers) {
        return 0;
    }
    return strtoul(content_length_header + 15, NULL, 10);
}

bool parse_url_query_params(Arena* arena, char* query, map* query_params) {
    char* key   = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;
    bool success = true;
    char* token  = strtok_r(query, "&", &save_ptr);

    while (token != NULL) {
        key   = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* queryName = arena_alloc_string(arena, key);
            if (queryName == NULL) {
                success = false;
                break;
            }

            char* queryValue = arena_alloc_string(arena, value);
            if (queryValue == NULL) {
                success = false;
                break;
            }

            map_set(query_params, queryName, queryValue);
        }
        token = strtok_r(NULL, "&", &save_ptr);
    }
    return success;
}

// Parse the URI, extracting path and query parameters
static bool parse_uri(Arena* arena, const char* decoded_uri, char** path, char** query, map** query_params) {
    *path = arena_alloc_string(arena, decoded_uri);
    if (!*path) {
        return false;
    }

    *query = strchr(*path, '?');
    if (*query) {
        **query = '\0';
        (*query)++;

        // key and value are allocated in pool and thus should not be freed.
        bool free_entries = false;
        *query_params     = map_create(4, key_compare_char_ptr, free_entries);
        if (!*query_params) {
            return false;
        }

        if (!parse_url_query_params(arena, *query, *query_params)) {
            map_destroy(*query_params);
            return false;
        }
    } else {
        *query_params = NULL;
    }

    return true;
}

// Allocate memory for the body and read it from the socket
bool allocate_and_read_body(Arena* arena, int client_fd, uint8_t** body, size_t body_size, size_t initial_read,
                            const char* initial_body) {
    *body = (uint8_t*)arena_alloc(arena, body_size + 1);
    if (!*body) return false;

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
void set_request_data(Arena* arena, Request* req, uint8_t* body, size_t content_length, map* query_params,
                      HttpMethod httpMethod, const char* http_version, const char* path) {

    req->body           = body;            // set request body
    req->content_length = content_length;  // set content length
    req->query_params   = query_params;    // set params in the request
    req->headers        = NULL;            // headers are allocated in the arena when parsing headers
    req->method         = httpMethod;      // set request method

    strncpy(req->http_version, http_version, sizeof(req->http_version) - 1);
    req->http_version[sizeof(req->http_version) - 1] = '\0';

    req->path = arena_alloc_string(arena, path);
    LOG_ASSERT(req->path != NULL, "malloc failed to allocate request path");
}

// Handle the case when a route is not found
bool handle_not_found(Request* req, const char* method, const char* http_version, const char* path) {
    if (notFoundRoute) {
        req->route = notFoundRoute;
        return true;
    } else {
        fprintf(stderr, "%s - %s %s 404 Not Found\n", method, http_version, path);
        http_error(req->client_fd, StatusNotFound, "Not Found\n");
        return false;
    }
}

bool registered = false;
Route* route_notfound(Handler h) {
    if (registered) {
        LOG_FATAL("registration of more than one 404 handler\n");
    }

    notFoundRoute = route_get("__notfound__", h);
    registered    = true;
    return notFoundRoute;
}

// Check if the CPU supports AVX
int check_avx() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return ecx & bit_AVX;
}

// handle the request and send response.
void process_request(Request* req, Arena* arena) {
    int client_fd = req->client_fd;

    char* path             = NULL;       // Request path
    char* query            = NULL;       // Query string
    map* query_params      = NULL;       // Query parameters
    uint8_t* body          = NULL;       // Request body (dynamically allocated)
    size_t total_read      = 0;          // Total bytes read
    HttpMethod httpMethod  = M_INVALID;  // Http method
    size_t header_capacity = 0;          // Size of the headers in the buffer (including the initial read)
    size_t body_size       = 0;          // Size of the request body (from the Content-Length header)

    char headers[4096];
    ssize_t bytes_read = recv(client_fd, headers, sizeof(headers) - 1, MSG_WAITALL);
    if (bytes_read <= 0) {
        http_error(client_fd, StatusBadRequest, "Error receiving data from client socket");
        return;
    }
    headers[bytes_read] = '\0';

    char *method, *uri, *http_version, *header_start, *end_of_headers;
    if (!parse_request_line(headers, &method, &uri, &http_version, &header_start)) {
        http_error(client_fd, StatusBadRequest, ERR_INVALID_STATUS_LINE);
        return;
    }

    httpMethod = method_fromstring(method);
    if (httpMethod == M_INVALID) {
        http_error(client_fd, StatusBadRequest, ERR_INVALID_STATUS_LINE);
        return;
    }

    // memmem  is slower than strstr but safer!
    end_of_headers = (char*)memmem(headers, bytes_read, "\r\n\r\n", 4);
    if (!end_of_headers) {
        http_error(client_fd, StatusBadRequest, "Invalid Http Payload");
        return;
    }

    header_capacity = end_of_headers - headers + 4;
    body_size       = parse_content_length(header_start, end_of_headers);

    char* decoded_uri = uri;
    char decoded[1024];
    if (strstr(uri, "%")) {
        url_percent_decode(uri, decoded, sizeof(decoded));
        decoded_uri = decoded;
    }

    if (!parse_uri(arena, decoded_uri, &path, &query, &query_params)) {
        http_error(client_fd, StatusInternalServerError, "error parsing query params");
        return;
    }

    req->route = default_route_matcher(httpMethod, path);
    if (req->route == NULL && !handle_not_found(req, method, http_version, path)) {
        return;
    }

    total_read = bytes_read - header_capacity;
    if (!is_safe_method(httpMethod) && body_size > 0) {
        if (!allocate_and_read_body(arena, client_fd, &body, body_size, total_read, headers + header_capacity)) {
            http_error(client_fd, StatusInternalServerError, "Failed to read request body");
            return;
        }
    }

    set_request_data(arena, req, body, body_size, query_params, httpMethod, http_version, path);

    Headers parsed_headers = parse_request_headers(header_start, header_capacity - 4);
    if (parsed_headers == NULL) {
        http_error(client_fd, StatusInternalServerError, "Failed to parse request headers");
        return;
    }

    req->headers = parsed_headers;
}
