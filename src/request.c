#include "../include/request.h"
#include "../include/route.h"

#include <cpuid.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

Route* notFoundRoute = NULL;  // 404 Route.

typedef enum { STATE_HEADER_NAME, STATE_HEADER_VALUE, STATE_HEADER_END } HeaderState;

// Function to report http errors while still parsing the request.
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

Headers* parse_request_headers(const char* header_text, size_t length) {
    if (!header_text || length == 0) {
        return NULL;
    }

    Headers* headers = headers_new(32);
    if (!headers) {
        LOG_ERROR("Failed to allocate headers structure");
        return NULL;
    }

    const char* current   = header_text;
    const char* const end = header_text + length;

    while (current < end) {
        // Find header name (until colon)
        const char* colon = memchr(current, ':', end - current);
        if (!colon) break;

        // Extract header name
        size_t name_length = colon - current;
        if (name_length >= MAX_HEADER_NAME_LENGTH) {
            LOG_ERROR("Header name exceeds maximum length");
            goto error_cleanup;
        }

        char header_name[MAX_HEADER_NAME_LENGTH];
        memcpy(header_name, current, name_length);
        header_name[name_length] = '\0';

        // Skip colon and whitespace
        current = colon + 1;
        while (current < end && *current == ' ') {
            current++;
        }

        // Find end of line (CRLF)
        const char* line_end = memchr(current, '\r', end - current);
        if (!line_end || line_end + 1 >= end || line_end[1] != '\n') {
            LOG_ERROR("Malformed header line ending");
            goto error_cleanup;
        }

        // Extract header value
        size_t value_length = line_end - current;
        if (value_length >= MAX_HEADER_VALUE_LENGTH) {
            LOG_ERROR("Header value exceeds maximum length");
            goto error_cleanup;
        }

        char header_value[MAX_HEADER_VALUE_LENGTH];
        memcpy(header_value, current, value_length);
        header_value[value_length] = '\0';

        // Add to headers collection
        if (!headers_append(headers, header_name, header_value)) {
            LOG_ERROR("Failed to add header to collection");
            goto error_cleanup;
        }

        // Move to next line
        current = line_end + 2;
    }

    return headers;

error_cleanup:
    headers_free(headers);
    return NULL;
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

bool parse_url_query_params(LArena* arena, char* query, Map* query_params) {
    char* key   = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;
    bool success = true;
    char* token  = strtok_r(query, "&", &save_ptr);

    while (token != NULL) {
        key   = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* queryName = larena_alloc_string(arena, key);
            if (queryName == NULL) {
                success = false;
                break;
            }

            char* queryValue = larena_alloc_string(arena, value);
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

// Map configuration for Query Parameters.
// key and value are allocated in pool and thus should not be freed.
static const MapConfig* cfg = &(MapConfig){
    .key_free     = NOFREE,
    .value_free   = NOFREE,
    .key_compare  = key_compare_char_ptr,
    .key_len_func = key_len_char_ptr,
};

// Allocate memory for the body and read it from the socket
bool allocate_and_read_body(int client_fd, uint8_t** body, size_t body_size, size_t initial_read,
                            const char* initial_body) {
    *body = (uint8_t*)malloc(body_size + 1);
    if (!*body) {
        perror("unable to allocate memory for the request body");
        return false;
    }

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
                perror("error reading body");
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

#define SEND_ERR(client_fd, status, msg)                                                                               \
    http_error((client_fd), (status), (msg));                                                                          \
    return false

#define BAD_REQ(client_fd, msg)    SEND_ERR(client_fd, StatusBadRequest, msg);
#define SERVER_ERR(client_fd, msg) SEND_ERR(client_fd, StatusInternalServerError, msg);

static inline char* find_end_of_headers(const char* headers, size_t bytes_read) {
    // Ensure we have at least 4 bytes to check
    if (bytes_read < 4) return NULL;

    // Scan for \r\n\r\n
    for (size_t i = 0; i <= bytes_read - 4; i++) {
        if (headers[i] == '\r' && headers[i + 1] == '\n' && headers[i + 2] == '\r' && headers[i + 3] == '\n') {
            return (char*)&headers[i];
        }
    }
    return NULL;
}

bool parse_http_request(Request* req, LArena* arena) {
    int client_fd          = req->client_fd;
    Map* query_params      = NULL;       // Query parameters
    uint8_t* body          = NULL;       // Request body (dynamically allocated)
    size_t total_read      = 0;          // Total bytes read
    HttpMethod httpMethod  = M_INVALID;  // Http method
    size_t header_capacity = 0;          // Size of the headers in the buffer (including the initial read)
    size_t body_size       = 0;          // Size of the request body (from the Content-Length header)

    char headers[4096];
    ssize_t bytes_read = recv(client_fd, headers, sizeof(headers) - 1, MSG_WAITALL);
    if (bytes_read <= 0) {
        BAD_REQ(client_fd, "Error receiving data from client socket");
    }
    headers[bytes_read] = '\0';

    char *method, *uri, *http_version, *header_start, *end_of_headers;
    if (!parse_request_line(headers, &method, &uri, &http_version, &header_start)) {
        BAD_REQ(client_fd, ERR_INVALID_STATUS_LINE);
    }

    httpMethod = method_fromstring(method);
    if (httpMethod == M_INVALID) {
        BAD_REQ(client_fd, ERR_INVALID_STATUS_LINE);
    }

    // memmem is rather slow.
    // end_of_headers = (char*)memmem(headers, bytes_read, "\r\n\r\n", 4);
    end_of_headers = find_end_of_headers(headers, bytes_read);
    if (!end_of_headers) {
        BAD_REQ(client_fd, "Invalid Http Payload");
    }

    header_capacity = end_of_headers - headers + 4;
    body_size       = parse_content_length(header_start, end_of_headers);

    const char* decoded_uri = uri;
    char decoded[1024];
    if (strstr(uri, "%")) {
        url_percent_decode(uri, decoded, sizeof(decoded));
        decoded_uri = decoded;
    }

    // Parse URI
    req->path = cstr_new(decoded_uri);
    if (!req->path) {
        return false;
    }

    const char* path_ptr = cstr_data_const(req->path);
    char* query_string   = strchr(path_ptr, '?');
    if (query_string) {
        *query_string = '\0';
        (*query_string)++;

        // Create a map of query params
        query_params = map_create(cfg);
        if (!query_params) {
            return false;
        }

        if (!parse_url_query_params(arena, query_string, query_params)) {
            map_destroy(query_params);
            return false;
        }
    }

    req->headers = parse_request_headers(header_start, header_capacity - 4);
    if (!req->headers) {
        SERVER_ERR(client_fd, "Failed to parse request headers");
    }

    req->route = default_route_matcher(httpMethod, path_ptr);
    if (req->route == NULL && !handle_not_found(req, method, http_version, path_ptr)) {
        return false;
    }

    total_read = bytes_read - header_capacity;
    if (!is_safe_method(httpMethod) && body_size > 0) {
        if (!allocate_and_read_body(client_fd, &body, body_size, total_read, headers + header_capacity)) {
            SERVER_ERR(client_fd, "Failed to read request body");
        }
    }

    req->body           = body;          // set request body
    req->content_length = body_size;     // set content length
    req->query_params   = query_params;  // set params in the request
    req->method         = httpMethod;    // set request method

    // copy http_version
    strncpy(req->http_version, http_version, sizeof(req->http_version) - 1);
    req->http_version[sizeof(req->http_version) - 1] = '\0';

    return true;
}
