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
    return headers_value(req->query_params, (void*)name);
}

bool parse_request_headers(const char* header_text, size_t length, Headers* headers) {
    const char* ptr = header_text;
    const char* end = ptr + length;

    char name[MAX_HEADER_NAME_LENGTH];    // Buffer to hold header name
    char value[MAX_HEADER_VALUE_LENGTH];  // Buffer to hold header value

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon) break;

        size_t name_len = colon - ptr;
        if (name_len + 1 > MAX_HEADER_NAME_LENGTH) {
            LOG_ERROR("Header name is too long\n");
            return false;
        }

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';  // null-terminate name

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n') break;

        size_t value_len = eol - ptr;
        if (value_len + 1 > MAX_HEADER_VALUE_LENGTH) {
            LOG_ERROR("Header value is too long");
            return NULL;
        }

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';  // null-terminate value
        headers_append(headers, name, value);
        ptr = eol + 2;  // Skip CRLF
    }
    return true;
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

bool parse_url_query_params(char* query, QueryParams* query_params) {
    char* save_ptr1 = NULL;
    char* save_ptr2 = NULL;
    char* pair      = strtok_r(query, "&", &save_ptr1);

    while (pair != NULL) {
        // Split into key and value
        char* key   = strtok_r(pair, "=", &save_ptr2);
        char* value = strtok_r(NULL, "", &save_ptr2);  // Get rest of string after first '='

        // Handle cases:
        // 1. key=value (normal case)
        // 2. key= (empty value)
        // 3. key (no equals)
        if (key != NULL) {
            if (!headers_append(query_params, key, value ? value : "")) {
                return false;
            }
        }
        pair = strtok_r(NULL, "&", &save_ptr1);
    }

    return true;
}

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

bool parse_http_request(Request* req) {
    int client_fd          = req->client_fd;
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

    // Decode the URL with percent_decoding if needed
    char decoded[1024];
    char* decoded_uri   = uri;  // Default to original URI
    bool needs_decoding = strstr(uri, "%") != NULL;

    if (needs_decoding) {
        url_percent_decode(uri, decoded, sizeof(decoded) - 1);
        decoded_uri = decoded;
    }

    // Extract path and query string
    char* query_string = strchr(decoded_uri, '?');
    if (query_string) {
        *query_string = '\0';  // Terminate path at question mark
        query_string++;        // Now points to query string

        // Only parse query params if there's actually content after the ?
        if (*query_string != '\0' && strstr(query_string, "=")) {
            req->query_params = kv_new();
            if (!req->query_params) {
                return false;
            }

            // Parse ONLY the query string portion
            if (!parse_url_query_params(query_string, req->query_params)) {
                return false;
            }
        }
    }

    // Store the path (already terminated at '?' if there was one)
    req->path = cstr_new(decoded_uri);
    if (!req->path) {
        return false;
    }

    req->headers = kv_new();
    if (!req->headers) {
        SERVER_ERR(client_fd, "Failed to parse request headers");
    }

    if (!parse_request_headers(header_start, header_capacity - 4, req->headers)) {
        SERVER_ERR(client_fd, "Failed to parse request headers");
    }

    req->route = default_route_matcher(httpMethod, cstr_data(req->path));
    if (req->route == NULL && !handle_not_found(req, method, http_version, cstr_data(req->path))) {
        return false;
    }

    total_read = bytes_read - header_capacity;
    if (!is_safe_method(httpMethod) && body_size > 0) {
        if (!allocate_and_read_body(client_fd, &body, body_size, total_read, headers + header_capacity)) {
            SERVER_ERR(client_fd, "Failed to read request body");
        }
    }

    req->body           = body;        // set request body
    req->content_length = body_size;   // set content length
    req->method         = httpMethod;  // set request method
    // copy http_version
    strncpy(req->http_version, http_version, sizeof(req->http_version) - 1);
    req->http_version[sizeof(req->http_version) - 1] = '\0';

    return true;
}
