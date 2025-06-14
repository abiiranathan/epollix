#include "../include/request.h"
#include "../include/route.h"

#include <assert.h>
#include <cpuid.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <immintrin.h>  // AVX intrinsics

Route* notFoundRoute = NULL;  // 404 Route.

typedef enum { STATE_HEADER_NAME, STATE_HEADER_VALUE, STATE_HEADER_END } HeaderState;

// Function to report http errors while still parsing the request.
extern void http_error(int client_fd, http_status status, const char* message);

// Create a new request object.
void request_init(Request* req, int client_fd, int epoll_fd, Headers* headers, QueryParams* query_params) {
    memset(req, 0, sizeof(Request));  // zero req struct

    // Set defaults
    req->client_fd    = client_fd;     // Attch client file descriptor
    req->epoll_fd     = epoll_fd;      // Attach epoll fd.
    req->method       = M_INVALID;     // Initialize http method with Invalid.
    req->query_params = query_params;  // Set query parameters
    req->headers      = headers;       // Set headers
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

    // match query parameters by exact key name.
    return headers_value_exact(req->query_params, (void*)name);
}

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

header_error_t parse_request_headers(const char* header_text, size_t length, Headers* headers, int* flags,
                                     size_t* content_length) {
    assert(content_length);
    assert(flags);

    const char* ptr = header_text;
    const char* end = ptr + length;

    char name[MAX_HEADER_NAME_LENGTH];
    char value[MAX_HEADER_VALUE_LENGTH];

    while (ptr < end) {
        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon) break;  // we are done.

        size_t name_len = colon - ptr;
        if (unlikely(name_len + 1 > MAX_HEADER_NAME_LENGTH)) {
            return header_name_toolong;
        }

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';  // null-terminate name

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (unlikely(!eol || eol + 1 >= end || eol[1] != '\n')) break;

        size_t value_len = eol - ptr;
        if (unlikely(value_len + 1 > MAX_HEADER_VALUE_LENGTH)) {
            return header_value_toolong;
        }

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';  // null-terminate value
        headers_append(headers, name, value);
        ptr = eol + 2;  // Skip CRLF

        // Check for special headers
        if (strcasecmp(name, "connection") == 0) {
            if (strcasestr(value, "keep-alive")) {
                *flags |= KEEPALIVE_REQUESTED;
            } else if (strcasestr(value, "close")) {
                *flags &= ~KEEPALIVE_REQUESTED;
            }
        } else if (strcasecmp(name, "content-length") == 0) {
            *content_length = strtoul(value, NULL, 10);
        } else if (strcasecmp(name, "transfer-encoding") == 0) {
            if (strcasestr(value, "chunked")) {
                *flags |= CHUNKED_ENCODING;
            }
        }
    }
    return header_success;
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

void parse_url_query_params(char* query, QueryParams* query_params) {
    char* save_ptr1 = NULL;
    char* save_ptr2 = NULL;
    char* pair      = strtok_r(query, "&", &save_ptr1);

    while (pair != NULL) {
        // Split into key and value
        char* key   = strtok_r(pair, "=", &save_ptr2);
        char* value = strtok_r(NULL, "", &save_ptr2);  // Get rest of string after first '='

        if (key != NULL) {
            headers_append(query_params, key, value ? value : "");
        }
        pair = strtok_r(NULL, "&", &save_ptr1);
    }
}

// Allocate memory for the body and read it from the socket
bool allocate_and_read_body(int client_fd, uint8_t** body, size_t body_size, size_t initial_read,
                            const char* initial_body) {

    *body = (uint8_t*)malloc(body_size + 1);
    if (!*body) {
        perror("unable to allocate memory for the request body");
        return false;
    }

    // copy the initial body read (with the first recv) if any
    if (initial_read > 0) {
        memcpy(*body, initial_body, initial_read);
    }

    size_t total_read = initial_read;

    // read the remaining bytes
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

static bool _404_registered = false;
Route* route_notfound(Handler h) {
    if (_404_registered) {
        LOG_FATAL("registration of more than one 404 handler\n");
    }

    notFoundRoute   = route_get("__notfound__", h);
    _404_registered = true;
    return notFoundRoute;
}

static inline char* find_end_of_headers(const char* headers, size_t bytes_read) {
    // Ensure we have at least 4 bytes to check
    if (bytes_read < 4) {
        return NULL;
    }

    const char* ptr = headers;
    const char* end = headers + bytes_read - 3;  // -3 because we need 4 bytes for \r\n\r\n

    // AVX2 vectors for pattern matching
    const __m256i cr_vec = _mm256_set1_epi8('\r');

    // Process 32-byte chunks with AVX2
    while (ptr + 32 <= end) {
        __m256i chunk = _mm256_loadu_si256((const __m256i*)ptr);

        // Find all CR positions
        __m256i cr_cmp   = _mm256_cmpeq_epi8(chunk, cr_vec);
        unsigned cr_mask = _mm256_movemask_epi8(cr_cmp);

        // Check each CR position for potential \r\n\r\n pattern
        while (cr_mask != 0) {
            unsigned cr_idx    = __builtin_ctz(cr_mask);
            const char* cr_pos = ptr + cr_idx;

            // Check if we have enough bytes remaining for \r\n\r\n
            if (cr_pos + 3 < headers + bytes_read) {
                // Check for exact pattern \r\n\r\n
                if (cr_pos[0] == '\r' && cr_pos[1] == '\n' && cr_pos[2] == '\r' && cr_pos[3] == '\n') {
                    return (char*)cr_pos;
                }
            }

            // Clear this bit and continue
            cr_mask &= ~(1u << cr_idx);
        }

        ptr += 32;
    }

    // Handle remaining bytes with scalar search
    while (ptr <= end) {
        if (ptr[0] == '\r' && ptr[1] == '\n' && ptr[2] == '\r' && ptr[3] == '\n') {
            return (char*)ptr;
        }
        ptr++;
    }

    return NULL;
}

parse_result parse_http_request(Request* req) {
    int client_fd                          = req->client_fd;
    uint8_t* body                          = NULL;  // Request body (dynamically allocated)
    size_t total_read                      = 0;     // Total bytes read
    size_t header_capacity                 = 0;     // Size of the headers in the buffer (including the initial read)
    static __thread char fist_buffer[4096] = {0};   // Headers + (possibly body)

    ssize_t bytes_read = recv(client_fd, fist_buffer, sizeof(fist_buffer) - 1, MSG_WAITALL);
    if (bytes_read <= 0) {
        return (parse_result){StatusBadRequest, "Unexpected closure of client socket"};
    }

    // null-terminate header data.
    fist_buffer[bytes_read] = '\0';

    char* end_of_headers = find_end_of_headers(fist_buffer, bytes_read);
    if (!end_of_headers) {
        return (parse_result){StatusBadRequest, "Invalid header termination"};
    }

    char *method = NULL, *uri = NULL, *http_version = NULL, *header_start = NULL;
    if (!parse_request_line(fist_buffer, &method, &uri, &http_version, &header_start)) {
        return (parse_result){StatusBadRequest, "Invalid http status line"};
    }

    req->method = method_fromstring(method);
    if (req->method == M_INVALID) {
        return (parse_result){StatusBadRequest, "Unsupported http method"};
    }

    // Decode the URL with percent_decoding if needed
    static __thread char decoded[1024];
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
        query_string++;        // Now points to query string portion
        if (*query_string != '\0' && strstr(query_string, "=")) {
            parse_url_query_params(query_string, req->query_params);
        }
    }

    // Store the path (already terminated at '?' if there was one)
    req->path = cstr_new(decoded_uri);
    if (!req->path) {
        return (parse_result){StatusInternalServerError, "Error allocating memory for path"};
    }

    header_error_t code;
    code = parse_request_headers(header_start, header_capacity - 4, req->headers, &req->flags, &req->content_length);
    if (code != header_success) {
        return (parse_result){StatusInternalServerError, header_error_string(code)};
    }

    req->route = default_route_matcher(req->method, cstr_data(req->path));
    if (req->route == NULL && notFoundRoute != NULL) req->route = notFoundRoute;
    if (req->route == NULL) {
        return (parse_result){StatusNotFound, "Not Found"};
    }

    // Compute header capacity including \r\n\r\n
    header_capacity = end_of_headers - fist_buffer + 4;
    total_read      = bytes_read - header_capacity;

    bool has_body = !is_safe_method(req->method) && req->content_length > 0;
    if (has_body) {
        if (!allocate_and_read_body(client_fd, &body, req->content_length, total_read, fist_buffer + header_capacity)) {
            return (parse_result){StatusInternalServerError, "Error allocating memory for body"};
        }
    }

    req->body = body;  // set request body
    strlcpy(req->http_version, http_version, sizeof(req->http_version));

    return (parse_result){StatusOK, NULL};
}
