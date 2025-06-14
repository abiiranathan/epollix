#ifndef REQUEST_H
#define REQUEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "route.h"

#define KEEPALIVE_REQUESTED        (1 << 1)
#define CONNECTION_CLOSE_REQUESTED (1 << 2)
#define CHUNKED_ENCODING           (1 << 3)

typedef struct request {
    int client_fd;              // Peer connection file descriptor
    int epoll_fd;               // epoll file descriptor
    HttpMethod method;          // Http request method as an integer enum
    size_t content_length;      // Content length or size of body
    struct Route* route;        // Matching route
    Headers* headers;           // Request headers.
    QueryParams* query_params;  // Query parameters.
    char http_version[12];      // Http version (e.g., "HTTP/1.1")
    cstr* path;                 // Request path and query string (dynamically allocated)
    uint8_t* body;              // Body of the request (dynamically allocated)

    // Flags
    int flags;  // Keep-alive / connection close flags
} Request;

// Initialize a new request object and allocate headers array.
void request_init(Request* req, int client_fd, int epoll_fd, Headers* headers, QueryParams* query_params);

static inline void request_destroy(Request* req) {
    if (req->path) cstr_free(req->path);
    if (req->body) free(req->body);   // free allocated req body
    headers_free(req->headers);       // free request headers map resources
    headers_free(req->query_params);  // free query params map resources
}

typedef enum : uint8_t {
    header_success,        // Headers parse successfully
    header_malformed,      // Missing colon or \r\n
    header_name_toolong,   // Header name too long.
    header_value_toolong,  // Header value too long.
    header_invalid_char,   // Invalid characters in the header.
} header_error_t;

// Parse request headers from header text without terminating \r\n\r\n.
header_error_t parse_request_headers(const char* header_text, size_t length, Headers* headers, int* flags,
                                     size_t* content_length);

static inline const char* header_error_string(header_error_t code) {
    const char* msg = "Failed to parse request headers";
    switch (code) {
        case header_success:
            unreachable();
        case header_invalid_char:
            msg = "Invalid characters in header";
            break;
        case header_name_toolong:
            msg = "Header name is too long";
            break;
        case header_value_toolong:
            msg = "Header value is too long";
            break;
        case header_malformed:
            msg = "Malformed header";
            break;
    }
    return msg;
}

// Parse URL query parameters from a query string.
// Populates the map.
void parse_url_query_params(char* query, QueryParams* query_params);

// Get the value of a query parameter by name.
const char* get_query_param(Request* req, const char* name);

// Get the value of a path parameter by name.
const char* get_param(Request* req, const char* name);

// Get the content type of the request.
const char* get_content_type(Request* req);

typedef struct parse_result {
    http_status status;     // Http status code.
    const char* error_msg;  // Error message
} parse_result;

// Handle Request and send response to the client.
// Returns parse result with status as StatusOK if successful.
parse_result parse_http_request(Request* req);

// Set a NotFoundHandler. This is handy for SPAs.
// It will be called if the RouteMatcher returns NULL.
Route* route_notfound(Handler h);

#ifdef __cplusplus
}
#endif
#endif /* REQUEST_H */
