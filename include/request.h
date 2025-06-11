#ifndef REQUEST_H
#define REQUEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "route.h"

#define KEEPALIVE_REQUESTED        (1 << 1)
#define CONNECTION_CLOSE_REQUESTED (1 << 2)

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

// Parse request headers from text.
bool parse_request_headers(const char* header_text, size_t length, Headers* headers);

// Parse URL query parameters from a query string.
// Populates the map.
void parse_url_query_params(char* query, QueryParams* query_params);

// Get the value of a query parameter by name.
const char* get_query_param(Request* req, const char* name);

// Get the value of a path parameter by name.
const char* get_param(Request* req, const char* name);

// Get the content type of the request.
const char* get_content_type(Request* req);

// Handle Request and send response to the client.
bool parse_http_request(Request* req);

// Set a NotFoundHandler. This is handy for SPAs.
// It will be called if the RouteMatcher returns NULL.
Route* route_notfound(Handler h);

#ifdef __cplusplus
}
#endif
#endif /* REQUEST_H */
