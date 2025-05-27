#ifndef REQUEST_H
#define REQUEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "route.h"

typedef struct request {
    int client_fd;          // Peer connection file descriptor
    int epoll_fd;           // epoll file descriptor
    HttpMethod method;      // Http request method as an integer enum
    size_t content_length;  // Content length or size of body
    struct Route* route;    // Matching route
    Headers* headers;       // Request headers.
    Map* query_params;      // Query parameters (consider replacing with a more efficient structure)
    char http_version[12];  // Http version (e.g., "HTTP/1.1")
    cstr* path;             // Request path and query string (dynamically allocated)
    uint8_t* body;          // Body of the request (dynamically allocated)
} Request;

// Initialize a new request object and allocate headers array.
void request_init(Request* req, int client_fd, int epoll_fd);

// Parse request headers from text.
Headers* parse_request_headers(const char* header_text, size_t length);

// Parse URL query parameters from a query string.
// Populates the map.
bool parse_url_query_params(LArena* arena, char* query, Map* query_params);

// Get the value of a query parameter by name.
const char* get_query_param(Request* req, const char* name);

// Get the value of a path parameter by name.
const char* get_param(Request* req, const char* name);

// Get the content type of the request.
const char* get_content_type(Request* req);

// Handle Request and send response to the client.
bool parse_http_request(Request* req, LArena* arena);

// Set a NotFoundHandler. This is handy for SPAs.
// It will be called if the RouteMatcher returns nullptr.
Route* route_notfound(Handler h);

#ifdef __cplusplus
}
#endif
#endif /* REQUEST_H */
