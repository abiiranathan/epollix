#ifndef C3BE04A4_5606_4AB8_B6B5_9D0E0ED0C1DF
#define C3BE04A4_5606_4AB8_B6B5_9D0E0ED0C1DF

#ifdef __cplusplus
extern "C" {
#endif

#include "route.h"
#include "types.h"

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

typedef enum {
    http_ok,
    http_max_headers_exceeded,
    http_max_header_name_exceeded,
    http_max_header_value_exceeded,
    http_memory_alloc_failed,
} http_error_t;

// Parse request headers from text.
http_error_t parse_request_headers(request_t* req, const char* header_text, size_t length);

// Parse URL query parameters from a query string.
// Populates the map.
bool parse_url_query_params(char* query, map* query_params);

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str);

// Decode a percent-encoded uri into dst.
void decode_uri(const char* src, char* dst, size_t dst_size);

// Handle Request and send response to the client.
void handle_request(request_t* req);

// Set a NotFoundHandler. This is handy for SPAs.
// It will be called if the RouteMatcher returns NULL.
Route* route_notfound(Handler h);

// Free up resources allocated by the request.
void request_destroy(request_t* req);

#ifdef __cplusplus
}
#endif
#endif /* C3BE04A4_5606_4AB8_B6B5_9D0E0ED0C1DF */
