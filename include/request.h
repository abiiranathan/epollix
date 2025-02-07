#ifndef C3BE04A4_5606_4AB8_B6B5_9D0E0ED0C1DF
#define C3BE04A4_5606_4AB8_B6B5_9D0E0ED0C1DF

#ifdef __cplusplus
extern "C" {
#endif

#include "route.h"
#include "types.h"

typedef struct request {
    int client_fd;                      // Peer connection file descriptor
    int epoll_fd;                       // epoll file descriptor
    char* path;                         // Request path and query string (dynamically allocated)
    HttpMethod method;                  // Http request method as an integer enum
    struct Route* route;                // Matching route
    size_t content_length;              // Content length or size of body
    uint8_t* body;                      // Body of the request (dynamically allocated)
    char http_version[12];              // Http version (e.g., "HTTP/1.1")
    uint8_t header_count;               // Number of headers
    header_t headers[MAX_REQ_HEADERS];  // Request headers
    map* query_params;                  // Query parameters (consider replacing with a more efficient structure)
} Request;

typedef enum {
    http_ok,
    http_max_headers_exceeded,
    http_memory_alloc_failed,
} http_error_t;

// Initialize a new request object and allocate headers array.
void request_init(Request* req, int client_fd, int epoll_fd);

// Free up resources allocated by the request.
// The request itself is on the stack and should not be freed.
void request_destroy(Request* req);

// Parse request headers from text.
http_error_t parse_request_headers(Request* req, const char* header_text, size_t length);

// Parse URL query parameters from a query string.
// Populates the map.
bool parse_url_query_params(char* query, map* query_params);

// Get request header value by name.
const char* get_request_header(Request* req, const char* name);

// Get the value of a query parameter by name.
const char* get_query_param(Request* req, const char* name);

// Get the value of a path parameter by name.
const char* get_param(Request* req, const char* name);

// Get the content type of the request.
const char* get_content_type(Request* req);

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str);

// Decode a percent-encoded uri into dst.
void decode_uri(const char* src, char* dst, size_t dst_size);

// Handle Request and send response to the client.
void process_request(Request* req);

// Set a NotFoundHandler. This is handy for SPAs.
// It will be called if the RouteMatcher returns nullptr.
Route* route_notfound(Handler h);

#ifdef __cplusplus
}
#endif
#endif /* C3BE04A4_5606_4AB8_B6B5_9D0E0ED0C1DF */
