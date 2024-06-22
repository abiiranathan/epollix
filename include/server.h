#ifndef C09A2944_5DDC_4879_9E04_7CF7FB027FC3
#define C09A2944_5DDC_4879_9E04_7CF7FB027FC3

#define _GNU_SOURCE 1

#include <solidc/map.h>
#include "constants.h"
#include "method.h"
#include "mime.h"
#include "multipart.h"
#include "params.h"
#include "status.h"

#define UNUSED(var) ((void)var)

typedef struct header {
    char name[MAX_HEADER_NAME];    // Header key
    char value[MAX_HEADER_VALUE];  // Header value
} header_t;

typedef struct request {
    int client_fd;        // Peer connection file descriptor
    int epoll_fd;         // epoll file descriptor.
    HttpMethod method;    // Http request method as an integer enum;
    char method_str[16];  // Http request method

    char path[1024];        // Request path and query string
    char http_version[16];  // Http version

    size_t header_count;                // Number of headers
    header_t headers[MAX_REQ_HEADERS];  // Request headers

    size_t content_length;  // Content length or size of body
    uint8_t* body;          // Body of the request.
    map* query_params;      // Query parameters

    struct Route* route;  // Matching route
} request_t;

typedef struct response {
    http_status status;                 // Status code
    uint8_t* data;                      // Response data as bytes.
    size_t content_length;              // Content-Length
    size_t header_count;                // Number of headers set.
    header_t headers[MAX_RES_HEADERS];  // Response headers

    request_t* request;  // Pointer to the request
    bool headers_sent;
} response_t;

typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

// Handler func.
typedef void (*Handler)(response_t* res);

typedef struct Route {
    HttpMethod method;          // HTTP Method.
    RouteType type;             // Type of Route (Normal or Static)
    char* pattern;              // Pattern to match
    Handler handler;            // Handler for the route
    char dirname[MAX_DIRNAME];  // Dirname for static route.
    PathParams* params;         // Parameters extracted from the URL
} Route;

// RouteMatcher matches the request to a given Route.
// The route handler is passed the response and request objects.
typedef Route* (*RouteMatcher)(HttpMethod method, const char* path);

bool set_header(response_t* res, const char* name, const char* value);

// Writes chunked data to the client. Note that each chunk must
// end with \r\n.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
int response_send_chunk(response_t* res, char* data, size_t len);

// End the chunked response. Must be called after all chunks have been sent.
int response_end(response_t* res);

// Write data to client connected to this response and send end of body.
int send_response(response_t* res, char* data, size_t len);

// serve a file with support for partial content specified by the "Range" header.
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
int http_serve_file(response_t* res, const char* filename);

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_threads is 0, we use the num_cpus on the target machine.
int listen_and_serve(char* port, RouteMatcher route_matcher, size_t num_threads);

// Default route matcher.
Route* default_route_matcher(HttpMethod method, const char* path);

// url_query_param returns the value associated with a query parameter.
// Returns NULL if the parameter is not found.
const char* url_query_param(request_t* req, const char* name);

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str);

// decode uri component and replace percent-encoded characters with proper
// ascii characters e.g %20 becomes " " etc.
void decode_uri(const char* url, char* dst, size_t dst_size);

// Return the content type for a given request.
// If the request has a content-type header, we return that.
// Otherwise returns NULL.
const char* get_content_type(request_t* request);

// Redirect the response to a new URL with a 302 status code.
void response_redirect(response_t* res, const char* url);

// url_path_param returns the value associated with a path parameter.
const char* url_path_param(request_t* req, const char* name);

// Register an OPTIONS route.
void OPTIONS_ROUTE(const char* pattern, Handler handler);

// Register a GET route.
void GET_ROUTE(const char* pattern, Handler handler);

// Register a POST route.
void POST_ROUTE(const char* pattern, Handler handler);

// Register a PUT route.
void PUT_ROUTE(const char* pattern, Handler handler);

// Register a PATCH route.
void PATCH_ROUTE(const char* pattern, Handler handler);

// Register a DELETE route.
void DELETE_ROUTE(const char* pattern, Handler handler);

// Serve directory at dirname.
// e.g   STATIC_DIR("/web", "/var/www/html");
void STATIC_DIR(const char* pattern, char* dirname);

// Set a NotFoundHandler. This is handy for SPAs.
void NOT_FOUND_ROUTE(const char* pattern, Handler h);

#endif /* C09A2944_5DDC_4879_9E04_7CF7FB027FC3 */
