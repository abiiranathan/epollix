#ifndef C09A2944_5DDC_4879_9E04_7CF7FB027FC3
#define C09A2944_5DDC_4879_9E04_7CF7FB027FC3

#ifdef __cplusplus
extern "C" {
#endif

#define _GNU_SOURCE 1

#include "constants.h"
#include "logging.h"
#include "method.h"
#include "mime.h"
#include "multipart.h"
#include "params.h"
#include "status.h"

// Macro to silence unused variable errors.
#define UNUSED(var) ((void)var)

#define ERR_MEMORY_ALLOC_FAILED "Memory allocation failed\n"
#define ERR_TOO_MANY_HEADERS "Too many headers\n"
#define ERR_HEADER_NAME_TOO_LONG "Header name too long\n"
#define ERR_HEADER_VALUE_TOO_LONG "Header name too long\n"
#define ERR_REQUEST_BODY_TOO_LONG "Request body too long\n"
#define ERR_INVALID_STATUS_LINE "Invalid http status line\n"
#define ERR_METHOD_NOT_ALLOWED "Method not allowed\n"

// Request object.
typedef struct request request_t;

// Response object.
typedef struct epollix_context context_t;

// Handler func.
typedef void (*Handler)(context_t* ctx);

// Route struct.
typedef struct Route Route;

// RouteGroup struct.
typedef struct RouteGroup RouteGroup;

// A middleware function that takes a context and a next function.
// The next function is a callback that will be called to pass control to the next middleware.
typedef void (*Middleware)(context_t* ctx, Handler next);

// RouteMatcher matches the request to a given Route.
// The route handler is passed the response and request objects.
typedef Route* (*RouteMatcher)(HttpMethod method, const char* path);

// Apply middleware(s) to all registered routes.
void use_global_middleware(int count, ...);

// Apply middleware(s) to a spacific route.
void use_route_middleware(Route* route, int count, ...);

// Apply middleware(s) to a group of routes.
void use_group_middleware(RouteGroup* group, int count, ...);

//  ================== Getters =====================

// Returns the query parameter by name or NULL if it does not exist.
const char* get_query(context_t* ctx, const char* name);

// Returns the path parameter by name or NULL if it does not exist.
const char* get_param(context_t* ctx, const char* name);

// Returns the Request PATH associated with this request.
// This excludes the query params.
const char* get_path(context_t* ctx);

// Returns a request header by name or NULL if it does not exist.
const char* get_header(context_t* ctx, const char* name);

// Returns a response header by name or NULL if it does not exist.
const char* get_response_header(context_t* ctx, const char* name);

// Returns the http method as a const char*. All methods are in uppercase.
// If you want the type-safe enum, use get_method.
const char* get_method_str(context_t* ctx);

// Returns the content-type for this request by reading the Content-Type header.
const char* get_content_type(context_t* ctx);

// Returns the IP address of the client.
// It reads the X-Forwarded-For header if it exists, if not
// reads X-Real-IP header before resolving the IP address from the socket.
// The returned address is a heap-allocated string that the caller must free.
char* get_ip_address(context_t* ctx);

// Returns the HttpMethod enum for the request.
// Use get_method_str if you want the method as a char*.
HttpMethod get_method(context_t* ctx);

// Returns the body of the request or NULL if there is no body.
char* get_body(context_t* ctx);

// Returns the number of bytes in the request body or 0 if no body.
size_t get_body_size(context_t* ctx);

// Returns the current route.
const Route* get_current_route(context_t* ctx);

// Returns the pattern for which route was registered.
const char* get_route_pattern(Route* route);

// Get response status code.
http_status get_status(context_t* ctx);

// =================== Setters =================================

// Set response header.
bool set_header(context_t* ctx, const char* name, const char* value);

// Set http status code for the response.
void set_status(context_t* ctx, http_status status);

// Set content type for the response.
void set_content_type(context_t* ctx, const char* content_type);

// ============== Send function variants ==========================

// Writes chunked data to the client.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
// Returns the number of bytes written or -1 on error.
int response_send_chunk(context_t* ctx, const char* data, size_t len);

// End the chunked response. Must be called after all chunks have been sent.
// Returns the number of bytes sent(that should be equal to 5) or -1 on error.
int response_end(context_t* ctx);

// Write data of length len as response to the client.
// Default content-type is text/html.
// Returns the number of bytes sent or -1 on error.
int send_response(context_t* ctx, const char* data, size_t len);

// Send response as JSON with the correct header.
// Returns the number of bytes sent or -1 on error.
int send_json(context_t* ctx, const char* data, size_t len);

// Send null-terminated JSON string.
int send_json_string(context_t* ctx, const char* data);

// Send the response as a null-terminated string.
// Default content-type is text/html.
// You can override it by calling set_content_type.
int send_string(context_t* ctx, const char* data);

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str);

// decode uri component and replace percent-encoded characters with proper
// ascii characters e.g %20 becomes " " etc.
void decode_uri(const char* url, char* dst, size_t dst_size);

// Redirect the response to a new URL with a 302 status code.
void response_redirect(context_t* ctx, const char* url);

// ==================== REGISTER ROUTES ON CTX ===================================
// Register an OPTIONS route.
Route* route_options(const char* pattern, Handler handler);

// Register a GET route.
Route* route_get(const char* pattern, Handler handler);

// Register a POST route.
Route* route_post(const char* pattern, Handler handler);

// Register a PUT route.
Route* route_put(const char* pattern, Handler handler);

// Register a PATCH route.
Route* route_patch(const char* pattern, Handler handler);

// Register a DELETE route.
Route* route_delete(const char* pattern, Handler handler);

// Serve static directory at dirname.
// e.g   route_static("/web", "/var/www/html");
Route* route_static(const char* pattern, const char* dirname);

// =========== REGISTER ROUTES ON Group ========================

// Create a new RouteGroup.
// A RouteGroup is a collection of routes that share the same prefix.
// The allocated group must be freed by calling ROUTE_GROUP_FREE.
RouteGroup* route_group(const char* pattern);

// Free a RouteGroup allocated by ROUTE_GROUP.
void route_group_free(RouteGroup* group);

// Register an OPTIONS route.
Route* route_group_options(RouteGroup* group, const char* pattern, Handler handler);

// Register a GET route.
Route* route_group_get(RouteGroup* group, const char* pattern, Handler handler);

// Register a POST route.
Route* route_group_post(RouteGroup* group, const char* pattern, Handler handler);

// Register a PUT route.
Route* route_group_put(RouteGroup* group, const char* pattern, Handler handler);

// Register a PATCH route.
Route* route_group_patch(RouteGroup* group, const char* pattern, Handler handler);

// Register a DELETE route.
Route* route_group_delete(RouteGroup* group, const char* pattern, Handler handler);

// Serve static directory at dirname.
// e.g   STATIC_GROUP_DIR(group, "/web", "/var/www/html");
Route* route_group_static(RouteGroup* group, const char* pattern, char* dirname);

// Set a NotFoundHandler. This is handy for SPAs.
// It will be called if the RouteMatcher returns NULL.
Route* route_notfound(const char* pattern, Handler h);

// =========================================================================

// Default route matcher. It matches the request method and path
// to the correct Route with support for path parameters, specified
// by curry-braces: e.g /users/{username}. This matcher will popolate the
// path parameters before returning the matched route or NULL if not found.
// No support for 405 codes. (right path for wrong method)
Route* default_route_matcher(HttpMethod method, const char* path);

// serve a file with support for partial content specified by the "Range" header.
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
int http_servefile(context_t* ctx, const char* filename);

// Add a value to the context. This is useful for sharing data between middleware.
// The key must be a null-terminated string. The value can be any
// heap-allocated pointer. If the key already exists, the value is replaced.
void set_context_value(context_t* ctx, const char* key, void* value);

// Get a value stored by  a call to `set_context_value` from the context.
// Returns NULL if the key does not exist.
void* get_context_value(context_t* ctx, const char* key);

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_threads is 0, we use the num_cpus on the target machine.
// The route matcher is a function pointer that is passed the request method
// and path and returns the matching route. It is also for pupulating the Route
// parameters be4 returning the route.
int listen_and_serve(const char* port, RouteMatcher route_matcher, size_t num_threads);

#ifdef __cplusplus
}
#endif

#endif /* C09A2944_5DDC_4879_9E04_7CF7FB027FC3 */
