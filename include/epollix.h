#ifndef C09A2944_5DDC_4879_9E04_7CF7FB027FC3
#define C09A2944_5DDC_4879_9E04_7CF7FB027FC3

#define _GNU_SOURCE 1

#include "constants.h"
#include "logging.h"
#include "method.h"
#include "mime.h"
#include "multipart.h"
#include "params.h"
#include "status.h"

#define UNUSED(var) ((void)var)

// Request object.
typedef struct request request_t;

// Response object.
typedef struct ep_context context_t;

// Handler func.
typedef void (*Handler)(context_t* ctx);

// Route struct.
typedef struct Route Route;

// A middleware function that takes a context and a next function.
// The next function is a callback that will be called to pass control to the next middleware.
typedef void (*Middleware)(context_t* ctx, Handler next);

// RouteMatcher matches the request to a given Route.
// The route handler is passed the response and request objects.
typedef Route* (*RouteMatcher)(HttpMethod method, const char* path);

void use_global_middleware(Middleware middleware);
void use_route_middleware(Route* route, Middleware middleware);

//  ================== Getters =====================
const char* get_query(context_t* ctx, const char* name);
const char* get_param(context_t* ctx, const char* name);
const char* get_path(context_t* ctx);
const char* get_header(context_t* ctx, const char* name);
const char* get_response_header(context_t* ctx, const char* name);
const char* get_method_str(context_t* ctx);
const char* get_content_type(context_t* ctx);
HttpMethod get_method(context_t* ctx);
char* get_body(context_t* ctx);
size_t get_body_length(context_t* ctx);
const Route* get_current_route(context_t* ctx);
const char* route_pattern(Route* route);

// =================== Setters =================================

bool set_header(context_t* ctx, const char* name, const char* value);
void set_status(context_t* ctx, http_status status);
void set_content_type(context_t* ctx, const char* content_type);

// ============== Send function variants ==========================

// Writes chunked data to the client.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
int response_send_chunk(context_t* ctx, char* data, size_t len);

// End the chunked response. Must be called after all chunks have been sent.
int response_end(context_t* ctx);

// Write data to client connected to this response and send end of body.
// Default content-type is text/html.
int send_response(context_t* ctx, char* data, size_t len);

int send_json(context_t* ctx, char* data, size_t len);

int send_raw_string(context_t* ctx, char* data, size_t len);

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str);

// decode uri component and replace percent-encoded characters with proper
// ascii characters e.g %20 becomes " " etc.
void decode_uri(const char* url, char* dst, size_t dst_size);

// Redirect the response to a new URL with a 302 status code.
void response_redirect(context_t* ctx, const char* url);

// Register an OPTIONS route.
Route* OPTIONS_ROUTE(const char* pattern, Handler handler);

// Register a GET route.
Route* GET_ROUTE(const char* pattern, Handler handler);

// Register a POST route.
Route* POST_ROUTE(const char* pattern, Handler handler);

// Register a PUT route.
Route* PUT_ROUTE(const char* pattern, Handler handler);

// Register a PATCH route.
Route* PATCH_ROUTE(const char* pattern, Handler handler);

// Register a DELETE route.
Route* DELETE_ROUTE(const char* pattern, Handler handler);

// Serve directory at dirname.
// e.g   STATIC_DIR("/web", "/var/www/html");
Route* STATIC_DIR(const char* pattern, char* dirname);

// Set a NotFoundHandler. This is handy for SPAs.
Route* NOT_FOUND_ROUTE(const char* pattern, Handler h);

// Default route matcher.
Route* default_route_matcher(HttpMethod method, const char* path);

// serve a file with support for partial content specified by the "Range" header.
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
int http_serve_file(context_t* ctx, const char* filename);

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_threads is 0, we use the num_cpus on the target machine.
int listen_and_serve(char* port, RouteMatcher route_matcher, size_t num_threads);

#endif /* C09A2944_5DDC_4879_9E04_7CF7FB027FC3 */
