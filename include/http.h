#ifndef HTTP_H
#define HTTP_H

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L
// for usleep
#define _GNU_SOURCE 1
#endif

#ifndef MAX_RESP_HEADERS
#define MAX_RESP_HEADERS 24
#endif

#ifndef MAX_ROUTES
#define MAX_ROUTES 100
#endif

#ifndef MAX_DIRNAME
#define MAX_DIRNAME 128
#endif

#ifndef MAX_PATH_SIZE
#define MAX_PATH_SIZE 256
#endif

#include <errno.h>
#include <magic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "headers.h"
#include "method.h"
#include "params.h"
#include "request.h"

typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

typedef struct Context {
    Request* request;           // Request object
    struct Response* response;  // Response object
    struct Route* route;        // Matched route
} Context;

typedef void (*RouteHandler)(Context* ctx);

typedef struct Route {
    HttpMethod method;          // HTTP Method.
    RouteType type;             // Type of Route (Normal or Static)
    char* pattern;              // Pattern to match
    RouteHandler handler;       // Handler for the route
    char dirname[MAX_DIRNAME];  // Dirname for static route.
    PathParams* params;         // Parameters extracted from the URL
} Route;

void initialize_libmagic(void);
void cleanup_libmagic(void);

// If regex are not included in pattern, they are added.
// Only ^ & $ are added to avoid partial matches.
Route* registerRoute(HttpMethod method, const char* pattern, RouteHandler handler, RouteType type);

// Register a /GET route.
void GET_ROUTE(const char* pattern, RouteHandler handler);

// Register a /POST route.
void POST_ROUTE(const char* pattern, RouteHandler handler);

// Register a /PUT route.
void PUT_ROUTE(const char* pattern, RouteHandler handler);

// Register a /PATCH route.
void PATCH_ROUTE(const char* pattern, RouteHandler handler);

// Register a /DELETE route.
void DELETE_ROUTE(const char* pattern, RouteHandler handler);

// Register an OPTIONS route.
void OPTIONS_ROUTE(const char* pattern, RouteHandler handler);

// Serve directory at dirname.
// e.g   STATIC_DIR("/web", "/var/www/html");
void STATIC_DIR(const char* pattern, char* dirname);

// Match the best regex pattern.
Route* matchRoute(HttpMethod method, URL* url);

// Called by server be4 shutdown to cleanup compiled
// regex patterns.
void router_cleanup();

// decode encoded URI in src into dst.
void urldecode(char* dst, size_t dst_size, const char* src);

typedef struct Response Response;

typedef enum {
    StatusContinue = 100,
    StatusSwitchingProtocols = 101,
    StatusProcessing = 102,
    StatusEarlyHints = 103,

    StatusOK = 200,
    StatusCreated = 201,
    StatusAccepted = 202,
    StatusNonAuthoritativeInfo = 203,
    StatusNoContent = 204,
    StatusResetContent = 205,
    StatusPartialContent = 206,
    StatusMultiStatus = 207,
    StatusAlreadyReported = 208,
    StatusIMUsed = 226,

    StatusMultipleChoices = 300,
    StatusMovedPermanently = 301,
    StatusFound = 302,
    StatusSeeOther = 303,
    StatusNotModified = 304,
    StatusUseProxy = 305,
    StatusUnused = 306,
    StatusTemporaryRedirect = 307,
    StatusPermanentRedirect = 308,

    StatusBadRequest = 400,
    StatusUnauthorized = 401,
    StatusPaymentRequired = 402,
    StatusForbidden = 403,
    StatusNotFound = 404,
    StatusMethodNotAllowed = 405,
    StatusNotAcceptable = 406,
    StatusProxyAuthRequired = 407,
    StatusRequestTimeout = 408,
    StatusConflict = 409,
    StatusGone = 410,
    StatusLengthRequired = 411,
    StatusPreconditionFailed = 412,
    StatusRequestEntityTooLarge = 413,
    StatusRequestURITooLong = 414,
    StatusUnsupportedMediaType = 415,
    StatusRequestedRangeNotSatisfiable = 416,
    StatusExpectationFailed = 417,
    StatusTeapot = 418,
    StatusMisdirectedRequest = 421,
    StatusUnprocessableEntity = 422,
    StatusLocked = 423,
    StatusFailedDependency = 424,
    StatusTooEarly = 425,
    StatusUpgradeRequired = 426,
    StatusPreconditionRequired = 428,
    StatusTooManyRequests = 429,
    StatusRequestHeaderFieldsTooLarge = 431,
    StatusUnavailableForLegalReasons = 451,

    StatusInternalServerError = 500,
    StatusNotImplemented = 501,
    StatusBadGateway = 502,
    StatusServiceUnavailable = 503,
    StatusGatewayTimeout = 504,
    StatusHTTPVersionNotSupported = 505,
    StatusVariantAlsoNegotiates = 506,
    StatusInsufficientStorage = 507,
    StatusLoopDetected = 508,
    StatusNotExtended = 510,
    StatusNetworkAuthenticationRequired = 511
} HttpStatus;

Response* alloc_response(Arena* arena, int client_fd);

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go
const char* StatusText(HttpStatus statusCode);

// Sents Transfer-Encoding to "chunked" and prepares internal state
// for multiple send calls.
void enable_chunked_transfer(Response* res);

// Set response status code and status text.
void set_status(Response* res, HttpStatus statusCode);

// Add new header to response headers.
void set_header(Response* res, const char* name, const char* value);

// Sends the response at once with the given data and content-length.
// Uses the DEFAULT_CONTENT_TYPE if none is set.
// by deafult, this is text/html
// Default status code is 200
int send_response(Context* ctx, void* data, ssize_t content_length);

// Send string with content-type text/html
int send_string(Context* ctx, const char* data);

// Send json with content-type application/json.
int send_json(Context* ctx, const char* data);

// Send error
void send_error(Context* ctx, HttpStatus status);

// Send error with message
void send_html_error(Context* ctx, HttpStatus status, const char* message);

// redirect to the given url.
void redirect(Context* ctx, const char* url);

// redirect to the given url with a custom status code
void redirect_with_status(Context* ctx, const char* url, HttpStatus status);

// Sends response in chunks. Intended to be called multiple times.
// You must call enable_chunked_transfer() before streaming large responses
// Or doing SSE.
bool send_chunk(Response* res, void* data, ssize_t chunk_size);

// Read contents and filename and send them to the remote server.
// Uses libmagic to guess the Mime-type. If your profile shows this as slow,
// consider setting the Content-Type yourself.
// Returns number of bytes sent or -1 for errors.
int send_file(Context* ctx, const char* filename);

// get the mime-type of the file using libmagic.
bool get_mime_type(const char* filename, size_t buffer_len, char mime_buffer[static buffer_len]);

// url_query_param returns the value associated with a query parameter.
const char* url_query_param(Context* ctx, const char* name);

// url_path_param returns the value associated with a path parameter.
const char* url_path_param(Context* ctx, const char* name);

#endif /* HTTP_H */
