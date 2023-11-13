#ifndef HTTP_H
#define HTTP_H

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#ifndef MAX_RESP_HEADERS
#define MAX_RESP_HEADERS 10
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

#define PCRE2_CODE_UNIT_WIDTH 8

#include <errno.h>
#include <magic.h>
#include <pcre2.h>
#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "headers.h"
#include "method.h"
#include "request.h"
#include "str.h"
#include "threadpool.h"

// =================================
// Http Routing
// =================================
typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

typedef struct Context {
  Request* request;
  struct Response* response;
  struct Route* route;
} Context;

typedef void (*RouteHandler)(Context* ctx);

typedef struct Route {
  HttpMethod method;  // HTTP Method.
  char* pattern;      // Pattern as a string

  // PCRE - compiled extended regex pattern See https://www.pcre.org/current/doc/html/
  pcre2_code* compiledPattern;
  RouteHandler handler;       // Handler for the route
  RouteType type;             // Type of Route
  char dirname[MAX_DIRNAME];  // Dirname for static route.
} Route;

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
Route* matchBestRoute(HttpMethod method, const char* path);

// Called by server be4 shutdown to cleanup compiled
// regex patterns.
void router_cleanup();

// decode encoded URI in src into dst.
void urldecode(char* dst, size_t dst_size, const char* src);

// Function to expand the tilde (~) character in a path to
// the user's home directory
char* expandVar(const char* path);

// =============================
// Http response
// =============================
typedef struct Response Response;

// Define an enum for HTTP status codes
typedef enum {
  StatusContinue           = 100,
  StatusSwitchingProtocols = 101,
  StatusProcessing         = 102,
  StatusEarlyHints         = 103,

  StatusOK                   = 200,
  StatusCreated              = 201,
  StatusAccepted             = 202,
  StatusNonAuthoritativeInfo = 203,
  StatusNoContent            = 204,
  StatusResetContent         = 205,
  StatusPartialContent       = 206,
  StatusMultiStatus          = 207,
  StatusAlreadyReported      = 208,
  StatusIMUsed               = 226,

  StatusMultipleChoices   = 300,
  StatusMovedPermanently  = 301,
  StatusFound             = 302,
  StatusSeeOther          = 303,
  StatusNotModified       = 304,
  StatusUseProxy          = 305,
  StatusUnused            = 306,
  StatusTemporaryRedirect = 307,
  StatusPermanentRedirect = 308,

  StatusBadRequest                   = 400,
  StatusUnauthorized                 = 401,
  StatusPaymentRequired              = 402,
  StatusForbidden                    = 403,
  StatusNotFound                     = 404,
  StatusMethodNotAllowed             = 405,
  StatusNotAcceptable                = 406,
  StatusProxyAuthRequired            = 407,
  StatusRequestTimeout               = 408,
  StatusConflict                     = 409,
  StatusGone                         = 410,
  StatusLengthRequired               = 411,
  StatusPreconditionFailed           = 412,
  StatusRequestEntityTooLarge        = 413,
  StatusRequestURITooLong            = 414,
  StatusUnsupportedMediaType         = 415,
  StatusRequestedRangeNotSatisfiable = 416,
  StatusExpectationFailed            = 417,
  StatusTeapot                       = 418,
  StatusMisdirectedRequest           = 421,
  StatusUnprocessableEntity          = 422,
  StatusLocked                       = 423,
  StatusFailedDependency             = 424,
  StatusTooEarly                     = 425,
  StatusUpgradeRequired              = 426,
  StatusPreconditionRequired         = 428,
  StatusTooManyRequests              = 429,
  StatusRequestHeaderFieldsTooLarge  = 431,
  StatusUnavailableForLegalReasons   = 451,

  StatusInternalServerError           = 500,
  StatusNotImplemented                = 501,
  StatusBadGateway                    = 502,
  StatusServiceUnavailable            = 503,
  StatusGatewayTimeout                = 504,
  StatusHTTPVersionNotSupported       = 505,
  StatusVariantAlsoNegotiates         = 506,
  StatusInsufficientStorage           = 507,
  StatusLoopDetected                  = 508,
  StatusNotExtended                   = 510,
  StatusNetworkAuthenticationRequired = 511
} HttpStatus;

Response* alloc_response(int client_fd);
void response_destroy(Response* res);

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go
const char* StatusText(int statusCode);

// Returns the value of the response header if exists or NULL.
const char* find_resp_header(Response* res, const char* name, int* index);

// Sents Transfer-Encoding to "chunked" and prepares internal state
// for multiple send calls.
void enable_chunked_transfer(Response* res);

// Set response status code and status text.
void set_status(Response* res, int statusCode);

// Add new header to response headers.
void set_header(Response* res, const char* name, const char* value);

// Sends the response at once.
int send_response(Context* ctx, void* data, ssize_t content_length);

// Sends response in chunks. Intended to be called multiple times.
// You must call enable_chunked_transfer() before streaming large responses
// Or doing SSE.
bool send_chunk(Response* res, void* data, ssize_t chunk_size);

// Read contents and filename and send them to the remote server.
// We try to guess the Mime-type but you should set it your-self to
// wrongly guessed mime-type.
// Returns number of bytes sent or -1 for errors.
int send_file(Context* ctx, const char* filename);

// get the mime-type of the file using libmagic.
bool get_mime_type(const char* filename, size_t buffer_len, char mime_buffer[buffer_len]);

#endif /* HTTP_H */
