#ifndef RESPONSE_H
#define RESPONSE_H
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>
#include "headers.h"
#include "stdbool.h"

#ifndef MAX_RESP_HEADERS
#define MAX_RESP_HEADERS 10
#endif


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

// Add new header to response headers.
void set_header(Response* res, const char* name, const char* value);

// Sends the response at once.
int send_response(Response* res, void* data, ssize_t content_length);

// Sends response in chunks. Intended to be called multiple times.
// You must call enable_chunked_transfer() before streaming large responses
// Or doing SSE.
bool send_chunk(Response* res, void* data, ssize_t chunk_size);

// Read contents and filename and send them to the remote server.
// We try to guess the Mime-type but you should set it your-self to
// wrongly guessed mime-type. returns false if file can't be read
// file size can't be determined or sending response fails.
// Files are sent in chunks.
bool send_file(Response* res, const char* filename, ssize_t* total_bytes_sent);

// get the mime-type of the file using libmagic.
bool get_mime_type(const char* filename, size_t buffer_len, char mime_buffer[buffer_len]);

#endif /* RESPONSE_H */
