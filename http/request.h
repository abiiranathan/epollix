#ifndef REQUEST_H
#define REQUEST_H

#include <solidc/cstr.h>
#include "headers.h"
#include "method.h"
#include "url.h"

#ifndef MAX_REQ_HEADERS
#define MAX_REQ_HEADERS 36
#endif

extern char* SCHEME;  // default scheme is "http"

typedef struct Request {
  HttpMethod method;  // enum for the request method.
  URL* url;           // URL for this request

  size_t header_length;  // Number of headers parsed from the request.
  Header** headers;      // array of headers with length(MAX_REQ_HEADERS).

  const char* body;    // Body of request if not (GET/OPTIONS) and provided or NULL;
  size_t body_length;  // Size of the request body.
} Request;

// parse Request from the received data from the socket.
// The http method, path, headers and request body will be populated.
// Query strings are not yet implemented.
Request* request_parse_http(Arena* arena, cstr* data);

// Free memory used by the request, headers and body. Passing NULL does nothing.
void request_destroy(Request* request);

// Returns the value of the response header if exists or NULL.
const char* find_req_header(Request* req, const char* name, int* index);
const char* getWebContentType(char* fileExtension);

#endif /* REQUEST_H */
