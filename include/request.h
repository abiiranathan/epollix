#ifndef REQUEST_H
#define REQUEST_H

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <solidc/cstr.h>
#include <solidc/map.h>
#include "headers.h"
#include "method.h"
#include "multipart.h"

#include "url.h"

// maximum number of request headers
#ifndef MAX_REQ_HEADERS
#define MAX_REQ_HEADERS 36
#endif

// The size of the boundary string for multipart/form-data
#define FORM_BOUNDARY_SIZE 128

// Maximum size of the URL.
#ifndef URL_MAX_LENGTH
#define URL_MAX_LENGTH 2048
#endif

extern const char* SCHEME;  // default scheme is "http" defined in request.c

typedef struct HttpInfo {
    char method[16];
    char http_version[24];
    char path[1024];
    HttpMethod httpMethod;
} HttpInfo;

typedef struct Request {
    char http_version[12];  // HTTP version of the request. e.g HTTP/1.1, HTTP/2.0, HTTP/3.0
    HttpMethod method;      // enum for the request method.
    URL* url;               // URL for this request

    size_t header_length;             // Number of headers parsed from the request.
    Header headers[MAX_REQ_HEADERS];  // array of headers with length(MAX_REQ_HEADERS).

    const char* body;    // Body of request if not (GET/OPTIONS) and provided or NULL;
    size_t body_length;  // Size of the request body.
} Request;

// parse Request from the received data from the socket.
// The http method, path, headers and request body will be populated.
// Query strings are not yet implemented.
Request* request_parse_http(Arena* arena, cstr* data, HttpInfo* info);

// Free memory used by the request, headers and body. Passing NULL does nothing.
void request_destroy(Request* request);

// Get the value of the header from the request.
const char* get_content_type(Request* request);

// =============== Multipart functions ==================

// Parse the multipart/form-data from the request body using the
// libmultipart library. The form data is stored in the MultipartForm struct.
// The boundary string is extracted from the Content-Type header.
// Returns the MultipartCode enum value indicating the success or failure of the operation.
MultipartCode parse_multipart_form(Request* request, MultipartForm* form);

// Free the memory allocate with free_form_data.
// Simply calls the multipart_free_form function from libmultipart.
void free_form_data(MultipartForm* form_data);

// ======== URLENCODED FORM DATA FUNCTIONS =============
typedef struct URLEncodedFormData {
    map* data;  // map of key-value pairs.
} URLEncodedFormData;

// Parse the urlencoded form data from the request body.
// Check for the Content-Type header to be application/x-www-form-urlencoded.
// If not found, NULL is returned.
// Get a value from the form data using get_urlencoded_value.
URLEncodedFormData* parse_urlencoded_form(Request* request);

// Free the memory allocated with parse_urlencoded_form.
void free_urlencoded_form_data(URLEncodedFormData* form_data);

// Get the value of the key from the URLEncodedFormData.
// If the key is not found, NULL is returned.
const char* get_urlencoded_value(URLEncodedFormData* form_data, const char* key);

#endif /* REQUEST_H */
