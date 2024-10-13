#ifndef C4C2FBAD_C23C_4F88_95D5_67AAD2406076
#define C4C2FBAD_C23C_4F88_95D5_67AAD2406076

#include "epollix.h"

// Allocate response headers.
bool allocate_headers(context_t* ctx);

// Process the response.
void process_response(request_t* req);

// Set response header.
bool set_response_header(context_t* ctx, const char* name, const char* value);

// Set content type for the response.
void set_content_type(context_t* ctx, const char* content_type);

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

// Send a formatted string as a response.
__attribute__((format(printf, 2, 3))) int send_string_f(context_t* ctx, const char* fmt, ...);

// Redirect the response to a new URL with a 302 status code.
void response_redirect(context_t* ctx, const char* url);

// serve a file with support for partial content specified by the "Range" header.
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
int servefile(context_t* ctx, const char* filename);

#endif /* C4C2FBAD_C23C_4F88_95D5_67AAD2406076 */
