#ifndef RESPONSE_H
#define RESPONSE_H

#define _GNU_SOURCE     1
#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include "net.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_HEADER_SIZE 2048

typedef struct response {
    int client_fd;       // Client fd.
    http_status status;  // Status code
    bool headers_sent;   // Headers already sent
    bool chunked;        // Is a chunked transfer

    // Response headers.
    size_t headers_written;         // Size of headers written
    char headers[MAX_HEADER_SIZE];  // Response headers
} Response;

// Initialize a new response object.
void response_init(Response* res, int client_fd);

// Process the response.
void process_response(context_t* ctx);

// Write a response header to response.
bool write_header(context_t* ctx, const char* name, const char* value);

// Set content type for the response.
void set_content_type(context_t* ctx, const char* content_type);

// Writes chunked data to the client.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
// Returns the number of bytes written or -1 on error.
ssize_t response_send_chunk(context_t* ctx, const char* data, size_t len);

// End the chunked response. Must be called after all chunks have been sent.
// Returns the number of bytes sent(that should be equal to 5) or -1 on error.
ssize_t response_end(context_t* ctx);

// Write http status code and send headers without the body.
void send_status(context_t* ctx, http_status code);

// Write data of length len as response to the client.
// Default content-type is text/html.
// Returns the number of bytes sent or -1 on error.
ssize_t send_response(context_t* ctx, const char* data, size_t len);

// Send response as JSON with the correct header.
// Returns the number of bytes sent or -1 on error.
ssize_t send_json(context_t* ctx, const char* data, size_t len);

// Send null-terminated JSON string.
ssize_t send_json_string(context_t* ctx, const char* data);

// Send the response as a null-terminated string.
// Default content-type is text/html.
// You can override it by calling set_content_type.
ssize_t send_string(context_t* ctx, const char* data);

// Send a formatted string as a response.
__attribute__((format(printf, 2, 3))) ssize_t send_string_f(context_t* ctx, const char* fmt, ...);

// Redirect the response to a new URL with a 302 status code.
void response_redirect(context_t* ctx, const char* url);

// serve a file with ABSOLUTE PATH of filename.
// Supports range requests like Video with Range header.
//
// Uses sendfile to copy content from file directly into the kernel space.
// See man(2) sendfile for more information.
// RFC: https://datatracker.ietf.org/doc/html/rfc7233 for more information about
// range requests.
ssize_t servefile(context_t* ctx, const char* filename);

// Serve an already opened file. The file must be opened in read mode.
// This is useful when the file is already opened by the caller and its not efficient to read
// the contents of the file again.
// The file is not closed by this function.
ssize_t serve_open_file(context_t* ctx, FILE* file, size_t file_size, const char* filename);

#ifdef __cplusplus
}
#endif

#endif /* RESPONSE_H */
