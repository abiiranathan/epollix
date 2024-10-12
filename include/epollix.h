#ifndef C09A2944_5DDC_4879_9E04_7CF7FB027FC3
#define C09A2944_5DDC_4879_9E04_7CF7FB027FC3

#ifdef __cplusplus
extern "C" {
#endif

#define _GNU_SOURCE 1

#include <stdio.h>
#include "middleware.h"
#include "mime.h"
#include "multipart.h"
#include "request.h"

// epollix context containing response primitives and request state.
typedef struct epollix_context {
    http_status status;                // Status code
    uint8_t* data;                     // Response data as bytes.
    size_t content_length;             // Content-Length
    request_t* request;                // Pointer to the request
    bool headers_sent;                 // Headers already sent
    bool chunked;                      // Is a chunked transfer
    size_t header_count;               // Number of headers set.
    header_t** headers;                // Response headers
    struct MiddlewareContext* mw_ctx;  // Middleware context
    map* locals;                       // user-data key-value store the context.
} context_t;

// Allocate memory for request headers.
bool allocate_headers(context_t* ctx);

// Set the response status code.
void set_status(context_t* ctx, http_status status);

// Get response status code.
http_status get_status(context_t* ctx);

// Get the content type of the request.
const char* get_content_type(context_t* ctx);

const char* get_param(context_t* ctx, const char* name);

// Like send(2) but sends the data on connected socket fd in chunks if larger than 4K.
// Adds MSG_NOSIGNAL to send flags to ignore sigpipe.
ssize_t sendall(int fd, const void* buf, size_t n);

// Send error back to client as html with a status code.
void http_error(int client_fd, http_status status, const char* message);

// =================== Setters =================================

// Set response header.
bool set_header(context_t* ctx, const char* name, const char* value);

// Set http status code for the response.
void set_status(context_t* ctx, http_status status);

// Set content type for the response.
void set_content_type(context_t* ctx, const char* content_type);

// Enable or disable directory browsing for the server.
// If the requested path is a directory, the server will list the files in the directory.
void enable_directory_browsing(bool enable);

// Returns the IP address of the client.
char* get_ip_address(context_t* ctx);

// format_file_size returns a human-readable string representation of the file size.
// The function returns a pointer to a static buffer that is overwritten on each call.
// This means that it is not thread-safe.
const char* format_file_size(off_t size);

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

// Send a formatted string as a response.
__attribute__((format(printf, 2, 3))) int send_string_f(context_t* ctx, const char* fmt, ...);

// Redirect the response to a new URL with a 302 status code.
void response_redirect(context_t* ctx, const char* url);

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

// Callback function will be called atexit.
typedef void (*cleanup_func)(void);

// Server request on given port. This blocks forever.
// port is provided as "8000" or "8080" etc.
// If num_workers is 0, we use the num_cpus on the target machine.
// The route matcher is a function pointer that is passed the request method
// and path and returns the matching route. It is also for pupulating the Route
// parameters be4 returning the route.
int listen_and_serve(const char* port, size_t num_workers, cleanup_func cf);

#ifdef __cplusplus
}
#endif

#endif /* C09A2944_5DDC_4879_9E04_7CF7FB027FC3 */
