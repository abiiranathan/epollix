#ifndef C09A2944_5DDC_4879_9E04_7CF7FB027FC3
#define C09A2944_5DDC_4879_9E04_7CF7FB027FC3

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "middleware.h"
#include "mime.h"
#include "multipart.h"
#include "request.h"

// epollix context containing response primitives and request state.
typedef struct epollix_context {
    Request* request;                  // Pointer to the request
    map* locals;                       // user-data key-value store the context.
    struct MiddlewareContext* mw_ctx;  // Middleware context
    struct response* response;         // Response pointer
} context_t;

void enable_keepalive(int sockfd);
int set_nonblocking(int sock);
void free_context(context_t* ctx);

// Like send(2) but sends the data on connected socket fd in chunks if larger than 4K.
// Adds MSG_NOSIGNAL to send flags to ignore sigpipe.
ssize_t sendall(int fd, const void* buf, size_t n);

// Send error back to client as html with a status code.
void http_error(int client_fd, http_status status, const char* message);

// Returns the IP address of the client.
char* get_ip_address(context_t* ctx);

// format_file_size returns a human-readable string representation of the file size.
// The function returns a pointer to a static buffer that is overwritten on each call.
// This means that it is not thread-safe.
const char* format_file_size(off_t size);

// Add a value to the context. This is useful for sharing data between middleware.
// The key must be a null-terminated string. The value can be any
// heap-allocated pointer. If the key already exists, the value is replaced.
void set_context_value(context_t* ctx, const char* key, void* value);

// Get a value stored by  a call to `set_context_value` from the context.
// Returns NULL if the key does not exist.
void* get_context_value(context_t* ctx, const char* key);

#ifdef __cplusplus
}
#endif

#endif /* C09A2944_5DDC_4879_9E04_7CF7FB027FC3 */
