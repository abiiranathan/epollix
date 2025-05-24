#ifndef C09A2944_5DDC_4879_9E04_7CF7FB027FC3
#define C09A2944_5DDC_4879_9E04_7CF7FB027FC3

#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "middleware.h"
#include "mime.h"
#include "multipart.h"
#include "request.h"

typedef struct ctx_value {
    char* key;    // Key for the value
    void* value;  // Value to store
} ctx_value;

// epollix context containing response primitives and request state.
typedef struct epollix_context {
    Request* request;                      // Pointer to the request
    struct MiddlewareContext* mw_ctx;      // Middleware context
    struct response* response;             // Response pointer
    ctx_value locals[MAX_CONTEXT_LOCALS];  // Local context values
    size_t locals_count;                   // Number of local context values
    LArena* arena;                         // Arena pool
    bool abort;                            // Abort request and stop processing middleware.
} context_t __attribute__((aligned(64)));

void enable_keepalive(int sockfd);
int set_nonblocking(int sock);

// Like send(2) but sends the data on connected socket fd in chunks if larger than 4K.
// Adds MSG_NOSIGNAL to send flags to ignore sigpipe.
ssize_t sendall(int fd, const void* buf, size_t n);

// Send error back to client as html with a status code.
void http_error(int client_fd, http_status status, const char* message);

// Set high performance socket options, socket reuse and congestion control.
int optimize_server_socket(int server_fd);

// Returns the IP address of the client.
char* get_ip_address(context_t* ctx);

// Add a value to the context. This is useful for sharing data between middleware.
// The key must be a null-terminated string. The value can be any
// heap-allocated pointer. If the key already exists, the value is replaced.
void set_context_value(context_t* ctx, const char* key, void* value);

// Get a value stored by  a call to `set_context_value` from the context.
// Returns nullptr if the key does not exist.
void* get_context_value(context_t* ctx, const char* key);

void free_locals(context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* C09A2944_5DDC_4879_9E04_7CF7FB027FC3 */
