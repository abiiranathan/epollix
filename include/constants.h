#ifndef EA56F184_3413_409F_A9D5_E26BBDFC9535
#define EA56F184_3413_409F_A9D5_E26BBDFC9535

#include <stdint.h>

// Maximum number of epoll events to process in one go.
#ifndef MAXEVENTS
#define MAXEVENTS 1024
#endif

// Determines the buffer size to read from the socket initially.
// to extract the request headers.
#ifndef READ_BUFFER_SIZE
#define READ_BUFFER_SIZE 1024
#endif

// Idle timeout for a connection.
#ifndef IDLE_TIMEOUT
#define IDLE_TIMEOUT 5
#endif

// Max number of context locals that can be defined.
// This is a per-request limit.
#ifndef MAX_CONTEXT_LOCALS
#define MAX_CONTEXT_LOCALS 8
#endif

// Max directory name length
#ifndef MAX_DIRNAME
#define MAX_DIRNAME 128
#endif

// Maximum number of routes that can be defined.
#ifndef MAX_ROUTES
#define MAX_ROUTES 48
#endif

// Maximum PATH length for a request.
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 512
#endif

// Maximum number of global middleware that can be defined.
#ifndef MAX_GLOBAL_MIDDLEWARE
#define MAX_GLOBAL_MIDDLEWARE 16
#endif

// Maximum number of group middleware that can be defined.
#ifndef MAX_GROUP_MIDDLEWARE
#define MAX_GROUP_MIDDLEWARE 4
#endif

// Arena memory allocated for the router.
#ifndef ROUTE_ARENA_MEM
#define ROUTE_ARENA_MEM (1 << 20)
#endif

// Per-request arena memory size.
#ifndef PER_REQUEST_ARENA_MEM
#define PER_REQUEST_ARENA_MEM ((size_t)8192 * 2)
#endif

#ifndef MAX_HEADER_NAME_LENGTH
#define MAX_HEADER_NAME_LENGTH (size_t)64
#endif

#ifndef MAX_HEADER_VALUE_LENGTH
#define MAX_HEADER_VALUE_LENGTH (size_t)1024
#endif

// Macro to silence unused variable errors.
#define UNUSED(var) ((void)(var))

#define ERR_MEMORY_ALLOC_FAILED   "Memory allocation failed\n"
#define ERR_TOO_MANY_HEADERS      "Too many headers\n"
#define ERR_REQUEST_BODY_TOO_LONG "Request body too long\n"
#define ERR_INVALID_STATUS_LINE   "Invalid http status line\n"
#define ERR_METHOD_NOT_ALLOWED    "Method not allowed\n"
#define CONTENT_TYPE_HEADER       "Content-Type"

#ifndef TCP_NODELAY_ON
#define TCP_NODELAY_ON 1
#endif

#ifndef TCP_KEEPALIVE
#define TCP_KEEPALIVE 1
#endif

#ifndef TCP_TIMEOUT_SEC
#define TCP_TIMEOUT_SEC 10
#endif

// Number of main workers
#ifndef NUM_WORKERS
#define NUM_WORKERS 8
#endif

#endif /* EA56F184_3413_409F_A9D5_E26BBDFC9535 */
