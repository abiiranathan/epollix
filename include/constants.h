#ifndef EA56F184_3413_409F_A9D5_E26BBDFC9535
#define EA56F184_3413_409F_A9D5_E26BBDFC9535

#include <stdint.h>

// Maximum number of epoll events to process in one go.
#ifndef MAXEVENTS
#define MAXEVENTS 128
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

// Maximum length of a header name.
#ifndef MAX_HEADER_NAME
#define MAX_HEADER_NAME 32
#endif

// Maximum length of a header value.
// Something reasonably long to accommodate JWT tokens, and cookies :)
#ifndef MAX_HEADER_VALUE
#define MAX_HEADER_VALUE 512
#endif

#ifndef MAX_REQ_HEADERS
#define MAX_REQ_HEADERS 32
#endif

#ifndef MAX_RES_HEADERS
#define MAX_RES_HEADERS 12
#endif

// Size of the buffer to hold the response headers.
#ifndef MAX_RES_HEADER_SIZE
#define MAX_RES_HEADER_SIZE 512
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
#define MAX_GLOBAL_MIDDLEWARE (uint8_t)8
#endif

// Maximum number of group middleware that can be defined.
#ifndef MAX_GROUP_MIDDLEWARE
#define MAX_GROUP_MIDDLEWARE 4
#endif

// Macro to silence unused variable errors.
#define UNUSED(var) ((void)(var))

#define ERR_MEMORY_ALLOC_FAILED "Memory allocation failed\n"
#define ERR_TOO_MANY_HEADERS "Too many headers\n"
#define ERR_HEADER_NAME_TOO_LONG "Header name too long\n"
#define ERR_HEADER_VALUE_TOO_LONG "Header value too long\n"
#define ERR_REQUEST_BODY_TOO_LONG "Request body too long\n"
#define ERR_INVALID_STATUS_LINE "Invalid http status line\n"
#define ERR_METHOD_NOT_ALLOWED "Method not allowed\n"
#define CONTENT_TYPE_HEADER "Content-Type"

#endif /* EA56F184_3413_409F_A9D5_E26BBDFC9535 */
