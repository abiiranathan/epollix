#ifndef EA56F184_3413_409F_A9D5_E26BBDFC9535
#define EA56F184_3413_409F_A9D5_E26BBDFC9535

#include <stdint.h>

#ifndef MAXEVENTS
#define MAXEVENTS 4096
#endif

#ifndef READ_BUFFER_SIZE
#define READ_BUFFER_SIZE 4096
#endif

#ifndef IDLE_TIMEOUT
#define IDLE_TIMEOUT 5
#endif

#ifndef MAX_HEADER_NAME
#define MAX_HEADER_NAME 64
#endif

// Something reasonably long to accommodate JWT tokens, and cookies :)
#ifndef MAX_HEADER_VALUE
#define MAX_HEADER_VALUE 1024
#endif

#ifndef MAX_REQ_HEADERS
#define MAX_REQ_HEADERS 32
#endif

#ifndef MAX_RES_HEADERS
#define MAX_RES_HEADERS 8
#endif

#ifndef MAX_RES_HEADER_SIZE
#define MAX_RES_HEADER_SIZE 1024
#endif

#ifndef MAX_DIRNAME
#define MAX_DIRNAME 128
#endif

#ifndef MAX_HEADER_SIZE
#define MAX_HEADER_SIZE 4096
#endif

#ifndef MAX_ROUTES
#define MAX_ROUTES 48
#endif

#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 1024
#endif

#ifndef MAX_GLOBAL_MIDDLEWARE
#define MAX_GLOBAL_MIDDLEWARE (uint8_t)8
#endif

#ifndef MAX_GROUP_MIDDLEWARE
#define MAX_GROUP_MIDDLEWARE 4
#endif

#endif /* EA56F184_3413_409F_A9D5_E26BBDFC9535 */
