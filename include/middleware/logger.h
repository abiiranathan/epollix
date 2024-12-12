#ifndef C2347D19_DD48_407D_8CD4_88B812043B24
#define C2347D19_DD48_407D_8CD4_88B812043B24

#ifdef __cplusplus
extern "C" {
#endif
#include "../net.h"

typedef enum {
    LOG_NONE = 0,
    LOG_DATE = 1 << 0,
    LOG_TIME = 1 << 1,
    LOG_METHOD = 1 << 2,
    LOG_PATH = 1 << 3,
    LOG_STATUS = 1 << 4,
    LOG_LATENCY = 1 << 5,
    LOG_USER_AGENT = 1 << 6,
    LOG_IP = 1 << 7,
    LOG_DEFAULT = LOG_DATE | LOG_TIME | LOG_METHOD | LOG_PATH | LOG_STATUS | LOG_LATENCY
} LogFlag;

extern LogFlag log_flags;

// Set the log flags
void set_log_flags(LogFlag flags);

// Get the log flags
LogFlag get_log_flags(void);

// Remove the log flags
void remove_log_flags(LogFlag flags);

// Append the log flags
void append_log_flags(LogFlag flags);

// Set the file where the logs will be written
// Default is stdout
void set_log_file(FILE* file);

// Logger middleware.
// You can customize the logger by setting the log flags using set_log_flags or append_log_flags.
// The default is LOG_DEFAULT.
void epollix_logger(context_t* ctx, Handler next);

#ifdef __cplusplus
}
#endif

#endif /* C2347D19_DD48_407D_8CD4_88B812043B24 */
