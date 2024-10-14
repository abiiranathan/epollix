#ifndef ACF45188_12CA_485F_9D2A_F5F14814CF41
#define ACF45188_12CA_485F_9D2A_F5F14814CF41

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include "net.h"

// Enable or disable directory browsing for the server.
// If the requested path is a directory, the server will list the files in the directory.
void enable_directory_browsing(bool enable);

void staticFileHandler(context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif /* ACF45188_12CA_485F_9D2A_F5F14814CF41 */
