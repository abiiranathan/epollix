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

// Write human readable file size to buffer. A good buffer size is like >= 32.
void format_file_size(off_t size, char* buf, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif /* ACF45188_12CA_485F_9D2A_F5F14814CF41 */
