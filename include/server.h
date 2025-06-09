#ifndef BD7EB0BF_BCBB_4B11_A823_631B2A8D9532
#define BD7EB0BF_BCBB_4B11_A823_631B2A8D9532

#include "request.h"
#include "static.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// Create an epoll server, bind it on port, listen and start the event loop.
// Uses the configured NUM_WORKERS on constants.h
int epoll_server_run(const uint16_t port);

#ifdef __cplusplus
}
#endif

#endif /* BD7EB0BF_BCBB_4B11_A823_631B2A8D9532 */
