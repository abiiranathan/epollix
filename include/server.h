#ifndef BD7EB0BF_BCBB_4B11_A823_631B2A8D9532
#define BD7EB0BF_BCBB_4B11_A823_631B2A8D9532

#include "request.h"
#include "static.h"
#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

// An epoll(2) powered TCP server.
typedef struct EpollServer EpollServer;

// Create a new EpollServer. If num_workers is 0, we use the num_cpus on the target machine.
// The best num_workers is between 2 and 4. Otherwise LOCK contension will increase latency.
EpollServer* epoll_server_create(size_t num_workers, const uint16_t port);

// Enable client keep alive.
void epoll_server_enable_keepalive(EpollServer* server, bool flag);

// Enable client keep alive.
void epoll_server_enable_tcp_nodelay(EpollServer* server, bool flag);

// Start the server and listen on the configured port.
int epoll_server_listen(EpollServer* server);

// parse port from string. If this fails, success will be set to false.
uint16_t parse_port(const char* port, bool* success);

#ifdef __cplusplus
}
#endif

#endif /* BD7EB0BF_BCBB_4B11_A823_631B2A8D9532 */
