#ifndef BD7EB0BF_BCBB_4B11_A823_631B2A8D9532
#define BD7EB0BF_BCBB_4B11_A823_631B2A8D9532

#ifdef __cplusplus
extern "C" {
#endif

#include <solidc/threadpool.h>
#include "request.h"
#include "static.h"
#include "types.h"

#define MAX_READ_TASKS 1024

typedef struct read_task {
    int epoll_fd;   // Epoll file descriptor
    int client_fd;  // Client file descriptor
    int index;      // Index of the task in the tasks array. -1 means task if free.
    Request* req;   // Request object
} read_task;

// User-defined callback function will be called atexit.
typedef void (*cleanup_func)(void);

// An epoll(2) powered TCP server.
typedef struct EpollServer {
    size_t num_workers;    // Number of worker threads
    int port;              // Port the server is listening on
    cleanup_func cleanup;  // Cleanup function
    int server_fd;         // Server file descriptor
    int epoll_fd;          // Epoll file descriptor
    ThreadPool pool;       // Thread pool
} EpollServer;

// Create a new EpollServer. If num_workers is 0, we use the num_cpus on the target machine.
EpollServer* epoll_server_create(size_t num_workers, const char* port, cleanup_func cf);

// Start the server and listen on the configured port.
int epoll_server_listen(EpollServer* server);

#ifdef __cplusplus
}
#endif

#endif /* BD7EB0BF_BCBB_4B11_A823_631B2A8D9532 */
