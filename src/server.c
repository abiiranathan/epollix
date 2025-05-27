#define _GNU_SOURCE 1

#include <errno.h>
#include <sys/poll.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <solidc/thread.h>
#include <solidc/threadpool.h>
#include <sys/epoll.h>

#include "../include/server.h"
#include "../include/response.h"
#include "../include/taskpool.h"

// An epoll(2) powered TCP server.
typedef struct EpollServer {
    size_t num_workers;       // Number of worker threads
    uint16_t port;            // Port the server is listening on
    int server_fd;            // Server file descriptor
    int epoll_fd;             // Epoll file descriptor
    int timeout_sec;          // client timeout in seconds
    bool enable_keepalive;    // Enable client keepalive
    bool enable_tcp_nodelay;  // Turn off Nagle's algorithm
    ThreadPool* pool;         // Threadpool
} EpollServer;

// global server object
EpollServer* epollServer = nullptr;

// Delete client socket from epoll tracking and close the client socket.
static inline void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, nullptr);
    close(client_fd);
}

// Connection handler thread worker.
static void handle_client(void* arg) {
    Task* task = (Task*)arg;
    Request req;
    Response res;

    request_init(&req, task->client_fd, task->epoll_fd);

    if (!response_init(&res, task->client_fd)) {
        LOG_ERROR("Failed to initialize response");
        http_error(task->client_fd, StatusInternalServerError, "Internal server error");
        close_connection(task->client_fd, task->epoll_fd);
        taskpool_put(task);
        return;
    };

    if (!parse_http_request(&req, task->arena)) {
        goto cleanup;
    };

    if (req.route != nullptr) {
        context_t ctx = {.request = &req, .response = &res, .arena = task->arena, .abort = false};
        process_response(&ctx);
        close_connection(task->client_fd, task->epoll_fd);
        free_locals(&ctx);
    }
cleanup:
    if (req.path) cstr_free(req.path);
    if (req.body) free(req.body);                         // free allocated req body
    if (req.query_params) map_destroy(req.query_params);  // free query params map
    if (req.headers) headers_free(req.headers);           // free request headers
    if (res.headers) headers_free(res.headers);           // free response hedaers
    taskpool_put(task);                                   // Return task to pool
}

ssize_t sendall(int fd, const void* buf, size_t n) {
    size_t sent      = 0;
    size_t remaining = n;
    const char* data = (const char*)buf;

    while (remaining > 0) {
        // Check if socket is writable before attempting to send
        struct pollfd pfd;
        pfd.fd     = fd;
        pfd.events = POLLOUT;
        int ret    = poll(&pfd, 1, 1000);  // 1000 ms timeout

        if (ret <= 0) {
            // Timeout or error
            fprintf(stderr, "timeout on send\n");
            return -1;
        }

        // Socket is writable, try to send
        size_t chunk_size  = remaining < 4096 ? remaining : 4096;
        ssize_t bytes_sent = send(fd, data + sent, chunk_size, MSG_NOSIGNAL);

        if (bytes_sent == -1) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                return -1;
            }
            // If we still got EAGAIN despite poll saying socket is writable,
            // we'll loop back and poll again
            continue;
        }
        sent += (size_t)bytes_sent;
        remaining -= (size_t)bytes_sent;
    }

    return (ssize_t)sent;
}

// Sends an error message to the client before the request is parsed.
void http_error(int client_fd, http_status status, const char* message) {
    char reply[1024];
    const char* status_str = http_status_text(status);
    const char* fmt        = "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n";

    // 20 is a safe margin for status and other formatting
    size_t max_message_length = sizeof(reply) - strlen(fmt) - 20;
    size_t message_length     = strlen(message);

    if (message_length >= max_message_length) {
        // use asprintf to allocate memory for the message if it's too long
        char* msg = NULL;
        int ret   = asprintf(&msg, fmt, status, status_str, message_length, message);
        if (ret < 0) {
            LOG_ERROR(ERR_MEMORY_ALLOC_FAILED);
            return;
        }

        sendall(client_fd, msg, strlen(msg));
        free(msg);
        return;
    }

    int ret = snprintf(reply, sizeof(reply), fmt, status, status_str, message_length, message);
    if (ret < 0 || (size_t)ret >= sizeof(reply)) {
        LOG_ERROR(ERR_MEMORY_ALLOC_FAILED);
        return;
    }

    sendall(client_fd, reply, strlen(reply));
}

static int setup_server_socket(uint16_t port) {
    struct addrinfo hints;
    struct addrinfo* result;
    int s, sfd;
    char port_str[6];  // Enough for "65535\0"

    // Convert port to string
    snprintf(port_str, sizeof(port_str), "%u", port);

    // Initialize hints
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;   /* Return IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* TCP socket */
    hints.ai_flags    = AI_PASSIVE;  /* All interfaces */

    // Get address info
    s = getaddrinfo(NULL, port_str, &hints, &result);
    if (s != 0) {
        LOG_ERROR("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    // Create socket with the first result
    sfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sfd == -1) {
        LOG_ERROR("socket: %s", strerror(errno));
        freeaddrinfo(result);
        return -1;
    }

    // Optimize the server socket be4 binding
    if (optimize_server_socket(sfd) == -1) {
        LOG_ERROR("socket option failed: %s\n", strerror(errno));
    };

    // Attempt to bind
    s = bind(sfd, result->ai_addr, result->ai_addrlen);
    if (s != 0) {
        LOG_ERROR("bind: %s", strerror(errno));
        close(sfd);
        freeaddrinfo(result);
        return -1;
    }

    // Free addrinfo and return socket descriptor
    freeaddrinfo(result);
    return sfd;
}

uint16_t parse_port(const char* _port, bool* success) {
    errno = 0;  // Reset errno before conversion
    char* endptr;
    long port = strtol(_port, &endptr, 10);

    // Check if the entire string was consumed and is non-empty
    if (endptr == _port || *endptr != '\0') {
        LOG_ERROR("Invalid port: '%s' is not a number", _port);
        *success = false;
        return 0;
    }

    // Check for out-of-range or negative values
    if (port < 0 || port > UINT16_MAX) {
        LOG_ERROR("Port out of range: %ld (must be 0-65535)", port);
        *success = false;
        return 0;
    }

    // Check for conversion errors (e.g., overflow)
    if (errno == ERANGE) {
        LOG_ERROR("Port conversion error: %s", strerror(errno));
        *success = false;
        return 0;
    }

    *success = true;
    return (uint16_t)port;
}

// Create a new EpollServer.
EpollServer* epoll_server_create(size_t num_workers, const uint16_t port) {
    EpollServer* server = (EpollServer*)malloc(sizeof(EpollServer));
    if (server == nullptr) {
        return nullptr;
    }

    // Get the number of threads to use for the server.
    if (num_workers <= 0) {
        num_workers = get_ncpus();
        LOG_ASSERT(num_workers > 0, "Failed to get number of CPUs\n");
    }

    server->num_workers = num_workers;
    server->port        = port;
    server->timeout_sec = 0;
    server->pool        = threadpool_create((int)num_workers);
    if (server->pool == nullptr) {
        free(server);
        return nullptr;
    }

    // Create an epoll instance
    server->server_fd = setup_server_socket(port);
    if (server->server_fd == -1) {
        LOG_FATAL("Failed to create server socket\n");
    }

    enable_keepalive(server->server_fd);

    int ret = set_nonblocking(server->server_fd);
    if (ret == -1) {
        LOG_FATAL("Failed to set non-blocking on server socket\n");
    }

    ret = listen(server->server_fd, MAXEVENTS);
    if (ret == -1) {
        perror("listen");
        LOG_FATAL("Failed to listen on server socket\n");
    }

    server->epoll_fd = epoll_create1(0);
    if (server->epoll_fd == -1) {
        perror("epoll_create");
        LOG_FATAL("Failed to create epoll instance\n");
    }
    return server;
}

// Enable client keep alive.
void epoll_server_enable_keepalive(EpollServer* server, bool flag) {
    server->enable_keepalive = flag;
}

// Enable client keep alive.
void epoll_server_enable_tcp_nodelay(EpollServer* server, bool flag) {
    server->enable_tcp_nodelay = flag;
}

void handle_sigint(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        LOG_INFO("Received signal %s\n", strsignal(sig));
        exit(EXIT_FAILURE);
    }
}

static void install_signal_handler(void) {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // See man 2 sigaction for more information.
    if (sigaction(SIGINT, &sa, nullptr) == -1) {
        LOG_FATAL("unable to call sigaction\n");
    };

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
}

// Listen and serve on the given port.
int epoll_server_listen(EpollServer* server) {
    epollServer = server;

    // Add the server socket to the epoll instance
    struct epoll_event event = {0}, events[MAXEVENTS] = {0};
    event.data.fd = server->server_fd;
    event.events  = EPOLLIN | EPOLLET;
    int ret       = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->server_fd, &event);
    if (ret == -1) {
        perror("epoll_ctl");
        LOG_FATAL("Failed to add server socket to epoll\n");
    }

    printf("[PID: %d]\n", get_gid());
    printf("[Server listening on port http://0.0.0.0:%d with %zu threads]\n", server->port, server->num_workers);

    // log max allowed file descriptors for the process
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd == -1) {
        perror("sysconf");
    } else {
        printf("[Max open file descriptors allowed: %ld]\n", maxfd);
    }

    // Install signal handler for SIGINT and SIGTERM
    install_signal_handler();
    taskpool_init();

    /* The event loop */
    while (true) {
        int nfds = epoll_wait(server->epoll_fd, events, MAXEVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (server->server_fd == events[i].data.fd) {
                while (1) {
                    struct sockaddr client_addr;
                    socklen_t client_len = sizeof client_addr;
                    int client_fd        = accept(server->server_fd, &client_addr, &client_len);
                    if (client_fd == -1) {
                        if (errno == EINTR) {
                            return -1;  // Interrupted by signal
                        }

                        if (errno == EAGAIN || errno == EWOULDBLOCK) {
                            break;  // No more incoming connections
                        }

                        perror("accept");
                        break;
                    }

                    ret = set_nonblocking(client_fd);
                    if (ret == -1) {
                        LOG_ERROR("Failed to set non-blocking on client socket\n");
                        break;
                    }

                    // Add client socket to epoll
                    event.data.fd = client_fd;
                    event.events  = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR | EPOLLONESHOT;
                    ret           = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
                    if (ret == -1) {
                        perror("epoll_ctl");
                        LOG_ERROR("epoll_ctl failed");
                        continue;
                    }

                    // Disable Nagle's algorithm for the client socket
                    if (server->enable_tcp_nodelay) {
                        int flag = 1;
                        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
                    }

                    // Enable keepalive for the client socket
                    if (server->enable_keepalive) {
                        enable_keepalive(client_fd);
                    }

                    if (server->timeout_sec > 0) {
                        struct timeval timeout;
                        timeout.tv_sec  = server->timeout_sec;
                        timeout.tv_usec = 0;
                        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
                    }
                }
            } else {
                // client socket is ready for reading
                if (events[i].events & EPOLLIN) {
                    Task* task = taskpool_get();
                    if (!task) {
                        http_error(events[i].data.fd, StatusServiceUnavailable, "Service Unavailable");
                        close_connection(events[i].data.fd, server->epoll_fd);
                        continue;
                    }

                    task->client_fd = events[i].data.fd;
                    task->epoll_fd  = server->epoll_fd;
                    threadpool_submit(server->pool, handle_client, task);
                } else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                    close_connection(events[i].data.fd, server->epoll_fd);
                }
            }
        }
    }

    return 0;
}

// Destructor extension for gcc and clang.
// This is automatically called atexit.
__attribute__((destructor)) void server_destructor(void) {
    if (!epollServer) {
        return;
    }

    if (epollServer->pool) {
        threadpool_destroy(epollServer->pool);
    }

    if (epollServer->epoll_fd != -1) {
        close(epollServer->epoll_fd);
    }

    if (epollServer->server_fd != -1) {
        close(epollServer->server_fd);
    }

    taskpool_destroy();
    free(epollServer);
}
