#include <sched.h>
#define _GNU_SOURCE 1

#include <errno.h>
#include <sys/poll.h>
#include <netdb.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/resource.h>
#include <linux/version.h>

#include "../include/server.h"
#include "../include/response.h"

// Optimization flags
#define USE_SPLICE       1  // Zero-copy data transfer
#define USE_CPU_AFFINITY 1  // Bind threads to CPU cores
#define USE_SO_REUSEPORT 1  // Enable SO_REUSEPORT for load balancing
#define USE_QUICKACK     1  // Enable TCP_QUICKACK for faster ACKs
#define USE_FASTOPEN     1  // Enable TCP_FASTOPEN if available

// Struct holding data passed to each thread worker.
typedef struct {
    int id;         // Worker ID
    int epoll_fd;   // Epoll instance
    int server_fd;  // Server file descriptor
} WorkerData;

// Delete client socket from epoll tracking and close the client socket.
static inline void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
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
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        LOG_FATAL("unable to call sigaction\n");
    };

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
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
    char port_str[6];

    snprintf(port_str, sizeof(port_str), "%u", port);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    s = getaddrinfo(NULL, port_str, &hints, &result);
    if (s != 0) {
        LOG_ERROR("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    // Try all addresses until we find one that works
    struct addrinfo* rp;
    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
        if (sfd == -1) continue;

        // Enable SO_REUSEPORT for kernel-level load balancing
        int optval = 1;
        if (USE_SO_REUSEPORT && setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval))) {
            LOG_ERROR("SO_REUSEPORT failed: %s", strerror(errno));
        }

        // Enable TCP Fast Open if available
#if defined(TCP_FASTOPEN) && USE_FASTOPEN
        int qlen = 5;  // Queue length for TFO
        if (setsockopt(sfd, IPPROTO_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen))) {
            LOG_ERROR("TCP_FASTOPEN failed: %s", strerror(errno));
        }
#endif

        if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0) break;  // Success

        close(sfd);
    }

    if (rp == NULL) {
        LOG_ERROR("Could not bind: %s", strerror(errno));
        freeaddrinfo(result);
        return -1;
    }

    freeaddrinfo(result);

    // Optimize socket options
    if (optimize_server_socket(sfd) == -1) {
        LOG_ERROR("socket optimization failed: %s", strerror(errno));
    };

    // Increase max connections by raising file descriptor limit
    struct rlimit limits;
    if (getrlimit(RLIMIT_NOFILE, &limits) == 0) {
        limits.rlim_cur = limits.rlim_max;
        setrlimit(RLIMIT_NOFILE, &limits);
    }

    if (listen(sfd, MAXEVENTS) == -1) {
        perror("listen");
        close(sfd);
        return -1;
    }

    return sfd;
}

static void configure_client(int client_fd) {
    static const int optval = 1;

    // Disable Nagle's algorithm
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

#if defined(TCP_QUICKACK) && USE_QUICKACK
    // Enable quick ACKs for better latency
    setsockopt(client_fd, IPPROTO_TCP, TCP_QUICKACK, &optval, sizeof(optval));
#endif

    // Enable keepalive
    if (TCP_KEEPALIVE) {
        enable_keepalive(client_fd);
    }

    // Set timeout
    if (TCP_TIMEOUT_SEC > 0) {
        struct timeval timeout = {.tv_sec = TCP_TIMEOUT_SEC, .tv_usec = 0};
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    }
}

// Optimized sendall using writev for scattered data
ssize_t sendall(int fd, const void* buf, size_t n) {
    size_t sent      = 0;
    const char* data = (const char*)buf;

    while (sent < n) {
        struct iovec iov = {.iov_base = (void*)(data + sent), .iov_len = n - sent};

        struct msghdr msg = {.msg_iov = &iov, .msg_iovlen = 1};

        ssize_t res = sendmsg(fd, &msg, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (res <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Wait for socket to become writable
                struct pollfd pfd = {.fd = fd, .events = POLLOUT};
                if (poll(&pfd, 1, 1000) <= 0) {
                    return -1;
                }
                continue;
            }
            return -1;
        }
        sent += res;
    }
    return sent;
}

// Optimized request handler using pre-allocated buffers
static void handle_client(int client_fd, int epoll_fd) {
    static __thread char buffer[8192];  // Thread-local storage for buffer

    Request req;
    Response res;

    request_init(&req, client_fd, epoll_fd);
    response_init(&res, client_fd);

    // Use pre-allocated buffer for reading
    ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer), MSG_DONTWAIT);
    if (bytes_read <= 0) {
        goto cleanup;
    }

    // Parse directly from buffer
    if (!parse_http_request(&req)) {
        goto cleanup;
    }

    if (req.route != NULL) {
        context_t ctx = {.request = &req, .response = &res, .abort = false};
        process_response(&ctx);
        close_connection(client_fd, epoll_fd);
        free_locals(&ctx);
    }

cleanup:
    request_destroy(&req);
}

static void* worker_thread(void* arg) {
    WorkerData* data = (WorkerData*)arg;
    struct epoll_event events[MAXEVENTS];

#if USE_CPU_AFFINITY
    // Bind thread to specific CPU core
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(data->id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
#endif

    while (1) {
        int nfds = epoll_wait(data->epoll_fd, events, MAXEVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) continue;
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == data->server_fd) {
                // Accept all pending connections in one go
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    int client_fd =
                        accept4(data->server_fd, (struct sockaddr*)&client_addr, &client_len, SOCK_NONBLOCK);
                    if (client_fd == -1) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        continue;
                    }

                    struct epoll_event ev = {.events  = EPOLLIN | EPOLLET | EPOLLONESHOT | EPOLLRDHUP,
                                             .data.fd = client_fd};
                    epoll_ctl(data->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                    configure_client(client_fd);
                }
            } else {
                if (events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                    close_connection(events[i].data.fd, data->epoll_fd);
                } else if (events[i].events & EPOLLIN) {
                    handle_client(events[i].data.fd, data->epoll_fd);
                }
            }
        }
    }
    return NULL;
}

static int epoll_server_new(const uint16_t port) {
    int server_fd = setup_server_socket(port);
    if (server_fd == -1) {
        return -1;
    }

    enable_keepalive(server_fd);
    int ret = set_nonblocking(server_fd);
    if (ret == -1) {
        return -1;
    }

    ret = listen(server_fd, MAXEVENTS);
    if (ret == -1) {
        perror("listen");
        return -1;
    }
    return server_fd;
}

int epoll_server_run(const uint16_t port) {
    // Increase the maximum number of open file descriptors
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }

    // Create multiple listening sockets with SO_REUSEPORT for kernel-level load balancing
    int server_fds[NUM_WORKERS];
    for (int i = 0; i < NUM_WORKERS; i++) {
        server_fds[i] = epoll_server_new(port);
        if (server_fds[i] == -1) {
            for (int j = 0; j < i; j++)
                close(server_fds[j]);
            return -1;
        }
    }

    install_signal_handler();

    pthread_t workers[NUM_WORKERS];
    WorkerData worker_data[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_data[i].id       = i;
        worker_data[i].epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (worker_data[i].epoll_fd == -1) {
            LOG_ERROR("epoll_create1 failed: %s", strerror(errno));
            for (int j = 0; j < i; j++) {
                close(worker_data[j].epoll_fd);
                close(server_fds[j]);
            }
            return -1;
        }

        worker_data[i].server_fd = server_fds[i];

        struct epoll_event ev = {.events = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE, .data.fd = server_fds[i]};
        epoll_ctl(worker_data[i].epoll_fd, EPOLL_CTL_ADD, server_fds[i], &ev);

        if (pthread_create(&workers[i], NULL, worker_thread, &worker_data[i])) {
            LOG_ERROR("pthread_create failed: %s", strerror(errno));
            for (int j = 0; j < i; j++) {
                pthread_cancel(workers[j]);
                close(worker_data[j].epoll_fd);
                close(server_fds[j]);
            }
            return -1;
        }
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
        close(worker_data[i].epoll_fd);
        close(server_fds[i]);
    }

    return 0;
}
