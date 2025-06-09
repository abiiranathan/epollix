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

// Struct holding data passed to each thread worker.
typedef struct {
    int id;         // Worker ID
    int epoll_fd;   // Epoll instance
    int server_fd;  // Server file descriptor
} WorkerData;

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

// Delete client socket from epoll tracking and close the client socket.
static inline void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
}

// Connection handler thread worker.
static void handle_client(int client_fd, int epoll_fd) {
    Request req;
    Response res;

    request_init(&req, client_fd, epoll_fd);
    response_init(&res, client_fd);

    if (!parse_http_request(&req)) {
        goto cleanup;
    };

    if (req.route != NULL) {
        context_t ctx = {.request = &req, .response = &res, .abort = false};

        // If keep-alive is requested
        if (req.flags & KEEPALIVE_REQUESTED) {
            write_header(&ctx, "Connection", "Keep-Alive");
            write_header(&ctx, "Keep-Alive", "timeout=300, max=200");
        } else {
            write_header(&ctx, "Connection", "Close");
        }

        process_response(&ctx);
        free_locals(&ctx);

        // Only-close connection if keep-alive is not requested.
        if (req.flags & KEEPALIVE_REQUESTED) {
            // re-arm epoll instance because we are using EPOLLONESHOT
            struct epoll_event ev;
            ev.events  = EPOLLIN | EPOLLET | EPOLLONESHOT;
            ev.data.fd = client_fd;
            epoll_ctl(epoll_fd, client_fd, EPOLL_CTL_MOD, &ev);
        } else {
            close_connection(client_fd, epoll_fd);
        }
    }
cleanup:
    request_destroy(&req);
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

// Create a new EpollServer.
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

static void configure_client(int client_fd) {
    // Disable Nagle's algorithm for the client socket
    if (TCP_NODELAY_ON) {
        int flag = 1;
        setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));
    }

    // Enable keepalive for the client socket
    if (TCP_KEEPALIVE) {
        enable_keepalive(client_fd);
    }

    if (TCP_TIMEOUT_SEC > 0) {
        struct timeval timeout;
        timeout.tv_sec  = TCP_TIMEOUT_SEC;
        timeout.tv_usec = 0;
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
    }
}

static void* worker_thread(void* arg) {
    WorkerData* data = (WorkerData*)arg;
    struct epoll_event events[MAXEVENTS];

    printf("Starting worker %d\n", data->id);

    while (1) {
        int nfds = epoll_wait(data->epoll_fd, events, MAXEVENTS, -1);

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == data->server_fd) {
                // Accept new connections
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd        = accept(data->server_fd, (struct sockaddr*)&client_addr, &client_len);
                if (client_fd == -1) {
                    continue;
                }

                if (set_nonblocking(client_fd) == 0) {
                    struct epoll_event ev;
                    ev.events  = EPOLLIN | EPOLLET | EPOLLONESHOT;
                    ev.data.fd = client_fd;
                    epoll_ctl(data->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);
                    configure_client(client_fd);
                };
            } else {
                // client socket is ready for reading
                if (events[i].events & EPOLLIN) {
                    handle_client(events[i].data.fd, data->epoll_fd);
                } else {
                    close_connection(events[i].data.fd, data->epoll_fd);
                }
            }
        }
    }
    return NULL;
}

// Start the event loop.
int epoll_server_run(const uint16_t port) {
    int server_fd = epoll_server_new(port);
    if (server_fd == -1) {
        return -1;
    }

    // Install signal handler for SIGINT and SIGTERM
    install_signal_handler();

    /* The event loop */
    pthread_t workers[NUM_WORKERS];
    WorkerData worker_data[NUM_WORKERS];

    for (int i = 0; i < NUM_WORKERS; i++) {
        worker_data[i].id = i;

        // Each worker gets its own epoll instance
        worker_data[i].epoll_fd = epoll_create1(0);
        LOG_ASSERT(worker_data[i].epoll_fd != -1, "error creating epoll instance");

        worker_data[i].server_fd = server_fd;

        // Add server socket to each epoll instance
        struct epoll_event ev;
        ev.events  = EPOLLIN | EPOLLET | EPOLLEXCLUSIVE;
        ev.data.fd = server_fd;
        epoll_ctl(worker_data[i].epoll_fd, EPOLL_CTL_ADD, server_fd, &ev);

        pthread_create(&workers[i], NULL, worker_thread, &worker_data[i]);
    }

    // Wait for all worker threads (in practice, you might want a shutdown mechanism)
    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(workers[i], NULL);
    }

    // Destroy the thread pool associated with this thread.
    close(server_fd);
    return 0;
}
