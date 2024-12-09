#define _GNU_SOURCE 1

#include "../include/server.h"
#include "../include/response.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <solidc/cstr.h>
#include <solidc/filepath.h>
#include <solidc/thread.h>
#include <solidc/threadpool.h>
#include <stdio.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <unistd.h>

static void close_connection(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
}

cleanup_func user_cleanup_func = NULL;  // User-defined cleanup function
EpollServer* srv = NULL;                // global server object

// Allocate memory for new task.
Task* newTask(int client_fd, int epoll_fd) {
    Task* task = (Task*)malloc(sizeof(Task));
    if (task == NULL) {
        return NULL;
    }

    task->client_fd = client_fd;
    task->epoll_fd = epoll_fd;

    // Allocate memory for the request object
    task->req = request_new(client_fd, epoll_fd);
    if (!task->req) {
        free(task);
        return NULL;
    }

    // Allocate response object
    task->res = response_new(client_fd);
    if (!task->res) {
        request_destroy(task->req);
        free(task);
        return NULL;
    }

    return task;
}

void freeTask(Task* task) {
    request_destroy(task->req);
    response_destroy(task->res);
    free(task);
}

static void handleConnection(void* arg) {
    Task* task = (Task*)arg;
    process_request(task->req);
    if (task->req->route != NULL) {
        process_response(task->req, task->res);
    }
    close_connection(task->client_fd, task->epoll_fd);
    freeTask(task);
}

ssize_t sendall(int fd, const void* buf, size_t n) {
    size_t sent = 0;
    size_t remaining = n;
    const char* data = (const char*)buf;

    // Send data in 4K chunks
    while (remaining > 0) {
        size_t chunk_size = remaining < 4096 ? remaining : 4096;

        ssize_t bytes_sent = send(fd, data + sent, chunk_size, MSG_NOSIGNAL);
        if (bytes_sent == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry after a short delay (consider using poll or epoll for efficiency)
                usleep(100);  // 100 microseconds
                continue;
            } else {
                return -1;
            }
        }
        sent += (size_t)bytes_sent;
        remaining -= (size_t)bytes_sent;
    }
    return sent;
}

// Sends an error message to the client before the request is parsed.
void http_error(int client_fd, http_status status, const char* message) {
    char* reply = NULL;
    const char* status_str = http_status_text(status);
    char* fmt = "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n";

    int ret = asprintf(&reply, fmt, status, status_str, strlen(message), message);
    if (ret == -1) {
        LOG_ERROR(ERR_MEMORY_ALLOC_FAILED);
        return;
    }

    sendall(client_fd, reply, strlen(reply));
    free(reply);
}

static int setup_server_socket(const char* port) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, sfd;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        LOG_ERROR("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        // Allow reuse of the port.
        int enable = 1;
        if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
            perror("setsockopt");
            LOG_FATAL("setsockopt(): new_tcpserver failed\n");
        }

        s = bind(sfd, rp->ai_addr, rp->ai_addrlen);
        if (s == 0) {
            /* We managed to bind successfully! */
            break;
        }

        close(sfd);
    }

    if (rp == NULL) {
        LOG_ERROR("Could not bind");
        return -1;
    }

    freeaddrinfo(result);
    return sfd;
}

// Create a new EpollServer.
EpollServer* epoll_server_create(size_t num_workers, const char* port, cleanup_func cf) {
    EpollServer* server = (EpollServer*)malloc(sizeof(EpollServer));
    if (server == NULL) {
        return NULL;
    }

    int port_int = atoi(port);
    if (port_int == 0) {
        LOG_FATAL("Invalid port number\n");
    }

    // Get the number of threads to use for the server.
    if (num_workers <= 0) {
        num_workers = get_ncpus();
        LOG_ASSERT(num_workers > 0, "Failed to get number of CPUs\n");
    }

    server->num_workers = num_workers;
    server->cleanup = cf;
    server->port = port_int;
    server->pool = threadpool_create(num_workers);
    if (server->pool == NULL) {
        free(server);
        return NULL;
    }

    middleware_init();

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

// Listen and serve on the given port.
int epoll_server_listen(EpollServer* server) {
    // set the global server object
    // Allows for easy cleanup at exit.
    srv = server;
    user_cleanup_func = server->cleanup;

    // Add the server socket to the epoll instance
    struct epoll_event event = {0}, events[MAXEVENTS] = {0};
    event.data.fd = server->server_fd;
    event.events = EPOLLIN | EPOLLET;
    int ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, server->server_fd, &event);
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
        printf("[Max file descriptors allowed: %ld]\n", maxfd);
    }

    // Install signal handler for SIGINT and SIGTERM
    install_signal_handler();

    /* The event loop */
    while (true) {
        int nfds = epoll_wait(server->epoll_fd, events, MAXEVENTS, -1);
        for (int i = 0; i < nfds; i++) {
            if (server->server_fd == events[i].data.fd) {
                while (1) {
                    struct sockaddr internetAddress;
                    socklen_t client_len;
                    int client_fd;
                    client_len = sizeof internetAddress;
                    client_fd = accept(server->server_fd, &internetAddress, &client_len);
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

                    event.data.fd = client_fd;
                    event.events = EPOLLIN | EPOLLET | EPOLLHUP | EPOLLERR | EPOLLONESHOT;
                    ret = epoll_ctl(server->epoll_fd, EPOLL_CTL_ADD, client_fd, &event);
                    if (ret == -1) {
                        perror("epoll_ctl");
                        LOG_ERROR("epoll_ctl failed");
                        continue;
                    }

                    // Disable Nagle's algorithm for the client socket
                    int flag = 1;
                    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(int));

                    // Enable keepalive for the client socket
                    enable_keepalive(client_fd);

                    struct timeval timeout;
                    timeout.tv_sec = 5;  // 5 seconds timeout
                    timeout.tv_usec = 0;
                    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
                }
            } else {
                // client socket is ready for reading
                if (events[i].events & EPOLLIN) {
                    Task* task = newTask(events[i].data.fd, server->epoll_fd);
                    if (!task) {
                        LOG_ERROR("Failed to get a free task from the pool");
                        http_error(events[i].data.fd, StatusInternalServerError, "Internal server error");
                        close_connection(events[i].data.fd, server->epoll_fd);
                        continue;
                    }

                    threadpool_add_task(server->pool, handleConnection, task);
                } else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP)) {
                    close_connection(events[i].data.fd, server->epoll_fd);
                }
            }
        }
    }

    return 0;
}

// shutdown the server.
static void epoll_server_shutdown(EpollServer* server) {
    if (!server) {
        return;
    }

    if (server->pool) {
        threadpool_wait(server->pool);
        threadpool_destroy(server->pool);
    }

    if (server->epoll_fd != -1) {
        close(server->epoll_fd);
    }

    if (server->server_fd != -1) {
        close(server->server_fd);
    }

    if (server->cleanup) {
        server->cleanup();
    }

    free(server);
}

// Destructor extension for gcc and clang.
// This is automatically called atexit.
__attribute__((destructor)) void server_destructor(void) {
    routes_cleanup();
    middleware_cleanup();
    epoll_server_shutdown(srv);

    if (user_cleanup_func) {
        user_cleanup_func();
    }
}
