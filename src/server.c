#define _XOPEN_SOURCE 700  // For sigaction
#define RWTASK_POOL_SIZE 1024

#include "../include/server.h"
#include <netinet/tcp.h>
#include <pthread.h>
#include <signal.h>
#include <solidc/threadpool.h>

volatile sig_atomic_t exit_server = 0;

typedef struct RWTask {
    _Atomic int client_fd;
    int epoll_fd;
    ServeMux serve_mux;
} RWTask;

RWTask rwtasks[RWTASK_POOL_SIZE] = {0};

static void init_rwtaks(void) {
    for (int i = 0; i < RWTASK_POOL_SIZE; i++) {
        rwtasks[i].client_fd = -1;
    }
}

static RWTask* get_free_rwtask(void) {
    for (int i = 0; i < RWTASK_POOL_SIZE; i++) {
        if (rwtasks[i].client_fd == -1) {
            return &rwtasks[i];
        }
    }
    return NULL;
}

static void handle_sigint(int signal) {
    if (signal == SIGINT || signal == SIGKILL) {
        exit_server = 1;
        printf("Detected %s signal(%d)\n", strsignal(signal), signal);

        // Bug: sometimes the server does not exit immediately.
        // and hangs for a few seconds. This is because the epoll_wait()
        // system call is blocking. The culprit is the sendfile() system call.
    }
}

static void install_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_sigint;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    // See man 2 sigaction for more information.
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        fprintf(stderr, "unable to call sigaction\n");
        exit(EXIT_FAILURE);
    };

    // Ignore SIGPIPE signal when writing to a closed socket or pipe.
    // Potential causes:
    // - Writing to a socket that has been closed by the peer.
    // - Writing to a pipe that has been closed by the reader.
    // Fast forward rapidly when streaming a video.
    // https://stackoverflow.com/questions/108183/how-to-prevent-sigpipes-or-handle-them-properly
    signal(SIGPIPE, SIG_IGN);
}

static void enable_keepalive(int sockfd) {
    int keepalive = 1;  // Enable keepalive
    int keepidle = 60;  // 60 seconds before sending keepalive probes
    int keepintvl = 5;  // 5 seconds interval between keepalive probes
    int keepcnt = 3;    // 3 keepalive probes before closing the connection

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {
        perror("setsockopt(): new_tcpserver failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {
        perror("setsockopt(): new_tcpserver failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {
        perror("setsockopt(): new_tcpserver failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {
        perror("setsockopt(): new_tcpserver failed");
        exit(EXIT_FAILURE);
    }
}

TCPServer* new_tcpserver(int port) {
    TCPServer* server = malloc(sizeof(TCPServer));
    assert(server);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    assert(sockfd != -1);

    // Allow reuse of the port.
    int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        perror("setsockopt(): new_tcpserver failed");
        exit(EXIT_FAILURE);
    }

    enable_keepalive(sockfd);
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind(): new_tcpserver failed");
        exit(EXIT_FAILURE);
    }

    server->port = port;
    server->server_addr = server_addr;
    server->server_fd = sockfd;
    return server;
}

int set_nonblocking(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl(): set_nonblocking() failed");
        exit(EXIT_FAILURE);
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
        perror("fcntl(): set_nonblocking() failed");
        exit(EXIT_FAILURE);
    }
    return 0;
}

void epoll_ctl_add(int epoll_fd, int sock_fd, struct epoll_event* event, uint32_t events) {
    event->data.fd = sock_fd;
    event->events = events;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, event) == -1) {
        perror("epoll_ctl(): epoll_ctl_add() failed");
        exit(EXIT_FAILURE);
    }
}

cstr* read_client_socket(Arena* arena, int client_fd, HttpInfo* info) {
    cstr* request_data = cstr_new(arena, 4096);
    if (!request_data) {
        return NULL;
    }

    int method_parsed = false;

    // 181258 read
    // Expected to read 306694 bytes
    size_t total_bytes_read = 0;
    int bytes_read;
    char buffer[1024] = {0};
    while ((bytes_read = read(client_fd, buffer, sizeof(buffer))) > 0) {
        buffer[bytes_read] = '\0';
        if (!cstr_append(arena, request_data, buffer)) {
            fprintf(stderr, "read_client_socket: cstr_append failed\n");
            return NULL;
        }
        total_bytes_read += bytes_read;

        if (!method_parsed) {
            // Parse the method and URL
            int n = sscanf(buffer, "%15s %1023s %23s", info->method, info->path, info->http_version);
            if (n == 3) {
                method_parsed = true;
                info->httpMethod = method_fromstring(info->method);
                if (info->httpMethod == M_INVALID) {
                    fprintf(stderr, "Invalid Http method\n");
                    return NULL;
                }

                if (!is_safe_method(info->httpMethod)) {
                    // We may need a bigger buffer. Resize to 2MB to avoid re-allocations
                    request_data = arena_realloc(arena, request_data, 2 * 1024 * 1024);
                    if (!request_data) {
                        fprintf(stderr, "Unable realloc() request data\n");
                        return NULL;
                    }
                }
            }
        }
    }

    if (info->httpMethod == M_INVALID) {
        fprintf(stderr, "Invalid Http method\n");
        return NULL;
    }

    printf("Total bytes read: %zu\n", total_bytes_read);
    return request_data;
}

static void http_error(int client_fd, int status, const char* message) {
    char reply[2048] = {0};

    snprintf(reply, sizeof(reply), "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n",
             status, StatusText(status), strlen(message), message);

    //  MSG_NOSIGNAL: Do not generate a SIGPIPE signal if the peer on
    // a stream-oriented socket has closed the connection.
    send(client_fd, reply, sizeof(reply), MSG_NOSIGNAL);
}

// close client connection
void close_client(int client_fd, int epoll_fd) {
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    shutdown(client_fd, SHUT_WR);
    close(client_fd);
}

void handleReadAndWrite(void* args) {
    RWTask* task = (RWTask*)args;
    int client_fd = task->client_fd;
    int epoll_fd = task->epoll_fd;
    ServeMux serve_mux = task->serve_mux;

    int status = StatusOK;
    Arena* arena = NULL;
    Request* request = NULL;
    Response* response = NULL;
    HttpInfo httpInfo = {0};

    arena = arena_create(ARENA_DEFAULT_CHUNKSIZE, SYSTEM_MAX_ALIGNMENT);
    if (!arena) {
        http_error(client_fd, StatusInternalServerError, "Unable to allocate memory");
        goto cleanup;
    }

    // Read the request data from the client
    cstr* data = read_client_socket(arena, client_fd, &httpInfo);
    if (!data || data->length == 0 || httpInfo.httpMethod == M_INVALID) {
        http_error(client_fd, StatusBadRequest, "Invalid request");
        goto cleanup;
    }

    request = request_parse_http(arena, data, &httpInfo);
    response = alloc_response(arena, client_fd);
    if (request == NULL || response == NULL) {
        // Likely broken pipe
        goto cleanup;
    }

    Context context = {.request = request, .response = response};
    Route* matching_route = serve_mux(request->method, request->url);
    if (!matching_route) {
        http_error(client_fd, StatusNotFound, StatusText(status));
        goto cleanup;
    }
    context.route = matching_route;
    matching_route->handler(&context);

cleanup:
    close_client(client_fd, epoll_fd);
    if (request)
        request_destroy(request);

    if (arena)
        arena_destroy(arena);

    // mark the task as unused
    task->client_fd = -1;
}

// Initialize a thread pool.
void listen_and_serve(TCPServer* server, ServeMux mux, int num_threads) {
    if (num_threads < 1) {
        fprintf(stderr, "listen_and_serve(): Invalid number of threads\n");
        exit(EXIT_FAILURE);
    }

    curl_global_init(CURL_GLOBAL_DEFAULT);
    initialize_libmagic();
    init_rwtaks();

    install_signal_handler();
    set_nonblocking(server->server_fd);

    int server_fd = server->server_fd;

    if (listen(server_fd, 500) == -1) {
        perror("listen_and_serve(): listen");
        exit(EXIT_FAILURE);
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("listen_and_serve(): epoll_create1");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    ThreadPool pool = threadpool_create(num_threads);
    if (!pool) {
        fprintf(stderr, "listen_and_serve(): Unable to allocate memory for a threadpool\n");
        exit(EXIT_FAILURE);
    }

    server->epoll_fd = epoll_fd;
    struct epoll_event event, events[MAX_EVENTS];
    epoll_ctl_add(epoll_fd, server_fd, &event, EPOLLIN);
    printf("Server listening on port %d\n", server->port);

    int exitCode = EXIT_SUCCESS;

    while (!exit_server) {
        int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            if (errno == EINTR) {
                // Interrupted by a signal, break the loop and shutdown.
                break;
            }

            perror("listen_and_serve(): epoll_wait");
            exitCode = EXIT_FAILURE;
            goto cleanup;
        }

        for (int i = 0; i < nfds; i++) {
            if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN))) {
                /* An error has occured on this fd, or the socket is not
                 ready for reading (why were we notified then?) */
                fprintf(stderr, "epoll error\n");
                close(events[i].data.fd);
                continue;
            } else if (events[i].data.fd == server_fd) {
                socklen_t client_len = sizeof(server->server_addr);
                int client_fd = accept(server_fd, (struct sockaddr*)&server->server_addr, &client_len);
                if (client_fd != -1) {
                    set_nonblocking(client_fd);
                    epoll_ctl_add(epoll_fd, client_fd, &event, EPOLLIN | EPOLLET);
                    // printf("Accepted connection from %s\n", inet_ntoa(server->server_addr.sin_addr));
                    // Here EPOLLONESHOT is used to ensure that when the read event is triggered,
                    // We read all the data at once. This is because we are using edge-triggered mode.
                } else {
                    perror("listen_and_serve(): accept");
                    // we don't want to exit the server on accept() error.
                    continue;
                }
            } else {
                // Find an available task slot.
                // No need to lock since we in the main thread.
                RWTask* task = get_free_rwtask();
                if (!task) {
                    fprintf(stderr, "listen_and_serve(): No available task slots\n");
                    continue;
                }

                task->client_fd = events[i].data.fd;
                task->serve_mux = mux;
                task->epoll_fd = epoll_fd;
                threadpool_add_task(pool, handleReadAndWrite, task);
            }
        }
    }

cleanup:
    curl_global_cleanup();
    cleanup_libmagic();

    if (pool) {
        threadpool_wait(pool);
        threadpool_destroy(pool);
    }

    shutdown(server_fd, SHUT_RDWR);
    close(server_fd);

    router_cleanup();

    free(server);
    exit(exitCode);
}
