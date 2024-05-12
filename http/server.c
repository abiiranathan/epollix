#define _XOPEN_SOURCE 700  // For sigaction
#define TCP_ENABLE_KEEPALIVE 1

#include "server.h"
#include <signal.h>
#include <solidc/arena.h>
#include <solidc/os.h>
#include <netinet/tcp.h>

volatile sig_atomic_t should_exit = 0;

typedef struct RWTask {
  int client_fd;
  int epoll_fd;
  ServeMux serve_mux;
} RWTask;

static void handle_sigint(int signal) {
  if (signal == SIGINT || signal == SIGKILL) {
    should_exit = 1;
    printf("Detected %s signal(%d)\n", strsignal(signal), signal);
  }
}

static void install_sigint_handler() {
  struct sigaction sa;
  sa.sa_handler = handle_sigint;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  if (sigaction(SIGINT, &sa, NULL) == -1) {
    fprintf(stderr, "unable to call sigaction\n");
    exit(EXIT_FAILURE);
  };

  // Ignore SIGPIPE
  // Otherwise it will crash the program.
  signal(SIGPIPE, SIG_IGN);
}

TCPServer* new_tcpserver(int port) {
  TCPServer* server = malloc(sizeof(TCPServer));
  if (!server) {
    perror("malloc(): new_tcpserver failed");
    exit(EXIT_FAILURE);
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("socket(): new_tcpserver failed");
    exit(EXIT_FAILURE);
  }

  int enable = 1;

  // Allow reuse of the port.
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    perror("setsockopt(): new_tcpserver failed");
    exit(EXIT_FAILURE);
  }

// Enable TCP Keepalive
#ifdef TCP_ENABLE_KEEPALIVE
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

  puts("TCP Keepalive enabled");
#endif


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

static int accept_new_connection(int epoll_fd, int server_fd, struct sockaddr_in server_addr,
                                 struct epoll_event* event) {

  socklen_t client_len = sizeof(server_addr);
  int client_fd = accept(server_fd, (struct sockaddr*)&server_addr, &client_len);

  if (client_fd != -1) {
    set_nonblocking(client_fd);
    epoll_ctl_add(epoll_fd, client_fd, event, EPOLLIN | EPOLLET | EPOLLONESHOT);
  }
  return client_fd;
}

static int read_from_client(int client_fd, char** buffer, ssize_t* buffer_len) {
  int total_bytes_read = 0;
  int success = 1;

  while (1) {
    char inner_buf[BUFSIZ];
    int bytes_read = read(client_fd, inner_buf, sizeof(inner_buf));

    if (bytes_read <= 0) {
      if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // No more data to read for now, try again later
          success = 1;
        } else {
          perror("read(): read_from_client failed");
          success = 0;
        }
      }
      break;
    } else {
      if (total_bytes_read + bytes_read <= *buffer_len) {
        // Copy the received data to the output buffer.
        memcpy(*buffer + total_bytes_read, inner_buf, bytes_read);
        total_bytes_read += bytes_read;
      } else {
        // Reallocate the buffer if it's too small.
        *buffer_len *= 2;
        *buffer = (char*)realloc(*buffer, *buffer_len);
        if (*buffer == NULL) {
          perror("realloc(): read_from_client failed");
          success = 0;
          break;
        }

        // Copy the received data to the expanded buffer.
        memcpy(*buffer + total_bytes_read, inner_buf, bytes_read);
        total_bytes_read += bytes_read;
      }
    }
  }

  if (total_bytes_read > 0) {
    // Ensure that the received data is null-terminated.
    (*buffer)[total_bytes_read] = '\0';
  }
  return success ? total_bytes_read : -1;
}

static void send_error(int client_fd, int status, const char* message) {
  char reply[2048];

  snprintf(reply, sizeof(reply),
           "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n", status,
           StatusText(status), strlen(message), message);
  send(client_fd, reply, sizeof(reply), 0);
}

// close client connection
void close_client(int client_fd, int epoll_fd) {
  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
  shutdown(client_fd, SHUT_WR);
  close(client_fd);
}

void* handleReadAndWrite(void* args) {
  RWTask* task = (RWTask*)args;
  int client_fd = task->client_fd;
  int epoll_fd = task->epoll_fd;
  ServeMux serve_mux = task->serve_mux;

  int status = StatusOK;
  char error[100] = {0};
  Arena arena;

  arena_init(&arena, BUFSIZ * 10);

  Request* request = NULL;
  Response* response = NULL;
  char* requestData = NULL;

  // Allocate a buffer for the request data.
  // Do not allocate this in Arena as it may be reallocated.
  ssize_t buffer_len = BUFSIZ;
  requestData = (char*)malloc(buffer_len);
  if (!requestData) {
    status = StatusInternalServerError;
    strncpy(error, "handleReadAndWrite(): unable to allocated requestData", sizeof(error));
    goto request_cleanup;
  }

  int bytes_read = read_from_client(client_fd, &requestData, &buffer_len);
  if (bytes_read <= 0) {
    status = StatusInternalServerError;
    strncpy(error, "handleReadAndWrite(): read_from_client returned negative bytes", sizeof(error));
    goto request_cleanup;
  }

  request = request_parse_http(&arena, requestData);
  if (!request) {
    status = StatusInternalServerError;
    strncpy(error, "handleReadAndWrite(): request_parse_http failed", sizeof(error));
    goto request_cleanup;
  }

  response = alloc_response(&arena, client_fd);
  if (!response) {
    status = StatusInternalServerError;
    strncpy(error, "handleReadAndWrite(): alloc_response failed", sizeof(error));
    goto request_cleanup;
  }

  Context context = {.request = request, .response = response};

  Route* matching_route = serve_mux(request->method, request->url->path);
  if (!matching_route) {
    status = StatusNotFound;
    strncpy(error, "handleReadAndWrite(): Page Not Found", sizeof(error));
    goto request_cleanup;
  }

  // Call the matching handler
  context.route = matching_route;
  matching_route->handler(&context);

request_cleanup:
  // Log request path
  if (request != NULL && request->url != NULL)
    printf("%s - %s\n", method_tostring(request->method), request->url->original_url);

  // Free thread args
  free(args);

  // Free request data if any.
  if (requestData != NULL) {
    free(requestData);
  }

  if (request != NULL)
    request_destroy(request);

  // If request failed, send an error.
  // Assume 100 - 308 are good requests.
  if (status > StatusPermanentRedirect) {
    send_error(client_fd, status, error);
  }

  // Close client connection and remove from monitored fds.
  close_client(client_fd, epoll_fd);

  // Free memory used by the arena.
  arena_destroy(&arena);
  return NULL;
}

// Initialize a thread pool.
void listen_and_serve(TCPServer* server, ServeMux mux) {
  curl_global_init(CURL_GLOBAL_DEFAULT);

  int exitCode = EXIT_SUCCESS;
  install_sigint_handler();
  set_nonblocking(server->server_fd);

  int server_fd = server->server_fd;
  ThreadPool* pool = threadpool_create(POOL_SIZE);
  if (!pool) {
    fprintf(stderr, "listen_and_serve(): Unable to allocate memory for a threadpool\n");
    exitCode = EXIT_FAILURE;
    goto cleanup;
  }

  if (listen(server_fd, SOMAXCONN) == -1) {
    perror("listen_and_serve(): listen");
    exitCode = EXIT_FAILURE;
    goto cleanup;
  }

  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("listen_and_serve(): epoll_create1");
    exitCode = EXIT_FAILURE;
    goto cleanup;
  }

  server->epoll_fd = epoll_fd;
  struct epoll_event event, events[MAX_EVENTS];
  epoll_ctl_add(epoll_fd, server_fd, &event, EPOLLIN);
  printf("Server listening on port %d\n", server->port);

  while (!should_exit) {
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
      if (events[i].data.fd == server_fd) {
        int client_fd = accept_new_connection(epoll_fd, server_fd, server->server_addr, &event);
        if (client_fd == -1) {
          perror("listen_and_serve(): accept");
          break;
        }
      } else {
        int client_fd = events[i].data.fd;
        RWTask* args = malloc(sizeof(RWTask));
        if (!args) {
          fprintf(stderr, "RWTask: malloc failed\n");
          close_client(client_fd, epoll_fd);
        } else {
          args->client_fd = client_fd;
          args->serve_mux = mux;
          args->epoll_fd = epoll_fd;
          threadpool_add_task(pool, handleReadAndWrite, args);
        }
      }
    }
  }

cleanup:
  curl_global_cleanup();

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
