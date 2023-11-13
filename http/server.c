#include "server.h"

volatile sig_atomic_t should_exit = 0;

typedef struct RWTask {
  int client_fd;
  int epoll_fd;
  ServeMux serve_mux;
} RWTask;

static void handle_sigint(int signal) {
  if (signal == SIGINT || signal == SIGKILL) {
    should_exit = 1;
    printf("Detected %s (%d). Shutting down!\n", strsignal(signal), signal);
  }
}

static void install_sigint_handler() {
  struct sigaction sa;
  sa.sa_handler = handle_sigint;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);

  // Ignore SIGPIPE
  // Otherwise it will crash the program.
  signal(SIGPIPE, SIG_IGN);
}

TCPServer* new_tcpserver(int port) {
  TCPServer* server = malloc(sizeof(TCPServer));
  if (!server) {
    perror("malloc");
    return NULL;
  }

  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  int enable = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    perror("setsockopt");
    exit(1);
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family      = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port        = htons(port);

  if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  server->port        = port;
  server->server_addr = server_addr;
  server->server_fd   = sockfd;
  return server;
}

int set_nonblocking(int sockfd) {
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }

  if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1) {
    perror("fcntl");
    exit(EXIT_FAILURE);
  }
  return 0;
}

void epoll_ctl_add(int epoll_fd, int sock_fd, struct epoll_event* event, uint32_t events) {
  event->data.fd = sock_fd;
  event->events  = events;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sock_fd, event) == -1) {
    perror("epoll_ctl");
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
  int success          = 1;

  while (1) {
    char inner_buf[BUFSIZ];
    int bytes_read = read(client_fd, inner_buf, sizeof(inner_buf));

    if (bytes_read <= 0) {
      if (bytes_read == 0) {
        // End of file. The remote has closed the connection.
        success = 1;
      } else if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // No more data to read for now, try again later
        } else {
          perror("read");
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
          perror("realloc");
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

  printf("[ERROR]: %s\n", message);
  send(client_fd, reply, sizeof(reply), 0);
}

// close client connection
void close_client(int client_fd, int epoll_fd) {
  epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
  shutdown(client_fd, SHUT_WR);
  close(client_fd);
}

void handleReadAndWrite(void* args) {
  RWTask* task       = (RWTask*)args;
  int client_fd      = task->client_fd;
  int epoll_fd       = task->epoll_fd;
  ServeMux serve_mux = task->serve_mux;

  int status         = StatusOK;
  char error[100]    = {0};
  Request* request   = NULL;
  Response* response = NULL;

  ssize_t buffer_len = 1024;
  char* requestData  = (char*)malloc(buffer_len);
  if (!requestData) {
    status = StatusInternalServerError;
    strncpy(error, "unable to allocated requestData", sizeof(error));
    goto request_cleanup;
  }

  int bytes_read = read_from_client(client_fd, &requestData, &buffer_len);
  if (bytes_read <= 0) {
    status = StatusInternalServerError;
    strncpy(error, "read_from_client returned negative bytes", sizeof(error));
    goto request_cleanup;
  }

  request = request_parse_http(requestData);
  if (!request) {
    status = StatusInternalServerError;
    strncpy(error, "request_parse_http failed", sizeof(error));
    goto request_cleanup;
  }

  response = alloc_response(client_fd);
  if (!response) {
    status = StatusInternalServerError;
    strncpy(error, "alloc_response failed", sizeof(error));
    goto request_cleanup;
  }

  Context context = {.request = request, .response = response};

  Route* matching_route = serve_mux(request->method, request->url->path);
  if (!matching_route) {
    status = StatusNotFound;
    strncpy(error, "Page Not Found", sizeof(error));
    goto request_cleanup;
  }

  // Call the matching handler
  context.route = matching_route;
  matching_route->handler(&context);

request_cleanup:
  // Log request path
  printf("%s - %s\n", method_tostring(request->method), request->url->original_url);

  // Free thread args
  free(args);

  // Free request data if any.
  if (requestData) {
    free(requestData);
  }

  request_destroy(request);
  response_destroy(response);

  // If request failed, send an error.
  // Assume 100 - 308 are good requests.
  if (status > StatusPermanentRedirect) {
    send_error(client_fd, status, error);
  }

  // Close client connection and remove from monitored fds.
  // TODO: Implement Keep-Alive
  close_client(client_fd, epoll_fd);
}

// Initialize a thread pool.
void listen_and_serve(TCPServer* server, ServeMux mux) {
  curl_global_init(CURL_GLOBAL_DEFAULT);

  int exitCode = EXIT_SUCCESS;
  install_sigint_handler();

  int server_fd = server->server_fd;
  set_nonblocking(server_fd);

  ThreadPool* pool = threadpool_create(POOL_SIZE);
  if (!pool) {
    fprintf(stderr, "Unable to allocate memory for a threadpool\n");
    exitCode = EXIT_FAILURE;
    goto cleanup;
  }

  if (listen(server_fd, SOMAXCONN) == -1) {
    perror("listen");
    exitCode = EXIT_FAILURE;
    goto cleanup;
  }

  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
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
      perror("epoll_wait");
      exitCode = EXIT_FAILURE;
      goto cleanup;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == server_fd) {
        int client_fd = accept_new_connection(epoll_fd, server_fd, server->server_addr, &event);
        if (client_fd == -1) {
          perror("accept");
          break;
        }
      } else {
        int client_fd = events[i].data.fd;
        RWTask* args  = malloc(sizeof(RWTask));
        if (!args) {
          fprintf(stderr, "RWTask: malloc failed\n");
          close_client(client_fd, epoll_fd);
        } else {
          args->client_fd = client_fd;
          args->serve_mux = mux;
          args->epoll_fd  = epoll_fd;
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
