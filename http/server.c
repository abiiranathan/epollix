#define _XOPEN_SOURCE 700  // For sigaction
#define TCP_ENABLE_KEEPALIVE 1
#define RWTASK_POOL_SIZE 1024

#include "server.h"
#include <netinet/tcp.h>
#include <signal.h>
#include <solidc/threadpool.h>

volatile sig_atomic_t should_exit = 0;

typedef struct RWTask {
  int client_fd;
  int epoll_fd;
  ServeMux serve_mux;
} RWTask;

RWTask rwtasks[RWTASK_POOL_SIZE] = {0};

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

cstr* read_from_client(Arena* arena, int client_fd) {
  bool success = 1;
  cstr* buffer = cstr_new(arena, 1024 * 1024);
  assert(buffer);

  while (1) {
    char inner_buf[1024];
    int bytes_read = read(client_fd, inner_buf, sizeof(inner_buf));
    if (bytes_read <= 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // No more data to read for now, try again later
        success = true;
      } else {
        success = false;
      }
      break;
    } else {
      inner_buf[bytes_read] = '\0';
      if (!cstr_append(arena, buffer, inner_buf)) {
        success = 0;
        break;
      }
    }
  }

  if (!success) {
    return NULL;
  }
  return buffer;
}

static void send_error(int client_fd, int status, const char* message) {
  char reply[2048];

  snprintf(reply, sizeof(reply),
           "HTTP/1.1 %u %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n%s\r\n", status,
           StatusText(status), strlen(message), message);

  //  Send without issues of SIGPIPE segfaults
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
  char error[1024] = {0};

  Arena* arena = NULL;
  Request* request = NULL;
  Response* response = NULL;

  arena = arena_create(ARENA_DEFAULT_CHUNKSIZE, SYSTEM_MAX_ALIGNMENT);
  assert(arena);

  // Read the request data from the client
  cstr* data = read_from_client(arena, client_fd);
  if (!data) {
    // client closed connection or error occurred
    close(client_fd);
    arena_destroy(arena);

    // mark the task as unused
    task->client_fd = -1;
    return;
  }

  request = request_parse_http(arena, data);
  assert(request);

  response = alloc_response(arena, client_fd);
  assert(response);

  Context context = {.request = request, .response = response};

  // Find the matching route
  Route* matching_route = serve_mux(request->method, request->url->path);
  if (!matching_route) {
    status = StatusNotFound;
    snprintf(error, sizeof(error), "404 Not Found: %s", request->url->path);
    send_error(client_fd, status, error);
    arena_destroy(arena);

    // mark the task as unused
    task->client_fd = -1;
    return;
  }

  // Call the matching handler
  context.route = matching_route;

  // printf("Request path: %s\n", request->url->path);
  matching_route->handler(&context);

  // If request failed, send an error.
  // Assume 100 - 308 are good requests.
  if (status > StatusPermanentRedirect) {
    send_error(client_fd, status, error);
  }

  // Close client connection and remove from monitored fds.
  close_client(client_fd, epoll_fd);

  // Free memory used by the arena.
  arena_destroy(arena);

  // mark the task as unused
  task->client_fd = -1;
}

// Initialize a thread pool.
void listen_and_serve(TCPServer* server, ServeMux mux) {
  // initialize curl
  curl_global_init(CURL_GLOBAL_DEFAULT);

  // initialize the tasks
  for (int i = 0; i < RWTASK_POOL_SIZE; i++) {
    rwtasks[i].client_fd = -1;  // Initialize as unused
  }

  int exitCode = EXIT_SUCCESS;
  install_sigint_handler();
  set_nonblocking(server->server_fd);

  int server_fd = server->server_fd;
  ThreadPool pool = threadpool_create(8);
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
        socklen_t client_len = sizeof(server->server_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&server->server_addr, &client_len);
        if (client_fd != -1) {
          set_nonblocking(client_fd);
          epoll_ctl_add(epoll_fd, client_fd, &event, EPOLLIN | EPOLLET | EPOLLONESHOT);
          printf("Accepted connection from %s\n", inet_ntoa(server->server_addr.sin_addr));

          // Set the client socket to close after 60 seconds of inactivity.
          struct timeval tv;
          tv.tv_sec = 60;
          tv.tv_usec = 0;
          setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
        } else {
          perror("listen_and_serve(): accept");
          // If accept failed, continue to the next iteration.
          continue;
        }
      } else {
        // Find an available task slot.
        int task_index = -1;
        for (int j = 0; j < RWTASK_POOL_SIZE; j++) {
          if (rwtasks[j].client_fd == -1) {
            task_index = j;
            break;
          }
        }

        if (task_index == -1) {
          fprintf(stderr, "No available task slots\n");
          continue;
        }

        RWTask* task = &rwtasks[task_index];
        task->client_fd = events[i].data.fd;
        task->serve_mux = mux;
        task->epoll_fd = epoll_fd;
        threadpool_add_task(pool, handleReadAndWrite, task);
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
