#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_EVENTS 10
#define PORT       8080

volatile sig_atomic_t should_exit = 0;

int create_and_bind(struct sockaddr_in* server_addr) {
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

  memset(server_addr, 0, sizeof(*server_addr));
  server_addr->sin_family      = AF_INET;
  server_addr->sin_addr.s_addr = INADDR_ANY;
  server_addr->sin_port        = htons(PORT);

  if (bind(sockfd, (struct sockaddr*)server_addr, sizeof(*server_addr)) == -1) {
    perror("bind");
    exit(EXIT_FAILURE);
  }

  return sockfd;
}

int make_socket_non_blocking(int sockfd) {
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

int accept_new_connection(int epoll_fd, int server_fd, struct sockaddr_in server_addr,
                          struct epoll_event* event) {

  socklen_t client_len = sizeof(server_addr);

  int client_fd = accept(server_fd, (struct sockaddr*)&server_addr, &client_len);

  if (client_fd != -1) {
    make_socket_non_blocking(client_fd);
    epoll_ctl_add(epoll_fd, client_fd, event, EPOLLIN | EPOLLET);
  }
  return client_fd;
}

void handle_signal(int signal) {
  should_exit = 1;
}

void install_signal_handler() {
  struct sigaction sa;
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
}

int read_from_client(int client_fd, char* buffer, ssize_t buffer_len, int* success) {
  int total_bytes_read = 0;

  while (total_bytes_read < buffer_len) {
    char inner_buf[BUFSIZ];
    int bytes_read = read(client_fd, inner_buf, sizeof(inner_buf));

    if (bytes_read <= 0) {
      if (bytes_read == 0) {
        // End of file. The remote has closed the connection.
      } else if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          *success = 1;
        } else {
          perror("read");
          *success = 0;
        }
      }
      break;
    } else {
      if (total_bytes_read + bytes_read <= buffer_len) {
        // Copy the received data to the output buffer.
        memcpy(buffer + total_bytes_read, inner_buf, bytes_read);
        total_bytes_read += bytes_read;
      } else {
        // Handle buffer overflow gracefully.
        break;
      }
    }
  }

  if (total_bytes_read > 0) {
    // Ensure that the received data is null-terminated.
    buffer[total_bytes_read] = '\0';
  }

  return total_bytes_read;
}

int send_response(int client_fd, char* data, ssize_t data_len, int* should_close) {
  // Process request here.
  // printf("Got data: %s\n-------------\n", data);

  // If keep-alive (*should_close=0)

  // Send response here
  const char* response =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "Hello, Client!\n";

  int n = write(client_fd, response, strlen(response));
  if (n == -1) {
    perror("write");
    *should_close = 1;
  }

  return 0;
}

int main() {
  install_signal_handler();

  struct sockaddr_in server_addr;
  int server_fd = create_and_bind(&server_addr);
  make_socket_non_blocking(server_fd);

  if (listen(server_fd, SOMAXCONN) == -1) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    exit(EXIT_FAILURE);
  }

  struct epoll_event event, events[MAX_EVENTS];
  epoll_ctl_add(epoll_fd, server_fd, &event, EPOLLIN);

  printf("Server listening on port %d\n", PORT);

  while (!should_exit) {
    int nfds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (nfds == -1) {
      perror("epoll_wait");
      exit(EXIT_FAILURE);
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == server_fd) {
        int client_fd = accept_new_connection(epoll_fd, server_fd, server_addr, &event);
        if (client_fd == -1) {
          perror("accept");
          break;
        }
      } else {
        int read_success    = 0;
        int should_close    = 0;
        char buffer[BUFSIZ] = {0};
        int client_fd       = events[i].data.fd;
        int bytes_read      = read_from_client(client_fd, buffer, BUFSIZ, &read_success);

        if (read_success) {
          send_response(client_fd, buffer, bytes_read, &should_close);
        }

        if (should_close) {
          epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
          shutdown(client_fd, SHUT_RDWR);
          close(client_fd);
        }
      }
    }
  }

  shutdown(server_fd, SHUT_RDWR);
  close(server_fd);
  return 0;
}
