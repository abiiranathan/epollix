#include "server.h"
#include <signal.h>
#include <sys/epoll.h>
#include "../http/threadpool.h"

/* Unexported functions */
static void ParseRequest(Context* ctx);
void HandleClient(void* clientArgs);
static void handle_shutdown(int signum);
static void debug_str_print(const char* str);
static int extract_headers_and_body(struct Request* request, char* buffer, size_t bytes_read,
                                    ssize_t* content_length);

static void closeClient(int client_fd);

static int running = 1;
#define MAX_EVENTS 50
#define POOL_SIZE  5

typedef struct Server {
  int fd;                            // Server file descriptor.
  int port;                          // Server port
  struct sockaddr_in addr;           // Server bind address
  void (*handler)(struct Context*);  // Request handler callback
} Server;

typedef struct ClientArg {
  Server* server;
  int client_fd;
} ClientArg;

typedef struct Request {
  int client_fd;
  Method method;
  char methodStr[MAX_METHOD_SIZE];
  char path[256];
  size_t num_headers;                   // Headers parsed from the request
  Header headers[MAX_REQUEST_HEADERS];  // Request headers
  char* body;                           // dynamically allocated body
} Request;

typedef struct Response {
  uint status;
  char statusText[25];
  void* data;
  ssize_t contentLength;
  ssize_t header_count;
  Header headers[MAX_RESPONSE_HEADERS];
} Response;

Server* NewTCPServer(unsigned int port) {
  Server* server = malloc(sizeof(Server));
  if (!server) {
    perror("malloc");
    exit(1);
  }

  if ((server->fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
    perror("socket");
    exit(1);
  }

  // Prepare server address structure
  server->addr.sin_family      = AF_INET;
  server->addr.sin_addr.s_addr = INADDR_ANY;
  server->addr.sin_port        = htons(port);
  server->port                 = port;
  memset(server->addr.sin_zero, 0, sizeof(server->addr.sin_zero));

  int enable = 1;
  if (setsockopt(server->fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    perror("setsockopt");
    exit(1);
  }
  return server;
}

void serverCleanup(Server* server) {
  // Gracefully shutdown the server socket
  if (shutdown(server->fd, SHUT_RDWR) == -1) {
    perror("shutdown");
  }

  close(server->fd);
  free(server);
}

void RunForever(Server* server) {
  assert(server->handler != NULL);
  ThreadPool* pool = threadpool_create(POOL_SIZE);
  if (!pool) {
    fprintf(stderr, "unable to create thread pool\n");
    exit(1);
  }

  // Install the signal handler for SIGTERM
  if (signal(SIGINT, handle_shutdown) == SIG_ERR) {
    perror("signal");
    exit(1);
  }

  // Bind to the socket
  if (bind(server->fd, (struct sockaddr*)&server->addr, sizeof(server->addr)) == -1) {
    perror("bind");
    exit(1);
  }

  // Listen for incoming connections
  if (listen(server->fd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  fprintf(stdout, "Server listening on 0.0.0.0:%u\n", server->port);

  socklen_t client_len = sizeof(server->addr);

  // Create an epoll instance
  int epoll_fd = epoll_create1(0);
  if (epoll_fd == -1) {
    perror("epoll_create1");
    serverCleanup(server);
    exit(EXIT_FAILURE);
  }

  // Register the server socket with epoll
  struct epoll_event event;

  // We're interested in read events (incoming connections)
  event.events = EPOLLIN;

  // Associate the server socket file descriptor
  event.data.fd = server->fd;

  // Add server_fd to event_queue.
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server->fd, &event) == -1) {
    perror("epoll_ctl");
    goto server_exit;
  }

  struct epoll_event events[MAX_EVENTS];

  while (running) {
    // Wait for events to occur
    int num_events = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
    if (num_events == -1) {
      perror("epoll_wait");
      goto server_exit;
    }

    for (int i = 0; i < num_events; i++) {
      if (events[i].data.fd == server->fd) {
        // Handle the server socket (new connection)
        ClientArg* args = malloc(sizeof(ClientArg));
        if (!args) {
          perror("unable to allocate memory for ClientArg");
          continue;  // reject the new connection but don't exit.
        }

        args->server = server;
        if ((args->client_fd = accept(server->fd, (struct sockaddr*)&server->addr, &client_len)) ==
            -1) {
          perror("accept");
          free(args);
          break;
        }
        threadpool_add_task(pool, HandleClient, args);
      }
    }
  }

server_exit:
  threadpool_wait(pool);
  threadpool_destroy(pool);
  serverCleanup(server);
}

int is_safe_method(const char* method) {
  if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0 ||
      strcmp(method, "DELETE") == 0) {
    return 0;
  }
  return 1;
}

// Parses request headers and allocated request body based on content-length.
int extract_headers_and_body(struct Request* request, char* buffer, size_t bytes_read,
                             ssize_t* content_length) {
  // Parse the request line
  if (sscanf(buffer, "%9s %255s", request->methodStr, request->path) != 2) {
    return -1;
  }

  arena_t* arena = arena_create(sizeof(Header) * MAX_REQUEST_HEADERS * 2);
  if (!arena) {
    return -1;
  }

  // Extract header
  Str* stringBuffer = str_new_witharena(buffer, arena);
  if (!stringBuffer) {
    perror("unable to malloc buffer");
    return -1;
  }

  int header_start_idx = str_find(stringBuffer, "\r\n");
  // char* header_start   = buffer + header_start_idx + 2;  // +2 to skip \r\n

  int end_of_headers_idx = str_find(stringBuffer, "\r\n\r\n");
  // char* end_of_headers   = buffer + end_of_headers_idx + 4;  // +4 to skip \r\n\r\n

  char headers_substring[4096] = {0};
  str_substring(stringBuffer, header_start_idx + 2, end_of_headers_idx, headers_substring,
                sizeof(headers_substring));

  Str* str_headers = str_new_witharena(headers_substring, arena);
  if (!str_headers) {
    fprintf(stderr, "unable to allocate str_headers\n");
    return -1;
  }

  char** substrings =
    str_split_max(str_headers, "\r\n", &request->num_headers, MAX_REQUEST_HEADERS);

  *content_length = 0;
  int n           = request->num_headers;
  int is_safe_m   = is_safe_method(request->methodStr);

  for (int i = 0; i < n; i++) {
    Str* header = str_new_witharena(substrings[i], arena);
    if (!header) {
      printf("unable to allocate header parts\n");
      return -1;
    }

    size_t num_parts    = 0;
    char** header_parts = str_split_max(header, ": ", &num_parts, 2);

    if (num_parts != 2) {
      // Skip this invalid header
      request->num_headers--;
      continue;
    }

    strcpy(request->headers[i].name, header_parts[0]);
    strcpy(request->headers[i].value, header_parts[1]);

    if (!is_safe_m) {
      if (strcmp(header_parts[0], "Content-Length") == 0 ||
          strcmp(header_parts[0], "content-length") == 0) {
        *content_length = atoi(header_parts[1]);
      }
    }
    str_free_substrings(header_parts, num_parts);
  }

  arena_free(arena);

  // Free memory used by substrings
  str_free_substrings(substrings, request->num_headers);

  // Expect no body for the request.
  if (is_safe_m || content_length == 0) {
    return 0;
  }

  request->body = (char*)malloc((*content_length) + 1);
  if (!request->body) {
    perror("malloc");
    return -1;
  }

  // Read the body
  size_t remaining_bytes = *content_length;
  size_t body_offset     = end_of_headers_idx + 4;

  // Copy the body content from the initial buffer
  char* body_ptr                = request->body;
  size_t body_in_initial_buffer = bytes_read - body_offset;
  strncpy(body_ptr, buffer + body_offset, body_in_initial_buffer);
  body_ptr += body_in_initial_buffer;
  remaining_bytes -= body_in_initial_buffer;

  if (remaining_bytes > 0) {
    // Continue reading data until the entire body is received
    while (remaining_bytes > 0) {
      ssize_t more_bytes;
      more_bytes = recv(request->client_fd, body_ptr, remaining_bytes, 0);
      if (more_bytes <= 0) {
        // Handle error or connection closed prematurely
        // Reuest body will be freed in HandleClient.
        printf("Client connection closed prematurely\n");
        return -1;
      }

      body_ptr += more_bytes;
      remaining_bytes -= more_bytes;
    }
  }

  // Null-terminate the body
  request->body[*content_length] = '\0';
  return 0;
}

static bool setRequestMethod(Request* request) {
  if (strcmp(request->methodStr, "GET") == 0) {
    request->method = METHOD_GET;
  } else if (strcmp(request->methodStr, "POST") == 0) {
    request->method = METHOD_POST;
  } else if (strcmp(request->methodStr, "PUT") == 0) {
    request->method = METHOD_PUT;
  } else if (strcmp(request->methodStr, "DELETE") == 0) {
    request->method = METHOD_DELETE;
  } else if (strcmp(request->methodStr, "HEAD") == 0) {
    request->method = METHOD_HEAD;
  } else if (strcmp(request->methodStr, "PATCH") == 0) {
    request->method = METHOD_PATCH;
  } else if (strcmp(request->methodStr, "OPTIONS") == 0) {
    request->method = METHOD_OPTIONS;
  } else {
    return false;
  }
  return true;
}

static void ParseRequest(Context* ctx) {
  char buffer[4096];
  ssize_t contentLen = 0, bytes_read = 0;

  if ((bytes_read = recv(ctx->req->client_fd, buffer, sizeof(buffer), 0)) == -1) {
    perror("recv");
    return;
  }

  if (extract_headers_and_body(ctx->req, buffer, bytes_read, &contentLen) == -1) {
    fprintf(stderr, "Error processing request\n");

    const char* data  = "Internal server error";
    Header headers[1] = {{.name = "Content-Type", .value = "text/html"}};
    setHeaderArray(ctx, headers, sizeof(headers) / sizeof(headers[0]));

    Status(ctx, 500);
    Send(ctx, (void*)data, strlen(data));
    return;
  };

  if (!setRequestMethod(ctx->req)) {
    const char* data  = "Method not allowed";
    Header headers[1] = {{.name = "Content-Type", .value = "text/html"}};
    setHeaderArray(ctx, headers, sizeof(headers) / sizeof(headers[0]));

    Status(ctx, 500);
    Send(ctx, (void*)data, strlen(data));
  }
}

const char* get_status_text(unsigned int statusCode) {
  switch (statusCode) {
    case 100:
      return "Continue";
    case 101:
      return "Switching Protocols";
    case 200:
      return "OK";
    case 201:
      return "Created";
    case 202:
      return "Accepted";
    case 204:
      return "No Content";
    case 300:
      return "Multiple Choices";
    case 301:
      return "Moved Permanently";
    case 302:
      return "Found";
    case 303:
      return "See Other";
    case 304:
      return "Not Modified";
    case 307:
      return "Temporary Redirect";
    case 308:
      return "Permanent Redirect";
    case 400:
      return "Bad Request";
    case 401:
      return "Unauthorized";
    case 403:
      return "Forbidden";
    case 404:
      return "Not Found";
    case 405:
      return "Method Not Allowed";
    case 500:
      return "Internal Server Error";

    default:
      return "Internal Server Error";
  }
}

ssize_t server_send(Context* ctx) {
  ssize_t bytes_sent = 0;

  Request* req  = ctx->req;
  Response* res = ctx->res;

  if (!ctx->headers_sent) {
    char status_line[64];
    size_t response_len = 0;

    // Calculate the total response length
    if (res->header_count > 0) {
      for (size_t i = 0; i < res->header_count; i++) {
        // 4 accounts for ": " and "\r\n"
        response_len += strlen(res->headers[i].name) + strlen(res->headers[i].value) + 4;
      }
    }

    response_len += 4;  // Account for an additional "\r\n" before the body

    char* headerResponse = (char*)malloc(response_len + sizeof(status_line) + 1);
    if (headerResponse == NULL) {
      perror("malloc");
      return -1;
    }

    headerResponse[0] = '\0';
    // Set default status code
    if (res->status == 0) {
      res->status = 200;
      strcpy(res->statusText, get_status_text(res->status));
    }

    snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u %s\r\n", res->status, res->statusText);
    strcat(headerResponse, status_line);

    // Add headers
    for (size_t i = 0; i < res->header_count; i++) {
      strcat(headerResponse, res->headers[i].name);
      strcat(headerResponse, ": ");
      strcat(headerResponse, res->headers[i].value);
      strcat(headerResponse, "\r\n");
    }

    // Add an additional line break before the body
    strcat(headerResponse, "\r\n");

    // Send the response headers
    bytes_sent = send(req->client_fd, headerResponse, strlen(headerResponse), 0);
    if (bytes_sent == -1) {
      perror("send");
    }

    free(headerResponse);
    ctx->headers_sent = true;
  }

  // Handle the case of chunked transfer encoding
  if (ctx->chunked) {
    char chunkSize[16];
    sprintf(chunkSize, "%zx\r\n", res->contentLength);
    // Send the chunk size
    send(req->client_fd, chunkSize, strlen(chunkSize), 0);
  }

  // Send the response body
  ssize_t body_bytes_sent = send(req->client_fd, res->data, res->contentLength, 0);
  if (body_bytes_sent == -1) {
    perror("send");
    return -1;
  } else {
    bytes_sent += body_bytes_sent;
  }

  if (ctx->chunked) {
    // Send end of chunk: Send the chunk's CRLF (carriage return and line feed)
    send(req->client_fd, "\r\n", 2, 0);
  }

  return bytes_sent;
}

void InstallHandler(Server* server, void (*handler)(Context* ctx)) {
  server->handler = handler;
}

void HandleClient(void* args) {
  ClientArg* clientArgs = (ClientArg*)args;
  Request* req          = malloc(sizeof(Request));
  if (!req) {
    perror("malloc");
    return;
  }

  req->body        = NULL;
  req->num_headers = 0;
  req->client_fd   = clientArgs->client_fd;

  // Initialize request/response context
  Context* ctx = &(Context){
    .req = req,
    .res =
      &(Response){
        .status     = 200,
        .statusText = "OK",
        .data       = NULL,
      },
    .headers_sent = 0,
  };

  ParseRequest(ctx);  // Populate request.

  // callback for user. All routing and request processing should be complete.
  clientArgs->server->handler(ctx);

  // for chunked transfer enconding, send end of request
  if (ctx->chunked) {
    // Signal the end of the response with a zero-size chunk
    send(req->client_fd, "0\r\n\r\n", 5, 0);
  }

  closeClient(req->client_fd);

  // Free request body
  if (req->body != NULL) {
    free(req->body);
  }

  free(req);   // Free request memory
  free(args);  // free thread arguments
}

// Signal handler for graceful shutdown on SIGTERM
void handle_shutdown(int signum) {
  printf("\nReceived Ctrl+C (SIGINT). Shutting down the server.\n");
  running = 0;
}

static void debug_str_print(const char* str) {
  for (int i = 0; str[i] != '\0'; i++) {
    if (str[i] == '\n') {
      // Replace newline with the visible escape sequence
      printf("\\n");
    } else if (str[i] == '\r') {
      printf("\\r");
    } else {
      // Print the character as is
      putchar(str[i]);
    }
  }
}

static void closeClient(int client_fd) {
  // Gracefully shutdown the client socket
  if (shutdown(client_fd, SHUT_RDWR) == -1) {
    perror("shutdown");
  }

  if (close(client_fd) == -1) {
    perror("close");
  };
}

// More public APIs for context
Method getMethod(Context* ctx) {
  return ctx->req->method;
}

const char* getMethodAsString(Context* ctx) {
  return (const char*)ctx->req->methodStr;
}

// Function to get a request header by key (case-insensitive)
// TODO: remove allocations
const char* getHeader(Context* ctx, char* key) {
  toLower(key);

  for (int i = 0; i < ctx->req->num_headers; i++) {
    char* h = ctx->req->headers[i].name;
    toLower(h);
    if (strcmp(key, h) == 0) {
      return ctx->req->headers[i].value;
    }
  }
  return "";
}

// Function to return all request headers
const Header* getHeaders(Context* ctx) {
  return ctx->req->headers;
}

// Function to return the number of request headers
ssize_t getNumHeaders(Context* ctx) {
  return ctx->req->num_headers;
}

const char* getBody(Context* ctx) {
  return ctx->req->body;
}

const char* getPathName(Context* ctx) {
  return ctx->req->path;
}

void Status(Context* ctx, uint status) {
  ctx->res->status = status;
  strcpy(ctx->res->statusText, get_status_text(status));
}

Header createHeader(const char* key, const char* value) {
  size_t key_len   = strlen(key);
  size_t value_len = strlen(value);
  Header header    = {0};

  if (key_len <= HEADER_KEY_LENGTH - 1 && value_len <= HEADER_VALUE_LENGTH - 1) {
    strncpy(header.name, key, sizeof(header.name));
    header.name[key_len] = '\0';

    strncpy(header.value, value, sizeof(header.value));
    header.value[value_len] = '\0';
  }
  return header;
}

void setHeader(Context* ctx, const char* key, const char* value) {
  if (ctx->res->header_count < MAX_RESPONSE_HEADERS) {
    Header header = createHeader(key, value);

    if (header.name[0] == '\0' || header.value[0] == '\0') {
      return;  // key or value overflow
    }
    ctx->res->headers[ctx->res->header_count++] = header;
  } else {
    fprintf(stderr, "Exceeded maximum allowed headers: [%d]\n", MAX_RESPONSE_HEADERS);
  }
}

void setHeaderArray(Context* ctx, Header* headers, uint num_headers) {
  for (int i = 0; (i < num_headers && i < MAX_RESPONSE_HEADERS &&
                   ctx->res->header_count < MAX_RESPONSE_HEADERS);
       i++) {
    ctx->res->headers[ctx->res->header_count++] = headers[i];
  }
}

void Send(Context* ctx, void* data, ssize_t contentLength) {
  ctx->res->data          = data;
  ctx->res->contentLength = contentLength;
  server_send(ctx);
}

void EnableStreaming(Context* ctx) {
  setHeader(ctx, "Transfer-Encoding", "chunked");
  ctx->chunked = true;
}

void toLower(char* str) {
  if (str == NULL) {
    return;
  }

  for (int i = 0; i < strlen(str); i++) {
    str[i] = tolower(str[i]);
  }
}
