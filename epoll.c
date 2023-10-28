#include "http/router.h"
#include "http/server.h"

void homeHandler(Context* ctx) {
  char* reply = "Hello world from home page\n";
  send_response(ctx->response, reply, strlen(reply));
}

void aboutHandler(Context* ctx) {
  char* reply = "<h1>Hello world from about page</h1>";
  set_header(ctx->response, "Content-Type", "text/html");
  send_response(ctx->response, reply, strlen(reply));
}

void download(Context* ctx) {
  ssize_t bytes_sent = 0;
  send_file(ctx->response, "/home/nabiizy/Downloads/Low Level Programming.pdf", &bytes_sent);
}

void setupRoutes() {
  GET_ROUTE("/", homeHandler);
  GET_ROUTE("/about", aboutHandler);
  GET_ROUTE("/download", download);
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [PORT]\n", argv[0]);
    return EXIT_FAILURE;
  }

  setupRoutes();

  int port          = atoi(argv[1]);
  TCPServer* server = new_tcpserver(port);
  listen_and_serve(server, matchRoute);
  free(server);
  return EXIT_SUCCESS;
}
