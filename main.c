#define _GNU_SOURCE 1  // for secure_getenv

#include "http/http.h"
#include "http/server.h"

void homeHandler(Context* ctx) {
  char* reply = "<h1>Hello world from home page</h1>\n";
  set_header(ctx->response, "Content-Type", "text/html");
  send_response(ctx, reply, strlen(reply));
}

void aboutHandler(Context* ctx) {
  char* reply = "<h1>Hello world from about page</h1>";
  set_header(ctx->response, "Content-Type", "text/html");
  send_response(ctx, reply, strlen(reply));
}

void download(Context* ctx) {
  send_file(ctx, "./README.md");
}

void setupRoutes() {
  GET_ROUTE("/", homeHandler);
  GET_ROUTE("/about", aboutHandler);
  GET_ROUTE("/download", download);
  // STATIC_DIR("/web", "~/server/build");
}

int main(int argc, char* argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s [PORT]\n", argv[0]);
    return EXIT_FAILURE;
  }

  setupRoutes();

  int port = atoi(argv[1]);

  TCPServer* server = new_tcpserver(port);
  listen_and_serve(server, matchRoute);
  return EXIT_SUCCESS;
}
