#include "server.h"

void RequestHandler(Context* ctx) {
  const char* buff = "<h1>Hello from the server</h1>\n";

  // const char* data = getBody(ctx);

  Send(ctx, (void*)buff, strlen(buff));
}

int main(int argc, char const* argv[]) {
  Server* server = NewTCPServer(9999);
  InstallHandler(server, RequestHandler);
  RunForever(server);
  return 0;
}
