// Compile with:
// g++ main.cpp ../src/*.c -lsolidc -lcjson -lssl -lcrypto -lz -lsodium ../deps/libbcrypt/libbcrypt.a
// If bcrypt is not compiled, you can use the following command to compile it:
// From the deps/libbcrypt directory:
// run: make
#include "../include/epollix.h"

void helloHandler(context_t* ctx) {
    send_string(ctx, "Hello, World!");
}

int main(void) {
    char port[] = "8080";

    route_get("/hello", helloHandler);

    // use lambda function
    route_get("/lambda", [](context_t* ctx) { send_string(ctx, "Hello, Lambda!"); });

    // use lambda function with parameters
    route_get("/lambda/{name}", [](context_t* ctx) {
        const char* name = get_param(ctx, "name");
        char response[100];
        sprintf(response, "Hello, %s!", name);
        send_string(ctx, response);
    });

    listen_and_serve(port, 4, nullptr);
    return 0;
}
