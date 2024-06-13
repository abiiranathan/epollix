#define _GNU_SOURCE 1  // for secure_getenv

#include <solidc/map.h>
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

void loginUser(Context* ctx) {
    parse_form(ctx->request);

    MultipartForm* multipart = ctx->request->multipart;
    if (multipart->form == NULL) {
        set_status(ctx->response, StatusBadRequest);
        char* msg = (char*)get_form_error(multipart->error);
        send_response(ctx, msg, strlen(msg));
        return;
    }

    const char* username = map_get(multipart->form, "username");
    const char* password = map_get(multipart->form, "password");

    if (username == NULL || password == NULL) {
        set_status(ctx->response, StatusBadRequest);
        send_response(ctx, "Username and password are required", 34);
        return;
    }

    // Extract file from request
    FileHeader* fileHeaders;
    size_t num_files;
    fileHeaders = get_form_files("file", ctx->request, &num_files);
    if (!fileHeaders) {
        set_status(ctx->response, StatusBadRequest);
        send_response(ctx, "Expected file, not found", 24);
        return;
    }

    char path[1024];
    filepath_join_buf("uploads", fileHeaders[0].filename, path, sizeof(path));

    if (!save_file_to_disk(path, fileHeaders[0], ctx->request)) {
        set_status(ctx->response, StatusInternalServerError);
        send_response(ctx, "Error saving file to disk", 25);
        return;
    }

    printf("File %s saved successfully\n", path);
    const char* json = "{\"username\": \"%s\", \"password\": \"%s\"}";

    // send back json
    char* reply = NULL;
    asprintf(&reply, json, username, password);
    set_header(ctx->response, "Content-Type", "application/json");
    send_response(ctx, reply, strlen(reply));

    map_destroy(multipart->form, true);
    free(reply);
}

void setupRoutes() {
    GET_ROUTE("/", homeHandler);
    GET_ROUTE("/about", aboutHandler);
    GET_ROUTE("/download", download);
    POST_ROUTE("/login", loginUser);
    STATIC_DIR("/web", "./web");
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
