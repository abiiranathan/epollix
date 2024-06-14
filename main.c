#define _GNU_SOURCE 1  // for secure_getenv

#include <solidc/map.h>
#include "include/http.h"
#include "include/server.h"

void homeHandler(Context* ctx) {
    set_header(ctx->response, "Content-Type", "text/html");
    send_string(ctx, "<h1>Hello world from home page</h1>\n");
}

void aboutHandler(Context* ctx) {
    set_header(ctx->response, "Content-Type", "text/html");
    send_string(ctx, "<h1>Hello world from about page</h1>");
}

void download(Context* ctx) {
    send_file(ctx, "./README.md");
}

// TODO: parse_form currently works well with application/x-www-form-urlencoded
// TODO: and multipart/form-data with text fields. It supports file uploads
// TODO: for plain text files. It does not support binary files yet.
void loginUser(Context* ctx) {
    parse_form(ctx->request);

    MultipartForm* multipart = ctx->request->multipart;
    if (multipart->form == NULL) {
        set_status(ctx->response, StatusBadRequest);
        send_string(ctx, get_form_error(multipart->error));
        return;
    }

    const char* username = map_get(multipart->form, "username");
    const char* password = map_get(multipart->form, "password");

    if (username == NULL || password == NULL) {
        set_status(ctx->response, StatusBadRequest);
        send_string(ctx, "Username and password are required\n");
        return;
    }

    // Extract file from request
    FileHeader* fileHeaders;
    size_t num_files;
    fileHeaders = get_form_files("file", ctx->request, &num_files);
    if (!fileHeaders) {
        set_status(ctx->response, StatusBadRequest);
        send_string(ctx, "Expected file, not found\n");
        return;
    }

    char path[1024];
    filepath_join_buf("uploads", fileHeaders[0].filename, path, sizeof(path));

    if (!save_file_to_disk(path, fileHeaders[0], ctx->request)) {
        set_status(ctx->response, StatusInternalServerError);
        send_string(ctx, "Error saving file to disk\n");
        return;
    }

    // printf("File %s saved successfully\n", path);
    const char* json = "{\"username\": \"%s\", \"password\": \"%s\"}";

    // send back json
    char* reply = NULL;
    asprintf(&reply, json, username, password);
    printf("JSON: %s\n", reply);
    free(reply);
    redirect(ctx, "/about");
}

// GET /users/{username}/profile
void profileHandler(Context* ctx) {
    const char* username = url_path_param(ctx, "username");
    char* reply = NULL;
    asprintf(&reply, "<h1>Hello %s</h1>\n", username);
    send_string(ctx, reply);
    free(reply);
}

void setupRoutes() {
    GET_ROUTE("/", homeHandler);
    GET_ROUTE("/about", aboutHandler);
    GET_ROUTE("/download", download);
    POST_ROUTE("/login", loginUser);
    GET_ROUTE("/users/{username}/profile", profileHandler);
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
    listen_and_serve(server, matchRoute, 2);
    return EXIT_SUCCESS;
}
