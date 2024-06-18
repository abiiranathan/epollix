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

void loginUser(Context* ctx) {
    MultipartForm form_data = {0};
    MultipartCode code;
    code = parse_multipart_form(ctx->request, &form_data);

    if (code != MULTIPART_OK) {
        set_status(ctx->response, StatusBadRequest);
        send_string(ctx, multipart_error_message(code));
        return;
    }

    const char* username = multipart_get_field_value(&form_data, "username");
    const char* password = multipart_get_field_value(&form_data, "password");
    printf("Username: %s\n", username);
    printf("Password: %s\n", password);

    // Save all the uploaded files if any to disk
    char path[1024] = {0};
    for (size_t i = 0; i < form_data.num_files; i++) {
        memset(path, 0, sizeof(path));  // re-initialize path
        bool ok = filepath_join_buf("uploads", form_data.files[i]->filename, path, sizeof(path));
        if (!ok) {
            printf("Error joining path\n");
            continue;
        }

        // The file is an offset+size of the body
        ok = multipart_save_file(form_data.files[i], ctx->request->body, path);
        if (!ok) {
            printf("Error saving file: %s\n", path);
            continue;
        }
        printf("File %s saved successfully with size %lu\n", path, form_data.files[i]->size);
    }

    // printf("File %s saved successfully\n", path);
    const char* json = "{\"username\": \"%s\", \"password\": \"%s\"}";

    // send back json
    char* reply = NULL;
    asprintf(&reply, json, username, password);

    // send back json
    set_status(ctx->response, StatusOK);
    set_header(ctx->response, "Content-Type", "application/json");
    send_json(ctx, reply);

    // Free reply
    free(reply);

    // Free form data
    free_form_data(&form_data);
    //  Or better: multipart_free_form(&form_data);
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

// 306694 - Screenshot