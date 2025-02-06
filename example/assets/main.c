#include "../../include/net.h"
#include "../../include/response.h"
#include "../../include/server.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void logging_middleware(context_t* ctx, Handler next) {
    printf("Request: %s %s\n", method_tostring(ctx->request->method), ctx->request->path);
    next(ctx);
}

void auth_middleware(context_t* ctx, Handler next) {
    const char* auth = get_request_header(ctx->request, "Authorization");
    if (auth && strcmp(auth, "secret") == 0) {
        printf("Authenticated!!\n");
        next(ctx);
    } else {
        ctx->response->status = 401;
        send_response(ctx->response, "Unauthorized", strlen("Unauthorized"));
    }
}

void index_page(context_t* ctx) {
    servefile(ctx, "build/index.html");
}

void serve_movie(context_t* ctx) {
    servefile(ctx, "build/BigBuckBunny.mp4");
}

// GET /greet/{name}
void handle_greet(context_t* ctx) {
    char* name = (char*)get_param(ctx->request, "name");
    assert(name);
    printf("Hello %s\n", name);

    set_response_header(ctx->response, "Content-Type", "text/plain");
    send_response(ctx->response, name, strlen(name));
}

// /POST /users/create
void handle_create_user(context_t* ctx) {
    MultipartForm form;
    MultipartCode code;
    const char* content_type = get_content_type(ctx->request);
    printf("Content-Type: %s\n", content_type);

    char boundary[128] = {0};
    const char* body = (const char*)ctx->request->body;
    size_t len = ctx->request->content_length;

    // You can also parse it from the body.
    bool ok = multipart_parse_boundary_from_header(content_type, boundary, sizeof(boundary));
    if (ok) {
        code = multipart_parse_form(body, len, boundary, &form);
        if (code != MULTIPART_OK) {
            ctx->response->status = StatusBadRequest;
            const char* error = multipart_error_message(code);
            send_response(ctx->response, (char*)error, strlen(error));
            return;
        }

        const char* username = multipart_get_field_value(&form, "username");
        const char* password = multipart_get_field_value(&form, "password");
        const char* email = multipart_get_field_value(&form, "email");

        printf("[Username]: %s, Password: %s, Email: %s\n", username, password, email);
        printf("\n******************Got %ld files *********************************\n", form.num_files);

        for (size_t i = 0; i < form.num_files; i++) {
            bool saved = multipart_save_file(form.files[i], body, form.files[i]->filename);
            assert(saved);
            printf("Saved file %s\n", form.files[i]->filename);
        }

        multipart_free_form(&form);
        response_redirect(ctx->response, "/");
    } else {
        ctx->response->status = StatusBadRequest;
        const char* error = multipart_error_message(INVALID_FORM_BOUNDARY);
        send_response(ctx->response, (char*)error, strlen(error));
    }
}

// GET /users/register
void render_register_form(context_t* ctx) {
    servefile(ctx, "./build/register_user.html");
}

void* send_time(void* arg) {
    context_t* ctx = (context_t*)arg;
    int count = 1000;
    while (1) {
        time_t rawtime;
        struct tm* timeinfo;
        char buffer[80];

        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

        int ret = response_send_chunk(ctx->response, buffer, strlen(buffer));
        if (ret < 0) {
            break;
        }

        usleep(5000);  // sleep for 500ms.

        if (--count == 0) {
            break;
        }
    }

    pthread_exit(nullptr);
}

void chunked_response(context_t* ctx) {
    pthread_t thread;
    pthread_create(&thread, nullptr, send_time, ctx);
    pthread_join(thread, nullptr);
    response_end(ctx->response);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        LOG_FATAL("Usage: %s [port]\n", argv[0]);
    }

    char* port = argv[1];

    route_get("/", index_page);
    route_get("/movie", serve_movie);
    route_get("/greet/{name}", handle_greet);

    Route* reg = route_get("/users/register", render_register_form);
    use_route_middleware(reg, 1, auth_middleware);

    route_post("/users/create", handle_create_user);
    route_get("/chunked", chunked_response);
    route_static("/static", "./build");

    // Add middleware
    use_global_middleware(1, logging_middleware);

    EpollServer* server = epoll_server_create(0, port, nullptr);
    if (server == nullptr) {
        LOG_FATAL("Failed to create server\n");
    }

    epoll_server_listen(server);
}