#include "include/epollix.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

void logging_middleware(context_t* ctx, Handler next) {
    printf("Request: %s %s\n", get_method_str(ctx), get_path(ctx));
    next(ctx);
}

void auth_middleware(context_t* ctx, Handler next) {
    const char* auth = get_header(ctx, "Authorization");
    if (auth && strcmp(auth, "secret") == 0) {
        printf("Authenticated!!\n");
        next(ctx);
    } else {
        set_status(ctx, 401);
        send_response(ctx, "Unauthorized", strlen("Unauthorized"));
    }
}

void index_page(context_t* ctx) {
    http_serve_file(ctx, "build/index.html");
}

void serve_movie(context_t* ctx) {
    http_serve_file(ctx, "build/BigBuckBunny.mp4");
}

// GET /greet/{name}
void handle_greet(context_t* ctx) {
    char* name = (char*)get_param(ctx, "name");
    assert(name);
    printf("Hello %s\n", name);

    set_header(ctx, "Content-Type", "text/plain");
    send_response(ctx, name, strlen(name));
}

// /POST /users/create
void handle_create_user(context_t* ctx) {
    MultipartForm form;
    MultipartCode code;
    const char* content_type = get_content_type(ctx);
    printf("Content-Type: %s\n", content_type);

    char boundary[128] = {0};
    // You can also parse it from the body.
    bool ok = multipart_parse_boundary_from_header(content_type, boundary, sizeof(boundary));
    if (ok) {
        char* body = get_body(ctx);
        code = multipart_parse_form(body, get_body_length(ctx), boundary, &form);
        if (code != MULTIPART_OK) {
            set_status(ctx, StatusBadRequest);
            const char* error = multipart_error_message(code);
            send_response(ctx, (char*)error, strlen(error));
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
        response_redirect(ctx, "/");
    } else {
        set_status(ctx, StatusBadRequest);
        const char* error = multipart_error_message(INVALID_FORM_BOUNDARY);
        send_response(ctx, (char*)error, strlen(error));
    }
}

// GET /users/register
void render_register_form(context_t* ctx) {
    http_serve_file(ctx, "./build/register_user.html");
}

void* send_time(void* arg) {
    context_t* ctx = (context_t*)arg;
    int count = 10000;
    while (1) {
        time_t rawtime;
        struct tm* timeinfo;
        char buffer[80];

        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

        int ret = response_send_chunk(ctx, buffer, strlen(buffer));
        if (ret < 0) {
            break;
        }

        usleep(5000);  // sleep for 500ms.

        if (--count == 0) {
            break;
        }
    }

    pthread_exit(NULL);
}

void chunked_response(context_t* ctx) {
    pthread_t thread;
    pthread_create(&thread, NULL, send_time, ctx);
    pthread_join(thread, NULL);
    response_end(ctx);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [port]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char* port = argv[1];

    GET_ROUTE("/", index_page);
    GET_ROUTE("/movie", serve_movie);
    GET_ROUTE("/greet/{name}", handle_greet);

    Route* reg = GET_ROUTE("/users/register", render_register_form);
    use_route_middleware(reg, auth_middleware);

    POST_ROUTE("/users/create", handle_create_user);
    GET_ROUTE("/chunked", chunked_response);
    STATIC_DIR("/static", "./build");

    // Add middleware
    use_global_middleware(logging_middleware);

    listen_and_serve(port, default_route_matcher, 4);
}