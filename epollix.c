#include "include/server.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define INDEX_TEMPL "index.html"
#define REGISTER_TEMPL "register_user.html"

void print_query_params(map* params) {
    map_foreach(params, entry) {
        printf("%s: %s\n", (char*)entry->key, (char*)entry->value);
    }
}

void index_page(response_t* res) {
    if (res->request->query_params) {
        print_query_params(res->request->query_params);
    }
    http_serve_file(res, "build/index.html");
}

void serve_movie(response_t* res) {
    http_serve_file(res, "build/BigBuckBunny.mp4");
}

// GET /greet/{name}
void handle_greet(response_t* res) {
    char* name = (char*)url_path_param(res->request, "name");
    assert(name);
    printf("Hello %s\n", name);

    set_header(res, "Content-Type", "text/plain");
    send_response(res, name, strlen(name));
}

// /POST /users/create
void handle_create_user(response_t* res) {
    MultipartForm form;
    MultipartCode code;
    const char* content_type = get_content_type(res->request);
    printf("Content-Type: %s\n", content_type);

    char boundary[128] = {0};
    // You can also parse it from the body.
    bool ok = multipart_parse_boundary_from_header(content_type, boundary, sizeof(boundary));
    if (ok) {
        code = multipart_parse_form((char*)res->request->body, res->request->content_length, boundary, &form);
        if (code != MULTIPART_OK) {
            res->status = StatusBadRequest;
            const char* error = multipart_error_message(code);
            send_response(res, (char*)error, strlen(error));
            return;
        }

        const char* username = multipart_get_field_value(&form, "username");
        const char* password = multipart_get_field_value(&form, "password");
        const char* email = multipart_get_field_value(&form, "email");

        printf("[Username]: %s, Password: %s, Email: %s\n", username, password, email);
        printf("\n******************Got %ld files *********************************\n", form.num_files);

        for (size_t i = 0; i < form.num_files; i++) {
            bool saved = multipart_save_file(form.files[i], (char*)res->request->body, form.files[i]->filename);
            assert(saved);
            printf("Saved file %s\n", form.files[i]->filename);
        }

        multipart_free_form(&form);
        response_redirect(res, "/");
    } else {
        res->status = StatusBadRequest;
        const char* error = multipart_error_message(INVALID_FORM_BOUNDARY);
        send_response(res, (char*)error, strlen(error));
    }
}

// GET /users/register
void render_register_form(response_t* res) {
    http_serve_file(res, "./build/register_user.html");
}

void* send_time(void* arg) {
    response_t* res = (response_t*)arg;
    while (1) {
        time_t rawtime;
        struct tm* timeinfo;
        char buffer[80];

        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", timeinfo);

        int ret = response_send_chunk(res, buffer, strlen(buffer));
        if (ret < 0) {
            break;
        }

        usleep(5000);  // sleep for 500ms.
    }

    pthread_exit(NULL);
}

void chunked_response(response_t* res) {
    // send server time every second in a seperate thread to avoid blocking the main thread.
    pthread_t thread;
    pthread_create(&thread, NULL, send_time, res);

    // Wait for the thread to finish.
    pthread_join(thread, NULL);

    response_end(res);
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
    GET_ROUTE("/users/register", render_register_form);
    POST_ROUTE("/users/create", handle_create_user);

    // Chunked response.
    GET_ROUTE("/chunked", chunked_response);

    // Serve a static directory.
    STATIC_DIR("/static", "./build");

    listen_and_serve(port, default_route_matcher, 4);
}