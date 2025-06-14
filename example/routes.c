#define USE_LOGGER 0

#include "../include/epollix.h"

#include <sys/cdefs.h>
#include <stdio.h>
#include <cipherkit/cipherkit.h>
#include <cjson/cJSON.h>

void index_page(context_t* ctx) {
    set_content_type(ctx, "text/html");
    servefile(ctx, "assets/index.html");
}

const char* filename = "~/Downloads/BigBuckBunny.mp4";
FILE* file           = NULL;
off64_t size         = 0;

void open_movie(void) {
    file = fopen(filename, "rb");
    if (!file) {
        LOG_ERROR("Unable to open file: %s", filename);
        return;
    }

    // Get the file size
    fseeko64(file, 0, SEEK_END);
    size = ftello64(file);
    fseeko64(file, 0, SEEK_SET);
}

void serve_movie(context_t* ctx) {
    if (file == NULL) {
        set_content_type(ctx, "video/mp4");
        serve_open_file(ctx, file, size, filename);
    } else {
        ctx->response->status = StatusNotFound;
        send_string(ctx, "FILE NOT FOUND");
    }
}

// GET /greet/{name}
void handle_greet(context_t* ctx) {
    const char* name = get_param(ctx->request, "name");
    assert(name);
    printf("Hello %s\n", name);

    write_header(ctx, "Content-Type", "text/plain");
    send_response(ctx, name, strlen(name));
}

// /POST /users/create
void handle_create_user(context_t* ctx) {
    MultipartForm form;
    MultipartCode code;
    const char* content_type = get_content_type(ctx->request);

    char boundary[128] = {0};
    if (!multipart_parse_boundary_from_header(content_type, boundary, sizeof(boundary))) {
        ctx->response->status = StatusBadRequest;
        const char* error     = multipart_error_message(INVALID_FORM_BOUNDARY);
        send_string(ctx, error);
        return;
    }
    printf("Boundary: %s\n", boundary);

    char* body = (char*)ctx->request->body;
    printf("Body: %s\n", body);
    code = multipart_parse_form((char*)body, ctx->request->content_length, boundary, &form);
    if (code != MULTIPART_OK) {
        ctx->response->status = StatusBadRequest;
        const char* error     = multipart_error_message(code);
        send_response(ctx, error, strlen(error));
        return;
    }

    const char* username = multipart_get_field_value(&form, "username");
    const char* password = multipart_get_field_value(&form, "password");
    const char* email    = multipart_get_field_value(&form, "email");

    printf("[Username]: %s, Password: %s, Email: %s\n", username, password, email);
    printf("\n******************Got %ld files *********************************\n", form.num_files);

    for (size_t i = 0; i < form.num_files; i++) {
        bool saved = multipart_save_file(form.files[i], body, form.files[i]->filename);
        if (!saved) {
            printf("Failed to save file %s\n", form.files[i]->filename);
            continue;
        }

        printf("Saved file %s\n", form.files[i]->filename);
    }

    // Generate a JWT token
    unsigned long expiry_hours_in_ms = 3600;  // 1 hour
    unsigned long expiry             = (unsigned long)(time(NULL) + expiry_hours_in_ms);
    const char* sub                  = username;

    JWTPayload payload = {.exp = expiry};
    strlcpy(payload.sub, sub, sizeof(payload.sub));
    strlcpy(payload.data, email, sizeof(payload.data));

    const char* secret = getenv(JWT_TOKEN_SECRET);
    if (secret == NULL) {
        LOG_ERROR("%s environment variable is not set", JWT_TOKEN_SECRET);
        ctx->response->status = StatusInternalServerError;
        send_string(ctx, "Internal Server Error");
        return;
    }

    char* jwtToken      = NULL;
    jwt_error_t jwt_err = jwt_token_create(&payload, secret, &jwtToken);
    if (jwt_err != JWT_SUCCESS) {
        LOG_ERROR("Failed to create JWT token: %s", jwt_error_string(jwt_err));
        ctx->response->status = StatusInternalServerError;
        send_string(ctx, "Internal Server Error");
        return;
    }

    LOG_INFO("Generated JWT token: %s", jwtToken);

    // response_redirect(ctx, "/");

    // Send a JSON response
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "username", username);
    cJSON_AddStringToObject(json, "email", email);
    cJSON_AddStringToObject(json, "token", jwtToken);

    free(jwtToken);

    char* data = cJSON_Print(json);
    send_json_string(ctx, data);
    free(data);

    cJSON_Delete(json);
    multipart_free_form((MultipartForm*)&form);
}

// GET /users/register
void render_register_form(context_t* ctx) {
    set_content_type(ctx, "text/html");
    servefile(ctx, "./assets/register_user.html");
}

// Beared Authenticated route
__attribute_used__ void protected_route(context_t* ctx) {
    const JWTPayload* payload = get_jwt_payload(ctx);
    send_string_f(ctx, "Protected route:\nYour username is: %s\n", payload->sub);
}

static void* send_time(void* arg) {
    context_t* ctx = (context_t*)arg;
    int count      = 1000;
    while (1) {
        time_t rawtime;
        struct tm* timeinfo;
        char buffer[80];

        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer, 80, "%Y-%m-%d %H:%M:%S\n", timeinfo);

        ssize_t ret = response_send_chunk(ctx, buffer, strlen(buffer));
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

void api_index(context_t* ctx) {
    char* data = "{\"message\": \"Welcome to the API\"}";
    send_json(ctx, data, strlen(data));
}

typedef struct User {
    char* username;
    char* email;
    char* password;
} User;

void api_users(context_t* ctx) {
    User users[10] = {0};
    for (int i = 0; i < 10; i++) {
        users[i].username = "user";
        users[i].email    = "randomemail@gmail.com";
        users[i].password = "password";
    }

    cJSON* root        = cJSON_CreateObject();
    cJSON* users_array = cJSON_CreateArray();

    for (int i = 0; i < 10; i++) {
        cJSON* user = cJSON_CreateObject();
        cJSON_AddStringToObject(user, "username", users[i].username);
        cJSON_AddStringToObject(user, "email", users[i].email);
        cJSON_AddStringToObject(user, "password", users[i].password);
        cJSON_AddItemToArray(users_array, user);
    }

    cJSON_AddItemToObject(root, "users", users_array);

    char* data = cJSON_Print(root);
    send_json_string(ctx, data);

    cJSON_Delete(root);
    free(data);
}

void api_user_by_id(context_t* ctx) {
    const char* id = get_param(ctx->request, "id");
    assert(id);

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "{\"user\": \"%s\"}", id);
    send_json_string(ctx, buffer);
}

void gzip_route(context_t* ctx) {
    char* data                     = "<h1>Hello there. This is GZIP compressed data</h1>";
    unsigned char* compressed_data = NULL;
    size_t compressed_data_len     = 0;
    gzip_compress_bytes((uint8_t*)data, strlen(data), &compressed_data, &compressed_data_len);

    write_header(ctx, "Content-Encoding", "gzip");
    send_response(ctx, (void*)compressed_data, compressed_data_len);

    free(compressed_data);
}
