#include <cjson/cJSON.h>
#include "../include/epollix.h"
#include "../include/mw/basicauth.h"
#include "../include/mw/logger.h"
#include "gzip.h"
#include "jwt.h"
#include "mw/tokenauth.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// ======================= Routes =======================
void index_page(context_t* ctx) {
    http_servefile(ctx, "assets/index.html");
}

void serve_movie(context_t* ctx) {
    http_servefile(ctx, "assets/BigBuckBunny.mp4");
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

    char boundary[128] = {0};
    if (!multipart_parse_boundary_from_header(content_type, boundary, sizeof(boundary))) {
        set_status(ctx, StatusBadRequest);
        const char* error = multipart_error_message(INVALID_FORM_BOUNDARY);
        send_string(ctx, error);
        return;
    }

    char* body = get_body(ctx);
    code = multipart_parse_form(body, get_body_size(ctx), boundary, &form);
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

    // Generate a JWT token
    unsigned long expiry_hours_in_ms = 3600;  // 1 hour
    unsigned long expiry = (unsigned long)(time(NULL) + expiry_hours_in_ms);
    char* sub = (char*)username;

    JWTPayload payload = {0};
    strncpy(payload.sub, sub, sizeof(payload.sub));
    payload.exp = expiry;
    strncpy(payload.data, email, sizeof(payload.data));

    const char* secret = getenv(JWT_TOKEN_SECRET);
    if (secret == NULL) {
        LOG_ERROR("%s environment variable is not set", JWT_TOKEN_SECRET);
        set_status(ctx, StatusInternalServerError);
        send_string(ctx, "Internal Server Error");
        return;
    }

    autofree char* jwtToken = jwt_token_create(&payload, secret);
    LOG_INFO("Generated JWT token: %s", jwtToken);

    // response_redirect(ctx, "/");

    // Send a JSON response
    cJSON* json = cJSON_CreateObject();
    cJSON_AddStringToObject(json, "username", username);
    cJSON_AddStringToObject(json, "email", email);
    cJSON_AddStringToObject(json, "token", jwtToken);

    autofree char* data = cJSON_Print(json);
    send_json_string(ctx, data);

    cJSON_Delete(json);
    multipart_free_form((MultipartForm*)&form);
}

// GET /users/register
void render_register_form(context_t* ctx) {
    http_servefile(ctx, "./assets/register_user.html");
}

// Beared Authenticated route
void protected_route(context_t* ctx) {
    const JWTPayload* payload = get_jwt_payload(ctx);
    if (payload == NULL) {
        set_status(ctx, StatusUnauthorized);
        send_string(ctx, "Unauthorized: Missing JWT token");
        return;
    }

    send_string_f(ctx, "Protected route:\nYour username is: %s\n", payload->sub);
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

static void api_index(context_t* ctx) {
    char* data = "{\"message\": \"Welcome to the API\"}";
    send_json(ctx, data, strlen(data));
}

static void api_users(context_t* ctx) {
    char* data = "{\"users\": [\"Alice\", \"Bob\", \"Charlie\"]}";
    send_json_string(ctx, data);
}

static void api_user_by_id(context_t* ctx) {
    char* id = (char*)get_param(ctx, "id");
    assert(id);

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "{\"user\": \"%s\"}", id);
    send_json_string(ctx, buffer);
}

void gzip_route(context_t* ctx) {
    char* data = "<h1>Hello there. This is GZIP compressed data</h1>";
    unsigned char* compressed_data = NULL;
    size_t compressed_data_len = 0;
    gzip_compress_bytes((uint8_t*)data, strlen(data), &compressed_data, &compressed_data_len);

    set_header(ctx, "Content-Encoding", "gzip");
    send_response(ctx, (void*)compressed_data, compressed_data_len);

    free(compressed_data);
}

FILE* logFile = NULL;

void cleanup(void) {
    if (logFile) {
        fclose(logFile);
    }
}

void spa_route(context_t* ctx) {
    printf("Serving SPA route\n");
    http_servefile(ctx, "/home/nabiizy/Code/C/pdfsearch/frontend/build/index.html");
}

// ======================= END OF ROUTES ========================================
int main(int argc, char** argv) {
    char* port = "3000";
    if (argc == 2) {
        port = argv[1];
    }

    BasicAuthData *guest = NULL, *admin = NULL;

    // Set the JWT token secret used to sign the token for Bearer authentication
    setenv(JWT_TOKEN_SECRET, "super_jwt_token_secret", 1);

    use_global_middleware(1, epollix_logger);

    // We need a way to associate the BasicAuthData to a route since C has no support for closures.
    // we can use the set_mw_context function to set the BasicAuthData to a specific route.
    // Or we can use the set_global_mw_context function to set the BasicAuthData to all routes.
    guest = create_basic_auth_data("guest", "guest", "Protected");
    admin = create_basic_auth_data("admin", "admin", "ProtectedAdmin");

    LOG_ASSERT(guest != NULL, "Failed to allocate memory for BasicAuthData");
    LOG_ASSERT(admin != NULL, "Failed to allocate memory for BasicAuthData");

    // set_global_mw_context(BASIC_AUTH_KEY, guest);
    // use_global_middleware(1, global_basic_auth);
    // Since guest is not used: lets free it manually
    // If passed to middleware context, its freed automatically
    free(guest);

    // route_get("/", index_page);
    route_get("/movie", serve_movie);
    route_get("/greet/{name}", handle_greet);
    route_get("/gzip", gzip_route);

    Route* pr = route_get("/protected", protected_route);

    // Expects a valid secret to be set in the JWT_TOKEN_SECRET environment variable
    use_route_middleware(pr, 1, BearerAuthMiddleware);

    Route* reg = route_get("/users/register", render_register_form);
    set_mw_context(reg, admin);
    use_route_middleware(reg, 1, route_basic_auth);

    route_post("/users/create", handle_create_user);
    route_get("/chunked", chunked_response);

    // Enable directory browsing
    enable_directory_browsing(true);
    route_static("/static", "./assets");

    // Create a route group
    RouteGroup* group = route_group("/api/v1");
    route_group_get(group, "/", api_index);
    route_group_get(group, "/users", api_users);
    route_group_get(group, "/users/{id}", api_user_by_id);
    route_group_free(group);

    // Add middleware
    append_log_flags(LOG_IP);

    logFile = fopen("server.log", "w");
    LOG_ASSERT(logFile != NULL, "Failed to open log file");
    set_log_file(logFile);

    listen_and_serve(port, default_route_matcher, 2, cleanup);
}
