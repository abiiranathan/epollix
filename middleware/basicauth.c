#include "basicauth.h"
#include <cipherkit/crypto.h>
#include <string.h>

struct basic_auth_data {
    const char* username;  // Username
    const char* password;  // Password
    const char* realm;     // Protected area
};

BasicAuthData* create_basic_auth_data(const char* username, const char* password, const char* realm) {
    BasicAuthData* data = (BasicAuthData*)malloc(sizeof(BasicAuthData));
    if (data == NULL) {
        return NULL;
    }

    data->username = username;
    data->password = password;
    data->realm = realm;
    return data;
}

// parse the Authorization header and extract credentials
static int parse_authorization_header(const char* auth_header, char** out_username, char** out_password) {
    // Check if the header starts with "Basic "
    if (strncmp(auth_header, "Basic ", 6) != 0) {
        return -1;
    }

    // Extract the Base64-encoded part of the header
    const char* encoded_credentials = auth_header + 6;

    // Decode the Base64-encoded credentials
    size_t decoded_length = 0;
    unsigned char* decoded_credentials = crypto_base64_decode(encoded_credentials, &decoded_length);
    if (decoded_credentials == NULL) {
        return -1;
    }

    // Null-terminate the decoded credentials
    decoded_credentials[decoded_length] = '\0';

    // Split the decoded credentials into username and password
    char* colon_pos = strchr((char*)decoded_credentials, ':');
    if (colon_pos == NULL) {
        free(decoded_credentials);
        return -1;
    }

    *colon_pos = '\0';
    *out_username = strdup((char*)decoded_credentials);
    *out_password = strdup(colon_pos + 1);

    free(decoded_credentials);
    return 0;
}

static void userUnathorized(context_t* ctx) {
    set_status(ctx, StatusUnauthorized);
    set_header(ctx, "WWW-Authenticate", "Basic realm=\"Protected\"");
    send_string(ctx, "Unauthorized");
}

static void handle(context_t* ctx, Handler next, BasicAuthData* auth_data) {
    const char* auth_header = find_header(ctx->request->headers, ctx->request->header_count, "Authorization");
    if (auth_header == NULL) {
        userUnathorized(ctx);
        return;
    }

    char* username = NULL;
    char* password = NULL;

    if (parse_authorization_header(auth_header, &username, &password) != 0) {
        goto unauthorized;
    }

    if (strcmp(username, auth_data->username) == 0 && strcmp(password, auth_data->password) == 0) {
        free(username);
        free(password);
        next(ctx);
        return;
    }

unauthorized:
    if (username) {
        free(username);
    }

    if (password) {
        free(password);
    }
    userUnathorized(ctx);
}

void route_basic_auth(context_t* ctx, Handler next) {
    BasicAuthData* auth_data = (BasicAuthData*)get_route_middleware_context(ctx);
    if (auth_data == NULL) {
        userUnathorized(ctx);
        return;
    }
    handle(ctx, next, auth_data);
}

void global_basic_auth(context_t* ctx, Handler next) {
    BasicAuthData* auth_data = (BasicAuthData*)get_global_middleware_context(BASIC_AUTH_KEY);
    if (auth_data == NULL) {
        userUnathorized(ctx);
        return;
    }
    handle(ctx, next, auth_data);
}