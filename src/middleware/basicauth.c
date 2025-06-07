#include <cipherkit/crypto.h>
#include <string.h>

#include "../include/middleware/basicauth.h"
#include "../include/response.h"
#include <solidc/defer.h>
#include <assert.h>

struct basicAuthUser {
    const char* username;  // Username
    const char* password;  // Password
    const char* realm;     // Protected area
};

BasicAuthUser* new_basic_auth_user(const char* username, const char* password, const char* realm) {
    BasicAuthUser* data = (BasicAuthUser*)malloc(sizeof(BasicAuthUser));
    assert(data != NULL);

    data->username = username;
    data->password = password;
    data->realm    = realm;
    return data;
}

// parse the Authorization header and extract credentials
static bool basic_auth_matches(const char* auth_header, BasicAuthUser* auth_data) {
    // Check if the header starts with "Basic "
    if (strncmp(auth_header, "Basic ", 6) != 0) {
        return false;
    }

    // Extract the Base64-encoded part of the header
    const char* encoded_credentials = auth_header + 6;
    if (strcmp(encoded_credentials, "") == 0) {
        return false;
    }

    // Decode the Base64-encoded credentials
    size_t decoded_length              = 0;
    unsigned char* decoded_credentials = crypto_base64_decode(encoded_credentials, &decoded_length);
    if (decoded_credentials == NULL || decoded_length == 0) {
        return false;
    }

    // Null-terminate the decoded credentials
    decoded_credentials[decoded_length] = '\0';
    defer({ free(decoded_credentials); });

    // Split the decoded credentials into username and password
    char* colon_pos = strchr((char*)decoded_credentials, ':');
    if (colon_pos == NULL) {
        return false;
    }
    *colon_pos = '\0';

    // compare username first
    if (strcmp(auth_data->username, (char*)decoded_credentials) != 0) {
        return false;
    }

    // Move past username and colon  to password
    char* password = colon_pos + 1;
    if (strcmp(auth_data->password, password) != 0) {
        return false;
    }
    return true;
}

static void userUnathorized(context_t* ctx) {
    ctx->response->status = StatusUnauthorized;
    write_header(ctx, "WWW-Authenticate", "Basic realm=\"Protected\"");
    send_string(ctx, "Unauthorized");
}

static void handleAuth(context_t* ctx, Handler next, BasicAuthUser* auth_data) {
    const char* auth_header = headers_value(ctx->request->headers, "Authorization");
    if (auth_header == NULL) {
        userUnathorized(ctx);
        return;
    }

    if (!basic_auth_matches(auth_header, auth_data)) {
        userUnathorized(ctx);
        return;
    }

    // User is authenticated.
    next(ctx);
}

void route_basic_auth(context_t* ctx, Handler next) {
    BasicAuthUser* auth_data = (BasicAuthUser*)route_middleware_context(ctx);
    assert(auth_data != NULL);
    handleAuth(ctx, next, auth_data);
}

void global_basic_auth(context_t* ctx, Handler next) {
    BasicAuthUser* auth_data = (BasicAuthUser*)get_global_middleware_context(BASIC_AUTH_KEY);
    assert(auth_data != NULL);
    handleAuth(ctx, next, auth_data);
}
