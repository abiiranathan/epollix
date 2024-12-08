
#define _GNU_SOURCE 1

#include "../include/middleware/tokenauth.h"
#include <stdlib.h>
#include <string.h>
#include "../include/fast_str.h"
#include "../include/response.h"

#define BEARER "Bearer "
#define BEARER_LEN 7
#define JWT_PAYLOAD_CONTEXT_NAME "JWT_PAYLOAD_CONTEXT_NAME"

void handleUnauthorized(Response* res) {
    res->status = StatusUnauthorized;
    send_string(res, "Unauthorized");
}

void BearerAuthMiddleware(context_t* ctx, Handler next) {
    const char* auth_header = find_header(ctx->request->headers, ctx->request->header_count, "Authorization");
    if (auth_header == NULL) {
        LOG_ERROR("Authorization header is missing");
        handleUnauthorized(ctx->response);
        return;
    }

    const char* secret = secure_getenv(JWT_TOKEN_SECRET);
    if (secret == NULL) {
        LOG_ERROR("%s environment variable is not set", JWT_TOKEN_SECRET);
        handleUnauthorized(ctx->response);
        return;
    }

    const char* token = boyer_moore_strstr(auth_header, BEARER);
    if (token == NULL) {
        handleUnauthorized(ctx->response);
        return;
    }

    token += BEARER_LEN;  // Skip "Bearer "

    // Verify the token
    JWTPayload* payload = (JWTPayload*)malloc(sizeof(JWTPayload));
    if (!payload) {
        LOG_ERROR("Failed to allocate memory for JWT payload");
        handleUnauthorized(ctx->response);
        return;
    }

    // Verify the token against the secret key.
    jwt_error_t code = jwt_token_verify(token, secret, payload);
    if (code != JWT_SUCCESS) {
        free(payload);
        payload = NULL;
        LOG_ERROR("Invalid JWT token: %s", token);
        handleUnauthorized(ctx->response);
        return;
    }

    // Store the payload in the context
    set_context_value(ctx, JWT_PAYLOAD_CONTEXT_NAME, payload);

    // Call the next middleware or handler
    next(ctx);
}

// Returns a pointer to the JWT payload stored in the context_t object or NULL if the payload is not found.
const JWTPayload* get_jwt_payload(context_t* ctx) {
    return (JWTPayload*)get_context_value(ctx, JWT_PAYLOAD_CONTEXT_NAME);
}
