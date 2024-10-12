#include "tokenauth.h"
#include <string.h>

#define BEARER "Bearer "
#define BEARER_LEN 7
#define JWT_PAYLOAD_CONTEXT_NAME "JWT_PAYLOAD_CONTEXT_NAME"

void unauthorized(context_t* ctx) {
    set_status(ctx, StatusUnauthorized);
    send_string(ctx, "Unauthorized");
}

void BearerAuthMiddleware(context_t* ctx, Handler next) {
    const char* auth_header = find_header(ctx->request->headers, ctx->request->header_count, "Authorization");
    if (auth_header == NULL) {
        unauthorized(ctx);
        return;
    }

    const char* secret = getenv(JWT_TOKEN_SECRET);
    if (secret == NULL) {
        LOG_ERROR("%s environment variable is not set", JWT_TOKEN_SECRET);
        unauthorized(ctx);
        return;
    }

    const char* token = strstr(auth_header, BEARER);
    if (token == NULL) {
        unauthorized(ctx);
        return;
    }

    token += BEARER_LEN;  // Skip "Bearer "

    // Verify the token
    JWTPayload* payload = (JWTPayload*)malloc(sizeof(JWTPayload));
    if (!payload) {
        LOG_ERROR("Failed to allocate memory for JWT payload");
        unauthorized(ctx);
        return;
    }

    if (!jwt_token_verify(token, secret, payload)) {
        LOG_ERROR("Invalid JWT token: %s", token);
        unauthorized(ctx);
        return;
    }

    // Store the payload in the context
    set_context_value(ctx, JWT_PAYLOAD_CONTEXT_NAME, payload);
    next(ctx);
}

// Returns a pointer to the JWT payload stored in the context_t object or NULL if the payload is not found.
const JWTPayload* get_jwt_payload(context_t* ctx) {
    return (const JWTPayload*)get_context_value(ctx, JWT_PAYLOAD_CONTEXT_NAME);
}