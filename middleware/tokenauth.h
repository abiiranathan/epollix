#ifndef CE7D16EF_5604_4957_A4B1_24F7EC61C514
#define CE7D16EF_5604_4957_A4B1_24F7EC61C514

#include <cipherkit/jwt.h>
#include "../include/net.h"

#define JWT_TOKEN_SECRET "JWT_TOKEN_SECRET"

// BearerAuthMiddleware is a middleware that checks if the Authorization header contains a valid Bearer token.
// You must set the JWT_TOKEN_SECRET environment variable to the null-terminated secret key used to sign the token.
// If the token is valid the middleware calls the next handler in the chain and stores the JWT payload in the context_t object.
// The payload can be retrieved using the get_jwt_payload function.
//
// If the token is invalid, the middleware sends a 401 Unauthorized response.
//
// This assumes that you generated the token using the jwt_token_create function passing the same
// secret key to sign the token.
void BearerAuthMiddleware(context_t* ctx, Handler next);

// Returns a pointer to the JWT payload stored in the context_t object or NULL if the payload is not found.
const JWTPayload* get_jwt_payload(context_t* ctx);

#endif /* CE7D16EF_5604_4957_A4B1_24F7EC61C514 */
