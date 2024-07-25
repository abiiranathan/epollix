#ifndef DF122B59_E09E_45EA_A842_517C7384D3EB
#define DF122B59_E09E_45EA_A842_517C7384D3EB

#include "../epollix.h"

#define BASIC_AUTH_KEY "BasicAuthData"

typedef struct basic_auth_data BasicAuthData;

BasicAuthData* create_basic_auth_data(const char* username, const char* password, const char* realm);

// Basic Auth Middleware applied to a specific route.
// You must set the BasicAuthData before using this middleware
// using the set_route_middleware_context function.
void route_basic_auth(context_t* ctx, Handler next);

// Basic Auth Middleware applied to all routes.
// You must set the BasicAuthData before using this middleware
// using the set_global_middleware_context function using the key BASIC_AUTH_KEY macro
// as the key.
void global_basic_auth(context_t* ctx, Handler next);

#endif /* DF122B59_E09E_45EA_A842_517C7384D3EB */
