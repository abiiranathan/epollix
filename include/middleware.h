#ifndef CD46D0A3_AC79_46D7_8A9C_993E1EAA4B34
#define CD46D0A3_AC79_46D7_8A9C_993E1EAA4B34

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <solidc/arena.h>
#include "params.h"
#include "route.h"
#include "types.h"

// Context for middleware functions.
typedef struct MiddlewareContext {
    uint8_t count;           // Number of middleware functions
    uint8_t index;           // Current index in the middleware array
    Middleware* middleware;  // Array of middleware functions
    Handler handler;         // Handler function
} MiddlewareContext;

// Initialize global middleware context.
void middleware_init(void);

// Free global middleware context.
void middleware_cleanup(void);

// get_global_middleware_count returns the number of global middleware functions.
size_t get_global_middleware_count(void);

// get_global_middleware returns the global middleware functions.
Middleware* get_global_middleware(void);

// Advance middleware group without calling the handler.
void execute_middleware_chain(struct epollix_context* ctx, MiddlewareContext* mw_ctx);

// Apply middleware(s) to all registered routes.
void use_global_middleware(int count, ...);

// Apply middleware(s) to a spacific route.
void use_route_middleware(Route* route, int count, ...);

// Apply middleware(s) to a group of routes.
void use_group_middleware(RouteGroup* group, int count, ...);

// Set route middleware context or userdata.
void set_middleware_context(Route* route, void* userdata);

// Set global middleware context or userdata.
void set_global_mw_context(const char* key, void* userdata);

// Returns the global middleware context or userdata or nullptr if not set.
void* get_global_middleware_context(const char* key);

#ifdef __cplusplus
}
#endif

#endif /* CD46D0A3_AC79_46D7_8A9C_993E1EAA4B34 */
