#ifndef CD46D0A3_AC79_46D7_8A9C_993E1EAA4B34
#define CD46D0A3_AC79_46D7_8A9C_993E1EAA4B34

#include <inttypes.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "params.h"
#include "route.h"
#include "types.h"

typedef enum { MwGlobal = 1, MwLocal } MwCtxType;

// Context for middleware functions.
typedef struct MiddlewareContext {
    union {
        struct {
            // Global middleware context
            size_t g_count;            // Number of middleware golabl mw functions
            size_t g_index;            // Current index in the global middleware array
            Middleware* g_middleware;  // Array of global middleware functions
        } Global;
        struct {
            size_t r_count;            // Number of route middleware functions
            size_t r_index;            // Current index in the route middleware array
            Middleware* r_middleware;  // Array of route middleware functions
        } Local;
    } ctx;

    MwCtxType ctx_type;
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
void use_global_middleware(size_t count, ...);

// Apply middleware(s) to a spacific route.
void use_route_middleware(Route* route, size_t count, ...);

// Apply middleware(s) to a group of routes.
void use_group_middleware(RouteGroup* group, size_t count, ...);

// Set route middleware context or userdata.
// This user data is free automatically for you at exit.
void set_middleware_context(Route* route, void* userdata);

// Set global middleware context or userdata.
void set_global_mw_context(const char* key, void* userdata);

// Returns the global middleware context or userdata or nullptr if not set.
void* get_global_middleware_context(const char* key);

#ifdef __cplusplus
}
#endif

#endif /* CD46D0A3_AC79_46D7_8A9C_993E1EAA4B34 */
