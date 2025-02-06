#include "../include/middleware.h"
#include "../include/net.h"
#include "../include/request.h"

#include <stdarg.h>

Middleware global_middleware[MAX_GLOBAL_MIDDLEWARE] = {};  // Global middleware
size_t global_middleware_count = 0;                        // Number of global middleware
static map* global_middleware_context = nullptr;           // Global middleware context

void middleware_init(void) {
    global_middleware_context = map_create(10, key_compare_char_ptr);
    if (!global_middleware_context) {
        LOG_FATAL("Failed to create global_middleware_context\n");
    }
}

void middleware_cleanup(void) {
    if (global_middleware_context) {
        map_destroy(global_middleware_context, true);
    }
}

// Set route middleware context or userdata.
void set_middleware_context(Route* route, void* userdata) {
    route->mw_data = userdata;
}

// Set route middleware context or userdata.
void set_global_mw_context(const char* key, void* userdata) {
    if (global_middleware_context == nullptr) {
        global_middleware_context = map_create(8, key_compare_char_ptr);
        if (global_middleware_context == nullptr) {
            LOG_ERROR("unable to create map for global middleware context");
            return;
        }
    }

    char* k = strdup(key);
    if (!k) {
        LOG_ERROR("unable to allocate memory for key: %s", key);
        return;
    }
    map_set(global_middleware_context, k, userdata);
}

void* get_global_middleware_context(const char* key) {
    if (global_middleware_context == nullptr) {
        return nullptr;
    }
    return map_get(global_middleware_context, (char*)key);
}

// get_global_middleware_count returns the number of global middleware functions.
inline size_t get_global_middleware_count(void) {
    return global_middleware_count;
}

// get_global_middleware returns the global middleware functions.
inline Middleware* get_global_middleware(void) {
    return global_middleware;
}

static void middleware_next(context_t* ctx) {
    MiddlewareContext* mw_ctx = ctx->mw_ctx;
    mw_ctx->index++;
    execute_middleware_chain(ctx, mw_ctx);
}

// Advance middleware group without calling the handler.
void execute_middleware_chain(context_t* ctx, MiddlewareContext* mw_ctx) {
    if (mw_ctx->index < mw_ctx->count) {
        // Execute the next middleware in the chain
        mw_ctx->middleware[mw_ctx->index](ctx, middleware_next);
        return;
    }

    // Execute the handler
    mw_ctx->handler(ctx);
}

// ================ Middleware logic ==================
void use_global_middleware(int count, ...) {
    if (global_middleware_count + count > MAX_GLOBAL_MIDDLEWARE) {
        LOG_FATAL("Exceeded maximum global middleware count\n");
    }

    va_list args;
    va_start(args, count);
    for (int i = 0; i < count && global_middleware_count < MAX_GLOBAL_MIDDLEWARE; i++) {
        global_middleware[global_middleware_count++] = va_arg(args, Middleware);
    }

    va_end(args);
}

// Register middleware for a route
void use_route_middleware(Route* route, int count, ...) {
    if (count <= 0) {
        return;
    }

    size_t new_count = route->middleware_count + count;
    Middleware* new_middleware = (Middleware*)realloc(route->middleware, sizeof(Middleware) * new_count);
    if (!new_middleware) {
        perror("realloc");
        LOG_FATAL("Failed to allocate memory for route middleware\n");
    }

    // Update the route middleware
    route->middleware = new_middleware;

    va_list args;
    va_start(args, count);

    // Append the new middleware to the route middleware
    for (size_t i = route->middleware_count; i < new_count; i++) {
        ((Middleware*)(route->middleware))[i] = va_arg(args, Middleware);
    }

    route->middleware_count = new_count;
    va_end(args);
}
