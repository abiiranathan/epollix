#include "../include/middleware.h"
#include "../include/epollix.h"
#include "../include/request.h"

#include <stdarg.h>

Middleware global_middleware[MAX_GLOBAL_MIDDLEWARE] = {};  // Global middleware
size_t global_middleware_count = 0;                        // Number of global middleware
static map* global_middleware_context = NULL;              // Global middleware context

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
    if (global_middleware_context == NULL) {
        global_middleware_context = map_create(8, key_compare_char_ptr);
        if (global_middleware_context == NULL) {
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
    if (global_middleware_context == NULL) {
        return NULL;
    }
    return map_get(global_middleware_context, (char*)key);
}

// Combine global and route-specific middleware
Middleware* merge_middleware(Route* route, MiddlewareContext* mw_ctx) {
    size_t total_count = global_middleware_count + route->middleware_count;
    Middleware* combined = (Middleware*)malloc(sizeof(Middleware) * total_count);
    if (combined == NULL) {
        LOG_ERROR("malloc failed");
        return NULL;
    }

    uint8_t combined_count = 0;

    // Add global middleware
    for (size_t i = 0; i < (size_t)global_middleware_count; i++) {
        combined[combined_count++] = global_middleware[i];
    }

    // Add route middleware.
    for (size_t i = 0; i < (size_t)route->middleware_count; i++) {
        combined[combined_count++] = ((Middleware*)(route->middleware))[i];
    }

    mw_ctx->middleware = combined;
    mw_ctx->count = combined_count;    // Set total mw count for the context.
    mw_ctx->index = 0;                 // Initialize middlewares traversed to 0
    mw_ctx->handler = route->handler;  // Store a reference to handler
    return combined;
}

// get_global_middleware_count returns the number of global middleware functions.
size_t get_global_middleware_count(void) {
    return global_middleware_count;
}

// get_global_middleware returns the global middleware functions.
Middleware* get_global_middleware(void) {
    return global_middleware;
}

static void middleware_next(context_t* ctx) {
    MiddlewareContext* mw_ctx = ctx->mw_ctx;
    execute_middleware(ctx, mw_ctx->middleware, mw_ctx->count, (mw_ctx->index++), mw_ctx->handler);
}

void execute_middleware(context_t* ctx, Middleware* middleware, size_t count, size_t index, Handler handler) {
    if (index < count) {
        // Execute the next middleware in the chain
        middleware[index](ctx, middleware_next);
        return;
    }

    // Call the handler if all middleware have been executed
    handler(ctx);
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