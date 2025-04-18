#include "../include/middleware.h"
#include "../include/net.h"
#include "constants.h"
#include "logging.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

static Middleware GLOBAL_MIDDLEWARE[MAX_GLOBAL_MIDDLEWARE] = {};       // Global middleware
static size_t global_middleware_count                      = 0;        // Number of global middleware
static map* global_middleware_context                      = nullptr;  // Global middleware context
static LArena* arena                                       = NULL;

#define MIDDLEWARE_ARENA_MEM (size_t)((MAX_GLOBAL_MIDDLEWARE + MAX_GROUP_MIDDLEWARE) * sizeof(Middleware) * 1.2)

__attribute__((constructor())) void middleware_init(void) {
    // Initialize global middleware context
    global_middleware_context = map_create(4, key_compare_char_ptr, true);
    LOG_ASSERT(global_middleware_context, "Failed to create global_middleware_context\n");

    // Initialize middleware memory pool
    arena = larena_create(MIDDLEWARE_ARENA_MEM);
    LOG_ASSERT(arena, "pool is NULL");
}

__attribute__((destructor())) void middleware_cleanup(void) {
    if (global_middleware_context) {
        map_destroy(global_middleware_context);
    }

    if (arena) {
        larena_destroy(arena);
    }
}

// Set route middleware context or userdata.
// This user data is free automatically for you at exit.
void set_middleware_context(Route* route, void* userdata) {
    route->mw_data = userdata;
}

// Set route middleware context or userdata.
void set_global_mw_context(const char* key, void* userdata) {
    // The key has the same life time as the map.
    char* ctx_key = strdup(key);
    if (!ctx_key) {
        LOG_ERROR("unable to allocate memory for key: %s", key);
        return;
    }
    map_set(global_middleware_context, ctx_key, userdata);
}

void* get_global_middleware_context(const char* key) {
    return map_get(global_middleware_context, (char*)key);
}

// get_global_middleware_count returns the number of global middleware functions.
size_t get_global_middleware_count(void) {
    return global_middleware_count;
}

// get_global_middleware returns the global middleware functions.
Middleware* get_global_middleware(void) {
    return GLOBAL_MIDDLEWARE;
}

static void middleware_next(context_t* ctx) {
    if (ctx->abort) return;

    switch (ctx->mw_ctx->ctx_type) {
        case MwGlobal: {
            MiddlewareContext* mw_ctx = ctx->mw_ctx;
            mw_ctx->ctx.Global.g_index++;
            execute_middleware_chain(ctx, mw_ctx);
        } break;
        case MwLocal: {
            MiddlewareContext* mw_ctx = ctx->mw_ctx;
            mw_ctx->ctx.Local.r_index++;
            execute_middleware_chain(ctx, mw_ctx);
        } break;
    }
}

// Advance middleware group without calling the handler.
void execute_middleware_chain(context_t* ctx, MiddlewareContext* mw_ctx) {
    if (ctx->abort) return;

    switch (ctx->mw_ctx->ctx_type) {
        case MwGlobal: {
            if (mw_ctx->ctx.Global.g_index < mw_ctx->ctx.Global.g_count) {
                // Execute the next global middleware in the chain
                mw_ctx->ctx.Global.g_middleware[mw_ctx->ctx.Global.g_index](ctx, middleware_next);
                return;
            }
        } break;
        case MwLocal: {
            if (mw_ctx->ctx.Local.r_index < mw_ctx->ctx.Local.r_count) {
                // Execute the next local middleware in the chain
                mw_ctx->ctx.Local.r_middleware[mw_ctx->ctx.Local.r_index](ctx, middleware_next);
                return;
            }
        }
    }
}

// ================ Middleware logic ==================
void use_global_middleware(size_t count, ...) {
    if (global_middleware_count + count > MAX_GLOBAL_MIDDLEWARE) {
        LOG_FATAL("Exceeded maximum global middleware count: %d. Recompile with a bigger -DMAX_GLOBAL_MIDDLEWARE \n",
                  MAX_GLOBAL_MIDDLEWARE);
    }

    va_list args;
    va_start(args, count);
    for (size_t i = 0; i < count && global_middleware_count < MAX_GLOBAL_MIDDLEWARE; i++) {
        GLOBAL_MIDDLEWARE[global_middleware_count++] = va_arg(args, Middleware);
    }

    va_end(args);
}

// Register middleware for a route
void use_route_middleware(Route* route, size_t count, ...) {
    if (count <= 0) {
        return;
    }

    size_t new_count = route->middleware_count + count;
    if (new_count <= route->middleware_capacity) {
        size_t capacity = new_count * 2;

        Middleware* new_middleware = (Middleware*)larena_alloc(arena, sizeof(Middleware) * capacity);
        LOG_ASSERT(new_middleware, "Failed to allocate memory for route middleware\n");

        memcpy(new_middleware, route->middleware, sizeof(Middleware) * route->middleware_count);
        route->middleware_capacity = (uint8_t)capacity;
        route->middleware          = new_middleware;
    }

    va_list args;
    va_start(args, count);

    // Append the new middleware to the route middleware
    for (size_t i = route->middleware_count; i < new_count; i++) {
        route->middleware[i] = va_arg(args, Middleware);
    }

    route->middleware_count = new_count;
    va_end(args);
}

// Attach route group middleware.
void use_group_middleware(RouteGroup* group, size_t count, ...) {
    if (count <= 0) {
        return;
    }

    size_t new_count = group->middleware_count + count;
    if (new_count <= group->middleware_capacity) {
        size_t capacity            = new_count * 2;
        Middleware* new_middleware = (Middleware*)larena_alloc(arena, sizeof(Middleware) * capacity);
        LOG_ASSERT(new_middleware, "Failed to allocate memory for group middleware\n");
        memcpy(new_middleware, group->middleware, sizeof(Middleware) * group->middleware_count);
        group->middleware_capacity = capacity;
        group->middleware          = new_middleware;
    }

    va_list args;
    va_start(args, count);
    for (size_t i = group->middleware_count; i < new_count; i++) {
        group->middleware[i] = va_arg(args, Middleware);
    }

    group->middleware_count = new_count;
    va_end(args);
}
