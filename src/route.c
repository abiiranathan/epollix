#include "../include/route.h"
#include "../include/static.h"
#include "constants.h"
#include "logging.h"

#include <linux/limits.h>
#include <solidc/filepath.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static Route routeTable[MAX_ROUTES] = {};
static size_t numRoutes             = 0;
static LArena* arena                = NULL;

__attribute__((constructor())) void init(void) {
    arena = larena_create(ROUTE_ARENA_MEM);
    LOG_ASSERT(arena, "arena is NULL");
}

__attribute__((destructor())) void cleanup(void) {
    if (arena) {
        larena_destroy(arena);
    }

    for (size_t i = 0; i < numRoutes; ++i) {
        if (routeTable[i].mw_data) {
            free(routeTable[i].mw_data);
        }
    }
}

const char* get_route_pattern(Route* route) {
    return route->pattern.data;
}

Route* default_route_matcher(HttpMethod method, const char* path) {
    bool matches = false;
    for (size_t i = 0; i < numRoutes; i++) {
        if (method != routeTable[i].method) {
            continue;
        }

        if (routeTable[i].type == NormalRoute) {
            matches = match_path_parameters(routeTable[i].pattern.data, path, routeTable[i].params);
            if (matches) {
                return &routeTable[i];
            }
        } else {
            // For static routes, we match only the prefix as an exact match.
            if (strncmp(routeTable[i].pattern.data, path, routeTable[i].pattern.length) == 0) {
                return &routeTable[i];
            }
        }
    }
    return nullptr;
}

// Helper function to register a new route
static Route* registerRoute(HttpMethod method, const char* pattern, Handler handler, RouteType type) {
    if (numRoutes >= (size_t)MAX_ROUTES) {
        LOG_FATAL("Number of routes %ld exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
    }

    printf("/%s %s\n", method_tostring(method), pattern);

    Route* route               = &routeTable[numRoutes];
    route->method              = method;
    route->handler             = handler;
    route->type                = type;
    route->mw_data             = nullptr;
    route->middleware_count    = 0;
    route->middleware_capacity = 1;
    route->middleware          = larena_alloc(arena, sizeof(Middleware) * route->middleware_capacity);

    char* pat = larena_alloc_string(arena, pattern);
    LOG_ASSERT(pat, "unable to allocate pattern");

    route->pattern = (str_view){.data = pat, .length = strlen(pat)};
    route->params  = (PathParams*)larena_alloc(arena, sizeof(PathParams));

    LOG_ASSERT(route->params, "unable to allocate params");
    LOG_ASSERT(route->middleware, "unable to allocate middleware");

    route->params->match_count = 0;
    memset(route->params->params, 0, sizeof(route->params->params));

    if ((strstr("{", pattern) && !strstr("}", pattern)) || (strstr("}", pattern) && !strstr("{", pattern))) {
        LOG_FATAL("Invalid path parameter in pattern: %s\n", pattern);
    }

    numRoutes++;
    return route;
}

Route* route_options(const char* pattern, Handler handler) {
    return registerRoute(M_OPTIONS, pattern, handler, NormalRoute);
}

Route* route_get(const char* pattern, Handler handler) {
    return registerRoute(M_GET, pattern, handler, NormalRoute);
}

Route* route_post(const char* pattern, Handler handler) {
    return registerRoute(M_POST, pattern, handler, NormalRoute);
}

Route* route_put(const char* pattern, Handler handler) {
    return registerRoute(M_PUT, pattern, handler, NormalRoute);
}

Route* route_patch(const char* pattern, Handler handler) {
    return registerRoute(M_PATCH, pattern, handler, NormalRoute);
}

Route* route_delete(const char* pattern, Handler handler) {
    return registerRoute(M_DELETE, pattern, handler, NormalRoute);
}

Route* route_static(const char* pattern, const char* dir) {
    LOG_ASSERT(MAX_DIRNAME > strlen(dir) + 1, "dir name too long");

    char* dirname = larena_alloc_string(arena, dir);
    LOG_ASSERT(dirname, "strdup failed");

    if (strstr(dirname, "~")) {
        char buf[PATH_MAX];
        if (!filepath_expanduser_buf(dir, buf, sizeof buf)) {
            LOG_ASSERT(dirname, "filepath_expanduser failed");
        };

        dirname = larena_alloc_string(arena, buf);
        LOG_ASSERT(dirname, "strdup failed");
    }

    // Check that dirname exists
    if (access(dirname, F_OK) == -1) {
        LOG_FATAL("STATIC_DIR: Directory \"%s\"does not exist", dirname);
    }

    size_t dirlen = strlen(dirname);
    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = (Route*)registerRoute(M_GET, pattern, (Handler)staticFileHandler, StaticRoute);
    LOG_ASSERT(route, "registerRoute failed");

    route->type    = StaticRoute;
    route->dirname = (str_view){.data = dirname, .length = strlen(dirname)};
    return route;
}

static Route* registerGroupRoute(RouteGroup* group, HttpMethod method, const char* pattern, Handler handler,
                                 RouteType type) {

    size_t pattern_len  = strlen(pattern);
    char* route_pattern = (char*)malloc(group->prefix.length + pattern_len + 1);
    LOG_ASSERT(route_pattern, "Failed to allocate memory for route pattern\n");
    snprintf(route_pattern, group->prefix.length + pattern_len + 1, "%s%s", group->prefix.data, pattern);

    if (group->count == group->capacity) {
        size_t capacity    = group->count * 2;
        Route** new_routes = (Route**)larena_alloc(arena, sizeof(Route*) * capacity);
        LOG_ASSERT(new_routes, "Failed to allocate memory for group routes");

        group->capacity = capacity;
        memcpy(new_routes, group->routes, sizeof(Route*) * group->count);
        group->routes = new_routes;
    }

    // This is allocated in static memory. Freed when the server exits.
    // Should not be freed in route_group_free.
    Route* route                  = (Route*)registerRoute(method, route_pattern, handler, type);
    group->routes[group->count++] = route;
    free(route_pattern);
    return route;
}

// Register an OPTIONS route.
Route* route_group_options(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_OPTIONS, pattern, handler, NormalRoute);
}

// Register a GET route.
Route* route_group_get(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_GET, pattern, handler, NormalRoute);
}

// Register a POST route.
Route* route_group_post(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_POST, pattern, handler, NormalRoute);
}

// Register a PUT route.
Route* route_group_put(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_PUT, pattern, handler, NormalRoute);
}

// Register a PATCH route.
Route* route_group_patch(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_PATCH, pattern, handler, NormalRoute);
}

// Register a DELETE route.
Route* route_group_delete(RouteGroup* group, const char* pattern, Handler handler) {
    return registerGroupRoute(group, M_DELETE, pattern, handler, NormalRoute);
}

// Serve static directory at dirname.
// e.g   STATIC_GROUP_DIR(group, "/web", "/var/www/html");
Route* route_group_static(RouteGroup* group, const char* pattern, char* dirname) {
    LOG_ASSERT(MAX_DIRNAME > strlen(dirname) + 1, "dirname is too long");

    char* fullpath = larena_alloc_string(arena, dirname);
    LOG_ASSERT(fullpath != nullptr, "larena_alloc_string failed");

    if (strstr(fullpath, "~")) {
        char buf[PATH_MAX];
        if (!filepath_expanduser_buf(fullpath, buf, sizeof buf)) {
            LOG_ASSERT(dirname, "filepath_expanduser failed");
        };

        fullpath = larena_alloc_string(arena, buf);
        LOG_ASSERT(fullpath, "larena_alloc_string failed");
    }

    // Check that dirname exists
    if (access(fullpath, F_OK) == -1) {
        LOG_FATAL("STATIC_GROUP_DIR: Directory \"%s\"does not exist", fullpath);
    }

    size_t dirlen = strlen(fullpath);

    // Remove trailing slash
    if (fullpath[dirlen - 1] == '/') {
        fullpath[dirlen - 1] = '\0';
    }

    Route* route = (Route*)registerGroupRoute(group, M_GET, pattern, (Handler)staticFileHandler, StaticRoute);
    LOG_ASSERT(route != nullptr, "registerGroupRoute failed");
    route->type    = StaticRoute;
    route->dirname = (str_view){.data = fullpath, .length = strlen(fullpath)};
    return route;
}

void* route_middleware_context(context_t* ctx) {
    return ctx->request->route->mw_data;
}

// Create a new RouteGroup.
RouteGroup* route_group(const char* pattern) {
    RouteGroup* group = (RouteGroup*)larena_alloc(arena, sizeof(RouteGroup));
    LOG_ASSERT(group, "Failed to allocate memory for RouteGroup\n");

    char* prefix = larena_alloc_string(arena, pattern);
    LOG_ASSERT(prefix, "Failed to allocate memory for RouteGroup prefix");
    group->prefix = (str_view){.data = prefix, .length = strlen(prefix)};

    group->middleware_count    = 0;
    group->middleware_capacity = 2;
    group->middleware          = larena_alloc(arena, sizeof(Middleware) * group->middleware_capacity);

    group->count    = 0;
    group->capacity = 8;
    group->routes   = larena_alloc(arena, sizeof(Route*) * group->capacity);

    LOG_ASSERT(group->routes, "Failed to allocate memory for RouteGroup routes\n");
    LOG_ASSERT(group->middleware, "Failed to allocate memory for RouteGroup middleware\n");

    return group;
}
