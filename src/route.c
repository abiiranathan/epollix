#include "../include/route.h"
#include "../include/static.h"

#include <solidc/filepath.h>

// =================== STATIC GLOBALS ================================================
static Route routeTable[MAX_ROUTES] = {};
static size_t numRoutes = 0;

const char* get_route_pattern(Route* route) {
    return route->pattern;
}

// Default route matcher.
Route* default_route_matcher(HttpMethod method, const char* path) {
    bool matches = false;

    for (size_t i = 0; i < numRoutes; i++) {
        if (method != routeTable[i].method) {
            continue;
        }

        if (routeTable[i].type == NormalRoute) {
            matches = match_path_parameters(routeTable[i].pattern, path, routeTable[i].params);
            if (matches) {
                return &routeTable[i];
            }
        } else {
            // For static routes, we match only the prefix as an exact match.
            if (strncmp(routeTable[i].pattern, path, strlen(routeTable[i].pattern)) == 0) {
                return &routeTable[i];
            }
        }
    }
    return NULL;
}

// ================== Main program ===========================

// ============ Registering routes ==========================
// Helper function to register a new route
static Route* registerRoute(HttpMethod method, const char* pattern, Handler handler, RouteType type) {
    if (numRoutes >= (size_t)MAX_ROUTES) {
        LOG_FATAL("Number of routes %ld exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
    }

    Route* route = &routeTable[numRoutes];
    route->method = method;
    route->handler = handler;
    route->type = type;
    route->mw_data = NULL;
    route->middleware_count = 0;
    route->middleware = NULL;

    route->pattern = strdup(pattern);
    route->params = (PathParams*)malloc(sizeof(PathParams));
    LOG_ASSERT(route->pattern, "strdup failed");
    LOG_ASSERT(route->params, "malloc failed");

    route->params->match_count = 0;
    memset(route->params->params, 0, sizeof(route->params->params));

    if ((strstr("{", pattern) && !strstr("}", pattern)) || (strstr("}", pattern) && !strstr("{", pattern))) {
        LOG_FATAL("Invalid path parameter in pattern: %s\n", pattern);
    }

    numRoutes++;
    return route;
}

void routes_cleanup(void) {
    for (size_t i = 0; i < numRoutes; i++) {
        Route route = routeTable[i];
        free(route.pattern);

        if (route.params) {
            free(route.params);
        }

        // Free the middleware data if it exists
        if (route.mw_data) {
            free(route.mw_data);
        }

        // Free the middleware array
        if (route.middleware) {
            free(route.middleware);
        }

        // Free the dirname for static routes
        if (route.dirname) {
            free(route.dirname);
        }
    }
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

    char* dirname = strdup(dir);
    LOG_ASSERT(dirname, "strdup failed");

    if (strstr(dirname, "~")) {
        free(dirname);
        dirname = filepath_expanduser(dir);
        LOG_ASSERT(dirname, "filepath_expanduser failed");
    }

    // Check that dirname exists
    if (access(dirname, F_OK) == -1) {
        LOG_ERROR("STATIC_DIR: Directory \"%s\"does not exist", dirname);
        free(dirname);
        exit(EXIT_FAILURE);
    }

    size_t dirlen = strlen(dirname);
    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = registerRoute(M_GET, pattern, (Handler)staticFileHandler, StaticRoute);
    LOG_ASSERT(route, "registerRoute failed");

    route->type = StaticRoute;
    route->dirname = dirname;
    return route;
}

static Route* registerGroupRoute(RouteGroup* group, HttpMethod method, const char* pattern, Handler handler,
                                 RouteType type) {
    char* route_pattern = (char*)malloc(strlen(group->prefix) + strlen(pattern) + 1);
    if (!route_pattern) {
        LOG_FATAL("Failed to allocate memory for route pattern\n");
    }

    int ret = snprintf(route_pattern, strlen(group->prefix) + strlen(pattern) + 1, "%s%s", group->prefix, pattern);
    if (ret < 0 || ret >= (int)(strlen(group->prefix) + strlen(pattern) + 1)) {
        LOG_FATAL("Failed to concatenate route pattern\n");
    }

    // realloc the routes array, may be null if this is the first route
    Route** new_routes = (Route**)realloc(group->routes, sizeof(Route*) * (group->count + 1));
    if (!new_routes) {
        LOG_FATAL("Failed to allocate memory for group routes\n");
    }

    // Update the routes array
    group->routes = new_routes;

    // This is allocated in static memory. Freed when the server exits.
    // Should not be freed in route_group_free.
    Route* route = registerRoute(method, route_pattern, handler, type);
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

    char* fullpath = strdup(dirname);
    LOG_ASSERT(fullpath != NULL, "strdup failed");

    if (strstr(fullpath, "~")) {
        free(fullpath);
        fullpath = filepath_expanduser(dirname);
        LOG_ASSERT(fullpath != NULL, "filepath_expanduser failed");
    }

    // Check that dirname exists
    if (access(fullpath, F_OK) == -1) {
        LOG_ERROR("STATIC_GROUP_DIR: Directory \"%s\"does not exist", fullpath);
        free(fullpath);
        exit(EXIT_FAILURE);
    }

    size_t dirlen = strlen(fullpath);
    if (fullpath[dirlen - 1] == '/') {
        fullpath[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = registerGroupRoute(group, M_GET, pattern, (Handler)staticFileHandler, StaticRoute);
    LOG_ASSERT(route != NULL, "registerGroupRoute failed");

    route->type = StaticRoute;
    route->dirname = fullpath;
    return route;
}

void* get_route_middleware_context(context_t* ctx) {
    return ctx->request->route->mw_data;
}