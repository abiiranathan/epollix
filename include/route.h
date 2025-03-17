#ifndef BA75E25E_A90C_4152_B4D7_55525BB1A33E
#define BA75E25E_A90C_4152_B4D7_55525BB1A33E

#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include "params.h"
#include "types.h"

// context_t formward declaration
struct epollix_context;
typedef void (*Middleware)(struct epollix_context* ctx, void (*next)(struct epollix_context* ctx));
typedef void (*Handler)(struct epollix_context* ctx);

// Route is a struct that contains the route pattern, handler, and middleware.
typedef struct Route {
    HttpMethod method;           // HTTP Method.
    RouteType type;              // Type of Route (Normal or Static)
    char* pattern;               // Pattern to match
    Handler handler;             // Handler for the route
    PathParams* params;          // Parameters extracted from the URL
    char* dirname;               // Dirname for static route(dynamic memory)
    Middleware* middleware;      // Array of middleware functions(allocated dynamically)
    size_t middleware_count;     // Number of middleware functions
    size_t middleware_capacity;  // Capacity of middleware
    void* mw_data;               // Middleware data. This is set by the user.
} Route;

// Route group is a collection of routes that share the same prefix.
typedef struct RouteGroup {
    char* prefix;                // Prefix for the group
    Route** routes;              // Array of routes(dynamic memory)
    size_t count;                // Number of routes in the group
    size_t capacity;             // capacity of routes in the group
    Middleware* middleware;      // Middleware for the group
    size_t middleware_count;     // Number of middleware functions
    size_t middleware_capacity;  // Capacity of middleware functions
} RouteGroup;

// ==================== REGISTER ROUTES ON CTX ===================================

// Register an OPTIONS route.
Route* route_options(const char* pattern, Handler handler);

// Register a GET route.
Route* route_get(const char* pattern, Handler handler);

// Register a POST route.
Route* route_post(const char* pattern, Handler handler);

// Register a PUT route.
Route* route_put(const char* pattern, Handler handler);

// Register a PATCH route.
Route* route_patch(const char* pattern, Handler handler);

// Register a DELETE route.
Route* route_delete(const char* pattern, Handler handler);

// Serve static directory at dirname.
// e.g   route_static("/web", "/var/www/html");
Route* route_static(const char* pattern, const char* dirname);

// Retruns the context data passed that was passed to this route and its middleware.
void* route_middleware_context(struct epollix_context* ctx);

// =========== REGISTER ROUTES ON Group ========================

// Create a new RouteGroup.
// A RouteGroup is a collection of routes that share the same prefix.
RouteGroup* route_group(const char* pattern);

// Register an OPTIONS route.
Route* route_group_options(RouteGroup* group, const char* pattern, Handler handler);

// Register a GET route.
Route* route_group_get(RouteGroup* group, const char* pattern, Handler handler);

// Register a POST route.
Route* route_group_post(RouteGroup* group, const char* pattern, Handler handler);

// Register a PUT route.
Route* route_group_put(RouteGroup* group, const char* pattern, Handler handler);

// Register a PATCH route.
Route* route_group_patch(RouteGroup* group, const char* pattern, Handler handler);

// Register a DELETE route.
Route* route_group_delete(RouteGroup* group, const char* pattern, Handler handler);

// Serve static directory at dirname.
// e.g   STATIC_GROUP_DIR(group, "/web", "/var/www/html");
Route* route_group_static(RouteGroup* group, const char* pattern, char* dirname);

// Default route matcher.
Route* default_route_matcher(HttpMethod method, const char* path);

#ifdef __cplusplus
}
#endif

#endif /* BA75E25E_A90C_4152_B4D7_55525BB1A33E */
