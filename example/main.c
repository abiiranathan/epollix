#include <errno.h>
#include "../include/epollix.h"

#define NUM_THREADS  4
#define DEFAULT_PORT 3000
#define USE_LOGGER   0

// Routes, defined in ./routes.c
extern void open_movie(void);
extern void index_page(context_t* ctx);
extern void serve_movie(context_t* ctx);
extern void handle_greet(context_t* ctx);
extern void gzip_route(context_t* ctx);

extern void render_register_form(context_t* ctx);
extern void handle_create_user(context_t* ctx);
extern void chunked_response(context_t* ctx);
extern void api_index(context_t* ctx);
extern void api_users(context_t* ctx);
extern void api_user_by_id(context_t* ctx);

static void user_route_mw(context_t* ctx, Handler next) {
    next(ctx);
    // Do whatever you want here...
}

static void defineRoutes() {
    BasicAuthUser *guest = NULL, *admin = NULL;

#if USE_LOGGER > 0
    // Logging middleware
    FILE* logfile = fopen("server.log", "a+");
    LOG_ASSERT(logfile, "Failed to open logfile");

    set_log_file(logfile);
    use_global_middleware(1, epollix_logger);
#endif

    guest = new_basic_auth_user("guest", "guest", "Protected");
    admin = new_basic_auth_user("admin", "admin", "ProtectedAdmin");

    LOG_ASSERT(guest != NULL, "Failed to allocate memory for BasicAuthData");
    LOG_ASSERT(admin != NULL, "Failed to allocate memory for BasicAuthData");

    set_global_mw_context(BASIC_AUTH_KEY, guest);
    // use_global_middleware(1, global_basic_auth);

    route_get("/", index_page);
    route_get("/movie", serve_movie);
    route_get("/greet/{name}", handle_greet);
    route_get("/gzip", gzip_route);

    // Route* pr = route_get("/protected", protected_route);

    // Expects a valid secret to be set in the JWT_TOKEN_SECRET environment variable
    // use_route_middleware(pr, 1, BearerAuthMiddleware);

    Route* reg = route_get("/users/register", render_register_form);
    set_middleware_context(reg, admin);
    use_route_middleware(reg, 1, route_basic_auth);

    route_post("/users/create", handle_create_user);
    route_get("/chunked", chunked_response);

    enable_directory_browsing(true);
    route_static("/static", "./");

    // Create a route group
    RouteGroup* group = route_group("/api/v1");

    route_group_get(group, "/", api_index);

    Route* userRoute = route_group_get(group, "/users", api_users);
    use_route_middleware(userRoute, 1, user_route_mw);

    route_group_get(group, "/users/{id}", api_user_by_id);

    use_group_middleware(group, 1, global_basic_auth);
}

uint16_t parse_port(const char* _port, bool* success) {
    errno = 0;  // Reset errno before conversion
    char* endptr;
    long port = strtol(_port, &endptr, 10);

    // Check if the entire string was consumed and is non-empty
    if (endptr == _port || *endptr != '\0') {
        LOG_ERROR("Invalid port: '%s' is not a number", _port);
        *success = false;
        return 0;
    }

    // Check for out-of-range or negative values
    if (port < 0 || port > UINT16_MAX) {
        LOG_ERROR("Port out of range: %ld (must be 0-65535)", port);
        *success = false;
        return 0;
    }

    // Check for conversion errors (e.g., overflow)
    if (errno == ERANGE) {
        LOG_ERROR("Port conversion error: %s", strerror(errno));
        *success = false;
        return 0;
    }

    *success = true;
    return (uint16_t)port;
}

int main(int argc, char** argv) {
    uint16_t port = DEFAULT_PORT;
    if (argc == 2) {
        bool ok;
        port = parse_port(argv[1], &ok);
        if (!ok) {
            LOG_FATAL("Invalid port");
        }
    }

    open_movie();

    // Set the JWT token for Bearer authentication
    setenv(JWT_TOKEN_SECRET, "super_jwt_token_secret", 1);

    defineRoutes();

    return epoll_server_run(port);
}
