#include "router.h"

static Route routeTable[MAX_ROUTES];
static int numRoutes = 0;

// Helper function to register a route
void registerRoute(HttpMethod method, const char* pattern, void (*handler)(Context*)) {
  // static regex_t regex;
  // if (regcomp(&regex, pattern, REG_EXTENDED) != 0) {
  //   fprintf(stderr, "Error compiling regex for route: %s\n", pattern);
  //   exit(1);
  // }

  if (numRoutes == MAX_ROUTES) {
    fprintf(stderr, "Number of routes %d exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
    exit(1);
  }

  routeTable[numRoutes].method  = method;
  routeTable[numRoutes].pattern = pattern;
  routeTable[numRoutes].handler = handler;
  numRoutes++;
}

void OPTIONS_ROUTE(const char* pattern, void (*handler)(Context*)) {
  registerRoute(M_OPTIONS, pattern, handler);
}

void GET_ROUTE(const char* pattern, void (*handler)(Context*)) {
  registerRoute(M_GET, pattern, handler);
}

void POST_ROUTE(const char* pattern, void (*handler)(Context*)) {
  registerRoute(M_POST, pattern, handler);
}

void PUT_ROUTE(const char* pattern, void (*handler)(Context*)) {
  registerRoute(M_PUT, pattern, handler);
}

void PATCH_ROUTE(const char* pattern, void (*handler)(Context*)) {
  registerRoute(M_PATCH, pattern, handler);
}

void DELETE_ROUTE(const char* pattern, void (*handler)(Context*)) {
  registerRoute(M_DELETE, pattern, handler);
}

Route* matchRoute(HttpMethod method, const char* path) {
  for (int i = 0; i < numRoutes; i++) {
    if (method == routeTable[i].method && strcmp(path, routeTable[i].pattern) == 0) {
      return &routeTable[i];
    }
  }
  return NULL;
}