#ifndef ROUTER_H
#define ROUTER_H

#include <regex.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "../str.h"
#include "method.h"

#include "context.h"

#ifndef MAX_ROUTES
#define MAX_ROUTES 100
#endif

typedef struct Route {
  HttpMethod method;
  const char* pattern;
  void (*handler)(Context* context);
} Route;

void registerRoute(HttpMethod method, const char* pattern, void (*handler)(Context*));
void GET_ROUTE(const char* pattern, void (*handler)(Context*));
void POST_ROUTE(const char* pattern, void (*handler)(Context*));
void PUT_ROUTE(const char* pattern, void (*handler)(Context*));
void PATCH_ROUTE(const char* pattern, void (*handler)(Context*));
void DELETE_ROUTE(const char* pattern, void (*handler)(Context*));
void OPTIONS_ROUTE(const char* pattern, void (*handler)(Context*));

// Function to match routes.
Route* matchRoute(HttpMethod method, const char* path);

#endif /* ROUTER_H */
