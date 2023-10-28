#ifndef METHOD_H
#define METHOD_H
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef enum {
  M_INVALID = -1,
  M_OPTIONS,
  M_GET,
  M_POST,
  M_PUT,
  M_PATCH,
  M_DELETE,
} HttpMethod;

__attribute__((always_inline)) inline const char* method_tostring(HttpMethod method) {
  switch (method) {
    case M_OPTIONS:
      return "OPTIONS";
    case M_GET:
      return "GET";
    case M_POST:
      return "POST";
    case M_PUT:
      return "PUT";
    case M_PATCH:
      return "PATCH";
    case M_DELETE:
      return "DELETE";
    case M_INVALID:
    default:
      fprintf(stderr, "Unsupported Http method\n");
      return NULL;
  }
}

__attribute__((always_inline)) inline HttpMethod method_fromstring(const char* method) {
  if (strcmp(method, "OPTIONS") == 0) {
    return M_OPTIONS;
  } else if (strcmp(method, "GET") == 0) {
    return M_GET;
  } else if (strcmp(method, "POST") == 0) {
    return M_POST;
  } else if (strcmp(method, "PUT") == 0) {
    return M_PUT;
  } else if (strcmp(method, "PATCH") == 0) {
    return M_PATCH;
  } else if (strcmp(method, "DELETE") == 0) {
    return M_DELETE;
  } else {
    fprintf(stderr, "Unsupported http method: %s\n", method);
    return M_INVALID;
  }
}

__attribute__((always_inline)) inline bool is_safe_method(HttpMethod method) {
  switch (method) {
    case M_OPTIONS:
    case M_GET:
      return true;
    default:
      return false;
  }
}

#endif /* METHOD_H */
