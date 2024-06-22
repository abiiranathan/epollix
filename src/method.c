#include "../include/method.h"
#include "../include/logging.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* method_mapping[7] = {
    [M_OPTIONS] = "OPTIONS", [M_HEAD] = "HEAD",  [M_GET] = "GET",       [M_POST] = "POST",
    [M_PUT] = "PUT",         [M_PATCH] = "PATH", [M_DELETE] = "DELETE",
};

const char* method_tostring(HttpMethod method) {
    if (method < M_OPTIONS || method > M_DELETE) {
        return NULL;
    }
    return method_mapping[method];
}

HttpMethod method_fromstring(const char* method) {
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
        LOG_ERROR("Unsupported http method: %s\n", method);
        return M_INVALID;
    }
}

bool is_safe_method(HttpMethod method) {
    switch (method) {
        case M_GET:
        case M_OPTIONS:
        case M_HEAD:
            return true;
        default:
            return false;
    }
}