#include "../include/params.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/**
 * match_path_parameters compares the pattern with the URL and extracts the parameters.
 * The pattern can contain parameters in the form of {name}.
 * 
 * @param pattern: The pattern to match
 * @param url_path: The URL path to match
 * @param pathParams: The PathParams struct to store the matched parameters
 * @return true if the pattern and URL match, false otherwise
 */
bool match_path_parameters(const char* pattern, const char* url_path, PathParams* pathParams) {
    const char* p           = pattern;
    const char* u           = url_path;
    size_t idx              = 0;
    pathParams->match_count = 0;

    // Fast path: exact match when no parameters
    if (!strchr(p, '{')) {
        while (*p && *u && *p == *u) {
            p++;
            u++;
        }
        // Skip trailing slashes
        while (*p == '/')
            p++;
        while (*u == '/')
            u++;
        return (*p == '\0' && *u == '\0');
    }

    while (*p && *u) {
        if (*p == '{') {
            // Bounds check
            if (idx >= MAX_PARAMS) return false;
            PathParam* param = &pathParams->params[idx++];

            // Extract parameter name
            p++;  // Skip '{'
            const char* name_start = p;
            while (*p && *p != '}')
                p++;
            if (*p != '}') return false;
            size_t name_len = p - name_start;
            if (name_len >= MAX_PARAM_NAME) return false;
            memcpy(param->name, name_start, name_len);
            param->name[name_len] = '\0';
            p++;  // Skip '}'

            // Extract parameter value
            const char* val_start = u;
            while (*u && *u != '/' && *u != *p)
                u++;
            size_t val_len = u - val_start;
            if (val_len >= MAX_PARAM_VALUE) return false;
            memcpy(param->value, val_start, val_len);
            param->value[val_len] = '\0';
        } else {
            if (*p != *u) return false;
            p++;
            u++;
        }
    }

    // Skip trailing slashes
    while (*p == '/')
        p++;
    while (*u == '/')
        u++;

    pathParams->match_count = idx;
    return (*p == '\0' && *u == '\0');
}

const char* get_path_param(const PathParams* pathParams, const char* name) {
    if (!pathParams || !name) {
        return nullptr;
    }

    for (size_t i = 0; i < pathParams->match_count; i++) {
        if (strcmp(pathParams->params[i].name, name) == 0) {
            return pathParams->params[i].value;
        }
    }
    return nullptr;
}
