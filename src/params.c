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
    const char* pat         = pattern;
    const char* url         = url_path;
    size_t nparams          = 0;
    pathParams->match_count = 0;

    // Fast path: exact match when no parameters
    if (!strchr(pat, '{')) {
        while (*pat && *url && *pat == *url) {
            pat++;
            url++;
        }
        // Skip trailing slashes
        while (*pat == '/')
            pat++;
        while (*url == '/')
            url++;
        return (*pat == '\0' && *url == '\0');
    }

    while (*pat && *url) {
        if (*pat == '{') {
            // Bounds check
            if (nparams >= MAX_PARAMS) return false;
            PathParam* param = &pathParams->params[nparams++];

            // Extract parameter name
            pat++;  // Skip '{'
            const char* name_start = pat;
            while (*pat && *pat != '}')
                pat++;
            if (*pat != '}') return false;
            size_t name_len = pat - name_start;
            if (name_len >= MAX_PARAM_NAME) return false;
            memcpy(param->name, name_start, name_len);
            param->name[name_len] = '\0';
            pat++;  // Skip '}'

            // Extract parameter value
            const char* val_start = url;
            while (*url && *url != '/' && *url != *pat)
                url++;
            size_t val_len = url - val_start;
            if (val_len >= MAX_PARAM_VALUE) return false;
            memcpy(param->value, val_start, val_len);
            param->value[val_len] = '\0';
        } else {
            if (*pat != *url) return false;
            pat++;
            url++;
        }
    }

    // Skip trailing slashes
    while (*pat == '/')
        pat++;
    while (*url == '/')
        url++;

    pathParams->match_count = nparams;
    return (*pat == '\0' && *url == '\0');
}

const char* get_path_param(const PathParams* pathParams, const char* name) {
    if (!pathParams || !name) {
        return NULL;
    }

    for (size_t i = 0; i < pathParams->match_count; i++) {
        if (strcmp(pathParams->params[i].name, name) == 0) {
            return pathParams->params[i].value;
        }
    }
    return NULL;
}
