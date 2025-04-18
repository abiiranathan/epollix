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
    // Initialize parameters for efficiency
    char* pattern_ptr       = (char*)pattern;
    char* url_ptr           = (char*)url_path;
    size_t idx              = 0;
    pathParams->match_count = 0;

    // Fast path: if no parameters in pattern, do a simple comparison
    if (!strchr(pattern, '{')) {
        size_t lpattern = strlen(pattern_ptr);
        size_t lurl     = strlen(url_ptr);

        // Handle trailing slashes for both strings
        if (lpattern > 1 && pattern_ptr[lpattern - 1] == '/') lpattern--;
        if (lurl > 1 && url_ptr[lurl - 1] == '/') lurl--;

        return (lpattern == lurl && memcmp(pattern_ptr, url_ptr, lpattern) == 0);
    }

    // Main matching loop with minimized branches
    while (*pattern_ptr && *url_ptr) {
        if (*pattern_ptr == '{') {
            // Check parameter array bounds early
            if (idx >= MAX_PARAMS) {
                return false;
            }

            // Skip the opening brace
            pattern_ptr++;

            // Find closing brace
            char* brace_end = strchr(pattern_ptr, '}');
            if (!brace_end) return false;

            // Get parameter name length
            size_t param_name_len = brace_end - pattern_ptr;
            if (param_name_len >= MAX_PARAM_NAME) return false;

            // Set up parameter reference (avoid struct access in tight loop)
            PathParam* param = &pathParams->params[idx];

            // Copy parameter name (single operation instead of loop)
            memcpy(param->name, pattern_ptr, param_name_len);
            param->name[param_name_len] = '\0';

            // Move pattern pointer past closing brace
            pattern_ptr = brace_end + 1;

            // Record start of parameter value
            char* value_start = url_ptr;

            // Find value end (next slash or end of string)
            while (*url_ptr && *url_ptr != '/') {
                url_ptr++;
            }

            // Check parameter value size
            size_t value_len = url_ptr - value_start;
            if (value_len >= MAX_PARAM_VALUE) return false;

            // Copy parameter value
            memcpy(param->value, value_start, value_len);
            param->value[value_len] = '\0';

            // Increment parameter count (only once per match, not in tight loop)
            idx++;
        } else {
            // Direct comparison of static parts
            if (*pattern_ptr != *url_ptr) return false;
            pattern_ptr++;
            url_ptr++;
        }
    }

    // Handle trailing slashes efficiently
    while (*pattern_ptr == '/')
        pattern_ptr++;
    while (*url_ptr == '/')
        url_ptr++;

    // Update match count at the end (just once)
    pathParams->match_count = idx;

    // Check if both strings are fully consumed
    return (*pattern_ptr == '\0' && *url_ptr == '\0');
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
