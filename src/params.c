#include "../include/params.h"
#include "../include/logging.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

/*
* match_path_parameters compares the pattern with the URL and extracts the parameters.
* The pattern can contain parameters in the form of {name}. The function extracts the
* parameter name and value from the URL and stores them in the PathParams struct.
* Regex is not supported in this implementation.
* The function is lax and ignores the trailing slash in the pattern and URL.
* e.g /about/ and /about are considered equal.
* The maximum number of parameters is defined by MAX_PARAMS, maximum parameter name
* length is defined by MAX_PARAM_NAME, and maximum parameter value length is defined
* by MAX_PARAM_VALUE. The function returns true if the pattern and URL match, false otherwise.
* 
* Example:
* pattern: /about/{name}/profile/{id}/
* 
* url: /about/john/profile/123
* 
* 
* @param pattern: The pattern to match
* @param url_path: The URL path to match
* @param pathParams: The PathParams struct to store the matched parameters
* 
*/
bool match_path_parameters(const char* pattern, const char* url_path, PathParams* pathParams) {
    const char* pattern_ptr = pattern;
    const char* url_ptr = url_path;
    pathParams->match_count = 0;

    // Early return if there are no parameters in the pattern
    if (!strchr(pattern, '{')) {
        // Compare ignoring trailing slashes
        size_t lpattern = strlen(pattern_ptr);
        size_t lurl = strlen(url_ptr);

        // Skip trailing slash for the pattern
        if (lpattern > 1 && pattern_ptr[lpattern - 1] == '/') {
            lpattern--;
        }

        // Skip trailing slash for the URL
        if (lurl > 1 && url_ptr[lurl - 1] == '/') {
            lurl--;
        }
        return lpattern == lurl && strncmp(pattern_ptr, url_ptr, lpattern) == 0;
    }

    // Main matching logic with path parameters
    while (*pattern_ptr && *url_ptr) {
        if (*pattern_ptr == '{') {
            // Check for parameter space
            if (pathParams->match_count >= MAX_PARAMS) {
                LOG_ERROR("PathParams size exceeded");
                return false;
            }

            // Extract parameter name
            pattern_ptr++;
            const char* brace_end = strchr(pattern_ptr, '}');
            if (!brace_end)
                return false;

            size_t param_name_len = brace_end - pattern_ptr;
            if (param_name_len >= MAX_PARAM_NAME)
                return false;

            // Prepare parameter
            PathParam* param = &pathParams->params[pathParams->match_count];
            memcpy(param->name, pattern_ptr, param_name_len);
            param->name[param_name_len] = '\0';

            pattern_ptr = brace_end + 1;

            // Extract parameter value
            const char* value_start = url_ptr;
            while (*url_ptr && *url_ptr != '/')
                url_ptr++;

            size_t value_len = url_ptr - value_start;
            if (value_len >= MAX_PARAM_VALUE)
                return false;

            memcpy(param->value, value_start, value_len);
            param->value[value_len] = '\0';

            pathParams->match_count++;
        } else {
            // Static comparison
            if (*pattern_ptr != *url_ptr)
                return false;
            pattern_ptr++;
            url_ptr++;
        }
    }

    // Ignore trailing slashes in both pattern and URL
    while (*pattern_ptr == '/')
        pattern_ptr++;

    while (*url_ptr == '/')
        url_ptr++;

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
