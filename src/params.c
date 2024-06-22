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
* By default the function is strict and requires the URL to match the pattern exactly.
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

    while (*pattern_ptr != '\0' && *url_ptr != '\0') {
        if (*pattern_ptr == '{') {
            // Check if we have space to store more parameters
            if (pathParams->match_count >= MAX_PARAMS) {
                LOG_ERROR("PathParams size exceeded\n");
                return false;
            }

            // Start of a parameter in the pattern
            pattern_ptr++;

            // Find the end of the parameter name
            const char* brace_end = strchr(pattern_ptr, '}');
            if (!brace_end) {
                return false;
            }

            // Copy the parameter name
            size_t param_name_len = brace_end - pattern_ptr;
            if (param_name_len >= MAX_PARAM_NAME) {
                return false;
            }

            PathParam param = {0};
            strncpy(param.name, pattern_ptr, param_name_len);
            param.name[param_name_len] = '\0';

            pattern_ptr = brace_end + 1;  // Move past the closing brace

            // Extract the parameter value from the URL
            const char* value_start = url_ptr;
            while (*url_ptr != '/' && *url_ptr != '\0') {
                url_ptr++;
            }

            size_t value_length = url_ptr - value_start;
            if (value_length >= MAX_PARAM_VALUE) {
                return false;
            }

            strncpy(param.value, value_start, value_length);
            param.value[value_length] = '\0';
            pathParams->params[pathParams->match_count++] = param;
        } else {
            // Static part of the pattern, should match exactly with the URL
            if (*pattern_ptr == *url_ptr) {
                pattern_ptr++;
                url_ptr++;
            } else {
                return false;
            }
        }
    }

    if (STRICT_SLASH) {
        // Check if we consumed the entire URL and pattern strictly
        if (*pattern_ptr != '\0' || *url_ptr != '\0') {
            return false;
        }

    } else {
        // Ignore trailing slashes in the pattern
        while (*pattern_ptr == '/')
            pattern_ptr++;

        // Ignore trailing slashes in the URL
        while (*url_ptr == '/')
            url_ptr++;

        // assert that we consumed the entire URL and pattern
        if (*pattern_ptr != '\0' || *url_ptr != '\0') {
            return false;
        }
    }

    // we consumed the entire URL and pattern
    return true;
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

// #define TEST_PARAMS
#ifdef TEST_PARAMS
int main() {
    const char* pattern = "/about/{name}/profile/{id}/";
    const char url[] = "/about/John Doe/profile/123/";

    PathParams pathParams = {0};
    bool matches = match_path_parameters(pattern, url, &pathParams);
    printf("Url Matches: %d\n", matches);
    printf("Matching Params: %ld\n", pathParams.match_count);

    // Print param values
    for (size_t i = 0; i < pathParams.match_count; i++) {
        printf("Param: %s, Value: %s\n", pathParams.params[i].name, pathParams.params[i].value);
    }

    // Get param by name
    const char* name = get_path_param(&pathParams, "name");
    const char* id = get_path_param(&pathParams, "id");

    printf("Name: %s, ID: %s\n", name, id);

    return 0;
}
#endif