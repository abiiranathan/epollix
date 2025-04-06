#ifndef D227A8DB_94E5_4627_A7A8_A35E2CA3AA04
#define D227A8DB_94E5_4627_A7A8_A35E2CA3AA04

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// Maximum length of a parameter name
#ifndef MAX_PARAM_NAME
#define MAX_PARAM_NAME 32
#endif

// Maximum length of a parameter value
#ifndef MAX_PARAM_VALUE
#define MAX_PARAM_VALUE 128
#endif

// Maximum number of parameters in a URL
#ifndef MAX_PARAMS
#define MAX_PARAMS 4
#endif

typedef struct {
    char name[MAX_PARAM_NAME];    // Parameter name
    char value[MAX_PARAM_VALUE];  // Parameter value from the URL
} PathParam;

typedef struct PathParams {
    PathParam params[MAX_PARAMS];  // Array of matched parameters
    size_t match_count;            // Number of matched parameters
} PathParams;

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
bool match_path_parameters(const char* pattern, const char* url_path, PathParams* pathParams);

const char* get_path_param(const PathParams* pathParams, const char* name);

#ifdef __cplusplus
}
#endif

#endif /* D227A8DB_94E5_4627_A7A8_A35E2CA3AA04 */
