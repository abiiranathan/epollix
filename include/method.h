#ifndef METHOD_H
#define METHOD_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    M_INVALID = -1,
    M_OPTIONS,
    M_HEAD,
    M_GET,
    M_POST,
    M_PUT,
    M_PATCH,
    M_DELETE,
} HttpMethod;

const char* method_tostring(HttpMethod method);
HttpMethod method_fromstring(const char* method);
bool is_safe_method(HttpMethod method);

#ifdef __cplusplus
}
#endif

#endif /* METHOD_H */
