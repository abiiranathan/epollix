#ifndef TYPES_H
#define TYPES_H

#include <solidc/larena.h>
#include <solidc/map.h>
#include <solidc/cstr.h>

#include <sys/types.h>

#include "constants.h"
#include "header.h"
#include "logging.h"
#include "method.h"
#include "mime.h"
#include "params.h"
#include "status.h"
#include "url.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
// GCC and clang support __builtin_expect
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
// For other compilers, just evaluate normally
#define likely(x)   (x)
#define unlikely(x) (x)
#endif

typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

#ifdef __cplusplus
}
#endif

#endif /* TYPES_H */
