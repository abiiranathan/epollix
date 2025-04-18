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

typedef enum RouteType { NormalRoute, StaticRoute } RouteType;

#ifdef __cplusplus
}
#endif

#endif /* TYPES_H */
