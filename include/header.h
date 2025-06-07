#ifndef HEADERS_H
#define HEADERS_H

#include <stddef.h>
#include "kv.h"

// Dynamic Array of headers.
typedef struct kv Headers;

// Query params are also stored as headers. (key/value)
typedef struct kv QueryParams;

bool headers_append(Headers* headers, const char* name, const char* value);
const char* headers_value(const Headers* headers, const char* name);

void headers_free(Headers* headers);

#endif
