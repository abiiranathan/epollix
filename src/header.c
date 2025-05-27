#include "../include/header.h"
#include "../include/constants.h"
#include <solidc/cstr.h>
#include <solidc/array.h>

#define LARGE_HEADER_FLAG 0x80000000

typedef struct {
    cstr* name;   // Header name
    cstr* value;  // Header value
} header_t;

ARRAY_DEFINE(Headers, header_t)

Headers* headers_new(size_t initial_capacity) {
    // Create headers with default capacity.
    Headers* headers = Headers_new();
    if (!headers) {
        return NULL;
    }

    if (headers->capacity < initial_capacity) {
        Headers_resize(headers, initial_capacity);
    }

    return headers;
}

const char* headers_value(const Headers* headers, const char* name) {
    if (!name) return NULL;

    for (size_t i = 0; i < headers->count; ++i) {
        const char* h_name = cstr_data_const(headers->items[i].name);
        if (!h_name) {
            continue;
        }
        if (strcasecmp(name, h_name) == 0) {
            return cstr_data_const(headers->items[i].value);
        }
    }
    return NULL;
}

bool headers_append(Headers* headers, const char* name, const char* value) {
    header_t hdr = {
        .name  = cstr_new(name),
        .value = cstr_new(value),
    };

    if (hdr.name && hdr.value) {
        Headers_append(headers, hdr);
        return true;
    }
    return false;
}

bool headers_tostring(const Headers* headers, char* buffer, size_t size) {
    if (!headers || !buffer || size < 3) return false;

    char* ptr        = buffer;
    size_t remaining = size;

    for (size_t i = 0; i < headers->count; i++) {
        const header_t* h = &headers->items[i];

        const char* name  = cstr_data_const(h->name);
        const char* value = cstr_data_const(h->value);

        int written = snprintf(ptr, remaining, "%s: %s\r\n", name, value);
        if (written < 0 || (size_t)written >= remaining) {
            return false;
        }

        ptr += written;
        remaining -= written;
    }

    if (remaining < 3) return false;
    memcpy(ptr, "\r\n", 3);  // Includes null terminator
    return true;
}

void headers_free(Headers* headers) {
    if (!headers) return;

    for (size_t i = 0; i < headers->count; i++) {
        cstr_free(headers->items[i].name);
        cstr_free(headers->items[i].value);
    }
    Headers_free(headers);
}
