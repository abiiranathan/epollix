#include "../include/header.h"
#include "../include/fast_str.h"

#include "../include/constants.h"
#include <solidc/cstr.h>
#include <solidc/array.h>

#define LARGE_HEADER_FLAG 0x80000000

typedef struct {
    char name[MAX_HEADER_NAME_LEN];  // Header name
    union {
        char small_value[SMALL_HEADER_VALUE_LEN];  // Small value buffer
        cstr* ptr;                                 // Heap-allocated large value
    };
    unsigned int flags;  // Stores LARGE_HEADER_FLAG if value is heap-allocated
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

static inline bool is_large_value(const header_t* h) {
    return h->flags & LARGE_HEADER_FLAG;
}

const char* headers_value(const Headers* headers, const char* name) {
    for (size_t i = 0; i < headers->count; ++i) {
        if (fast_strcasecmp(name, headers->items[i].name) == 0) {
            header_t* item = &headers->items[i];
            return is_large_value(item) ? str_data(item->ptr) : item->small_value;
        }
    }
    return NULL;
}

bool headers_append(Headers* headers, const char* name, const char* value) {
    size_t name_len  = strlen(name);
    size_t value_len = strlen(value);

    if (name_len >= MAX_HEADER_NAME_LEN) {
        printf("Header name: %s too long\n", name);
        return false;
    }

    header_t hdr = {0};

    // Copy name (safe because we checked length)
    memcpy(hdr.name, name, name_len);
    hdr.name[name_len] = '\0';
    hdr.flags          = 0;

    // Handle value
    if (value_len < SMALL_HEADER_VALUE_LEN) {
        memcpy(hdr.small_value, value, value_len);
        hdr.small_value[value_len] = '\0';
    } else {
        hdr.ptr = str_from(value);
        if (!hdr.ptr) {
            headers->count--;  // Rollback
            return false;
        }
        hdr.flags |= LARGE_HEADER_FLAG;
    }

    Headers_append(headers, hdr);
    return true;
}

bool headers_tostring(const Headers* headers, char* buffer, size_t size) {
    if (!headers || !buffer || size < 3) return false;

    char* ptr        = buffer;
    size_t remaining = size;

    for (size_t i = 0; i < headers->count; i++) {
        const header_t* h = &headers->items[i];
        const char* value = is_large_value(h) ? str_data(h->ptr) : h->small_value;
        int written       = snprintf(ptr, remaining, "%s: %s\r\n", h->name, value);
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

    // Free large values
    for (size_t i = 0; i < headers->count; i++) {
        if (is_large_value(&headers->items[i])) {
            str_free(headers->items[i].ptr);
        }
    }

    Headers_free(headers);
}
