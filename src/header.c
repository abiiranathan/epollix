#include "../include/header.h"
#include "../include/constants.h"
#include "../include/fast_str.h"
#include "logging.h"
#include <strings.h>  // for strcasecmp

typedef struct {
    char name[MAX_HEADER_NAME_LEN];  // Header name
    union {
        char small_value[SMALL_HEADER_VALUE_LEN];  // Small value buffer
        struct {
            char* ptr;   // Pointer to heap-allocated value
            size_t len;  // Length of the value
        } large_value;   // Heap-allocated value
    };
    unsigned int flags;  // Stores LARGE_HEADER_FLAG if value is heap-allocated
} header_t;

// Header list structure
struct header_list {
    header_t* entries;  // Array of headers
    size_t count;       // Number of headers
    size_t capacity;    // Capacity of the array
};

Headers headers_new(size_t initial_capacity) {
    Headers headers = malloc(sizeof(struct header_list));
    if (!headers) return NULL;

    headers->entries = calloc(initial_capacity, sizeof(header_t));
    if (!headers->entries) {
        free(headers);
        return NULL;
    }

    headers->count    = 0;
    headers->capacity = initial_capacity;
    return headers;
}

// Get the number of headers.
size_t headers_count(const Headers headers) {
    if (!headers) return 0;
    return headers->count;
}

static inline bool is_large_value(const header_t* h) {
    return h->flags & LARGE_HEADER_FLAG;
}

const char* headers_value(const Headers headers, const char* name) {
    for (size_t i = 0; i < headers->count; ++i) {
        if (fast_strcasecmp(name, headers->entries[i].name) == 0) {
            return is_large_value(&headers->entries[i]) ? headers->entries[i].large_value.ptr
                                                        : headers->entries[i].small_value;
        }
    }
    return NULL;
}

bool headers_append(Headers headers, const char* name, const char* value) {
    if (!headers || !name || !value) return false;

    size_t name_len  = strlen(name);
    size_t value_len = strlen(value);

    if (name_len >= MAX_HEADER_NAME_LEN) {
        LOG_ERROR("Header name too long");
        return false;
    }

    // Resize if needed
    if (headers->count >= headers->capacity) {
        size_t new_cap     = headers->capacity * 2;
        header_t* new_data = realloc(headers->entries, new_cap * sizeof(header_t));
        if (!new_data) return false;
        headers->entries  = new_data;
        headers->capacity = new_cap;
    }

    header_t* hdr = &headers->entries[headers->count++];

    // Copy name (safe because we checked length)
    memcpy(hdr->name, name, name_len);
    hdr->name[name_len] = '\0';
    hdr->flags          = 0;

    // Handle value
    if (value_len < SMALL_HEADER_VALUE_LEN) {
        memcpy(hdr->small_value, value, value_len);
        hdr->small_value[value_len] = '\0';
    } else {
        char* val_copy = malloc(value_len + 1);
        if (!val_copy) {
            headers->count--;  // Rollback
            return false;
        }

        memcpy(val_copy, value, value_len);
        val_copy[value_len]  = '\0';
        hdr->large_value.ptr = val_copy;
        hdr->large_value.len = value_len;
        hdr->flags |= LARGE_HEADER_FLAG;
    }
    return true;
}

bool headers_tostring(const Headers headers, char* buffer, size_t size) {
    if (!headers || !buffer || size < 3) return false;

    char* ptr        = buffer;
    size_t remaining = size;

    for (size_t i = 0; i < headers->count; i++) {
        const header_t* h = &headers->entries[i];
        const char* value = is_large_value(h) ? h->large_value.ptr : h->small_value;

        int written = snprintf(ptr, remaining, "%s: %s\r\n", h->name, value);
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

void headers_free(Headers headers) {
    if (!headers) return;

    // Free large values
    for (size_t i = 0; i < headers->count; i++) {
        if (is_large_value(&headers->entries[i])) {
            free(headers->entries[i].large_value.ptr);
        }
    }

    free(headers->entries);
    free(headers);
}
