#include "../include/header.h"
#include "../include/constants.h"

const char* headers_value(const Headers* headers, const char* name) {
    for (size_t i = 0; i < headers->count; ++i) {
        header_t h         = headers->items[i];
        const char* h_name = cstr_data_const(h.name);
        if (!h_name) {
            continue;
        }
        if (strcasecmp(name, h_name) == 0) {
            return cstr_data_const(h.value);
        }
    }
    return NULL;
}

bool headers_append(Headers* headers, const char* name, const char* value) {
    header_t hdr = {.name = cstr_new(name), .value = cstr_new(value)};
    ASSERT(hdr.name);
    ASSERT(hdr.value);
    return kv_append(headers, hdr);
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
    kv_free(headers);
}
