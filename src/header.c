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

void headers_free(Headers* headers) {
    if (!headers) return;

    for (size_t i = 0; i < headers->count; i++) {
        cstr_free(headers->items[i].name);
        cstr_free(headers->items[i].value);
    }
    kv_free(headers);
}
