#include "../include/headers.h"
#include <strings.h>

Header* new_header(Arena* arena, const char* name, const char* value) {
    Header* header = arena_alloc(arena, sizeof(Header));
    if (header == NULL) {
        return NULL;
    }

    header->name = cstr_from(arena, name);
    if (header->name == NULL) {
        return NULL;
    }

    header->value = cstr_from(arena, value);
    if (header->value == NULL) {
        return NULL;
    }
    return header;
}

cstr* header_tostring(Arena* arena, const Header* h) {
    cstr* str = cstr_new(arena, 1024);
    if (str == NULL) {
        return NULL;
    }

    if (!cstr_append_fmt(arena, str, "%s: %s", h->name->data, h->value->data)) {
        return NULL;
    }
    return str;
}

Header* header_fromstring(Arena* arena, const cstr* str) {
    size_t n = 0;
    cstr** parts = cstr_split_at(arena, str, ": ", 2, &n);
    if (n != 2 || parts == NULL) {
        return NULL;
    }

    Header* header = arena_alloc(arena, sizeof(Header));
    if (header == NULL) {
        return NULL;
    }

    header->name = parts[0];
    header->value = parts[1];
    return header;
}

cstr* headers_loopup(Header** headers, size_t num_headers, const char* name) {
    for (size_t i = 0; i < num_headers; i++) {
        if (strcasecmp(headers[i]->name->data, name) == 0) {
            return headers[i]->value;
        }
    }
    return NULL;
}
