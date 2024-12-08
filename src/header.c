#include "../include/header.h"
#include "../include/logging.h"

#include <string.h>
#include <strings.h>

header_t* header_new(const char* name, const char* value, Arena* arena) {
    header_t* header = arena_alloc(arena, sizeof(header_t));
    if (!header) {
        return NULL;
    }

    header->name = arena_alloc(arena, strlen(name) + 1);
    if (!header->name) {
        return NULL;
    }
    strcpy(header->name, name);

    header->value = arena_alloc(arena, strlen(value) + 1);
    if (!header->value) {
        return NULL;
    }
    strcpy(header->value, value);

    return header;
}

// Parse header_t from http header string.
header_t* header_fromstring(const char* str, Arena* arena) {
    const char* colon = strchr(str, ':');
    if (!colon || colon == str) {
        return NULL;
    }

    size_t name_length = colon - str;
    header_t* header = arena_alloc(arena, sizeof(header_t));
    if (!header) {
        return NULL;
    }

    char* name = arena_alloc(arena, name_length + 1);
    if (!name) {
        return NULL;
    }
    memcpy(name, str, name_length);
    name[name_length] = '\0';
    header->name = name;

    const char* value_start = colon + 1;
    while (*value_start == ' ') {
        value_start++;
    }

    size_t value_length = strlen(value_start);
    char* value = arena_alloc(arena, value_length + 1);
    if (!value) {
        return NULL;
    }

    memcpy(value, value_start, value_length);
    value[value_length] = '\0';
    header->value = value;
    return header;
}

char* find_header(header_t** headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcasecmp(headers[i]->name, name) == 0) {
            return headers[i]->value;
        }
    }
    return NULL;
}

int find_header_index(header_t** headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcasecmp(headers[i]->name, name) == 0) {
            return i;
        }
    }
    return -1;
}
