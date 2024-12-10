#include "../include/header.h"
#include "../include/logging.h"

#include <string.h>
#include <strings.h>

header_t* header_new(const char* name, const char* value) {
    header_t* header = malloc(sizeof(header_t));
    if (!header) {
        return NULL;
    }

    header->name = strdup(name);
    header->value = strdup(value);
    return header;
}

void header_free(header_t* header) {
    if (!header)
        return;
    free(header->name);
    free(header->value);
    free(header);
    header = NULL;
}

// Parse header_t from http header string.
header_t* header_fromstring(const char* str) {
    const char* colon = strchr(str, ':');
    if (!colon || colon == str) {
        return NULL;
    }

    size_t name_length = colon - str;
    header_t* header = malloc(sizeof(header_t));
    if (!header) {
        return NULL;
    }

    char* name = malloc(name_length + 1);
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
    char* value = malloc(value_length + 1);
    if (!value) {
        return NULL;
    }

    memcpy(value, value_start, value_length);
    value[value_length] = '\0';
    header->value = value;
    return header;
}

char* find_header(header_t* headers, size_t count, const char* name) {
    for (size_t i = 0; i < count; ++i) {
        if (strcasecmp(headers[i].name, name) == 0) {
            return headers[i].value;
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
