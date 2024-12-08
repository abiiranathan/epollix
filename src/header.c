#include "../include/header.h"
#include "../include/logging.h"

#include <string.h>
#include <strings.h>

// Allocate a new header from name and value.
// Returns NULL if allocation fails.
header_t* header_new(const char* name, const char* value) {
    header_t* header = (header_t*)malloc(sizeof(header_t));
    if (!header) {
        return NULL;
    }

    strncpy(header->name, name, MAX_HEADER_NAME - 1);
    header->name[MAX_HEADER_NAME - 1] = '\0';

    strncpy(header->value, value, MAX_HEADER_VALUE - 1);
    header->value[MAX_HEADER_VALUE - 1] = '\0';
    return header;
}

// Parse header_t from http header string.
header_t* header_fromstring(const char* str) {
    const char* colon = strchr(str, ':');
    if (!colon || colon == str) {
        return NULL;
    }

    size_t name_length = colon - str;
    if (name_length >= MAX_HEADER_NAME) {
        LOG_ERROR("Header name too long for %s, Max length is %d", str, MAX_HEADER_NAME - 1);
        return NULL;
    }

    header_t* header = malloc(sizeof(header_t));
    if (!header) {
        return NULL;
    }

    memcpy(header->name, str, name_length);
    header->name[name_length] = '\0';

    const char* value_start = colon + 1;
    while (*value_start == ' ') {
        value_start++;
    }

    size_t value_length = strlen(value_start);
    if (value_length >= MAX_HEADER_VALUE) {
        LOG_ERROR("Header value too long for %s, Max length is %d", str, MAX_HEADER_VALUE - 1);
        free(header);
        return NULL;
    }

    memcpy(header->value, value_start, value_length);
    header->value[value_length] = '\0';

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
