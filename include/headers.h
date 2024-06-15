#ifndef HEADERS_H
#define HEADERS_H

#include <solidc/arena.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define MAX_HEADER_NAME 64
#define MAX_HEADER_VALUE 256

typedef struct Header {
    char name[MAX_HEADER_NAME];
    char value[MAX_HEADER_VALUE];
} Header;

Header new_header(const char* name, const char* value);
void header_tostring(const Header* h, char buffer[MAX_HEADER_NAME + MAX_HEADER_VALUE + 4], size_t buffer_size);
Header header_fromstring(const char* str);
const char* find_header(Header* headers, size_t num_headers, const char* name);
int find_header_index(Header* headers, size_t num_headers, const char* name);
bool header_valid(const Header* h);

#endif /* HEADERS_H */
