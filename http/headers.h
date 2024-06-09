#ifndef HEADERS_H
#define HEADERS_H

#include <solidc/cstr.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct Header {
  cstr* name;
  cstr* value;
} Header;

Header* new_header(Arena* arena, const char* name, const char* value);
cstr* header_tostring(Arena* arena, const Header* h);
Header* header_fromstring(Arena* arena, const cstr* str);

cstr* headers_loopup(Header** headers, size_t num_headers, const char* name);
#endif /* HEADERS_H */
