#ifndef HEADERS_H
#define HEADERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#define HEADER_KEY_LENGTH 64
#define HEADER_VALUE_LENGTH 256

typedef struct Header {
  char name[HEADER_KEY_LENGTH];
  char value[HEADER_VALUE_LENGTH];
} Header;

bool new_header(const char* name, const char* value, Header* header);
bool header_tostring(const Header* h, char* buffer, size_t buffer_len);
bool header_fromstring(const char* str, Header* header);
char* headers_loopup(Header* headers, size_t num_headers, const char* name);
#endif /* HEADERS_H */
