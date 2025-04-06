#ifndef HEADERS_H
#define HEADERS_H

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define LARGE_HEADER_FLAG 0x80000000

// Headers opaque type for http headers.
typedef struct header_list* Headers;

// Allocate a new headers object with an initial capacity.
Headers headers_new(size_t initial_capacity);

// Get the number of headers.
size_t headers_count(const Headers headers);

// Get the name of a header at a given index.
int headers_index(const Headers headers, const char* name);

// Get the value of a header by name.
const char* headers_value(const Headers headers, const char* name);

// Get the value of a header by index.
bool headers_append(Headers headers, const char* name, const char* value);

// Append a header to the headers list.
void headers_free(Headers headers);

// Format headers to the standard http header format.
// and store it in the buffer.
// Returns true on success, false on failure.
// For empty headers, it will write only "\r\n" to the buffer.
bool headers_tostring(const Headers headers, char* buffer, size_t size);

#endif
