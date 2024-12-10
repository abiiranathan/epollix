#ifndef E809A397_804A_4866_8AE8_61C4E9E27E82
#define E809A397_804A_4866_8AE8_61C4E9E27E82

#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <solidc/arena.h>
#include <stddef.h>
#include "constants.h"

// Header struct contains header name and value.
typedef struct header {
    char* name;   // header name
    char* value;  // header value
} header_t;

// Create a new header_t.
header_t* header_new(const char* name, const char* value);

// Free memory used by header.
void header_free(header_t* header);

// Parse header_t from http header string.
header_t* header_fromstring(const char* str);

// Find the header_t value matching the name in the array of headers.
// Returns NULL if not found.
char* find_header(header_t* headers, size_t count, const char* name);

// Find the index of the header matching name or -1 if not found.
int find_header_index(header_t** headers, size_t count, const char* name);

#ifdef __cplusplus
}
#endif

#endif /* E809A397_804A_4866_8AE8_61C4E9E27E82 */
