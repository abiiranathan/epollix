#ifndef E809A397_804A_4866_8AE8_61C4E9E27E82
#define E809A397_804A_4866_8AE8_61C4E9E27E82

#include <stdlib.h>
#ifdef __cplusplus
extern "C" {
#endif

#include <solidc/arena.h>
#include <solidc/memory_pool.h>
#include <stddef.h>
#include "constants.h"

// Header struct contains header name and value.
typedef struct header {
    const char* name;   // header name
    const char* value;  // header value
} header_t;

// Parse header_t from http header string.
header_t* header_fromstring(MemoryPool* pool, const char* str);

// Find the header_t value matching the name in the array of headers.
// Returns nullptr if not found.
const char* find_header(header_t* headers, size_t count, const char* name);

// Find the index of the header matching name or -1 if not found.
int find_header_index(header_t** headers, size_t count, const char* name);

#ifdef __cplusplus
}
#endif

#endif /* E809A397_804A_4866_8AE8_61C4E9E27E82 */
