#ifndef HEADER_H
#define HEADER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct headert_t {
    char* key;
    char* value;
} headert_t;

// maximum number of headers.
#ifndef NUM_HEADERS
#define NUM_HEADERS 64
#endif

// Maximum memory for headers.
#define HEADER_ARENA_CAP (NUM_HEADERS * sizeof(headert_t) * 8)  // 8 K memory

typedef struct header_arena {
    size_t allocated;
    uint8_t memory[HEADER_ARENA_CAP];
} header_arena;

// Dynamic Array of headers.
typedef struct Headers {
    size_t count;         // Number of headers appended.
    headert_t* entries;   // array of the headers (up to NUM_HEADERS)
    header_arena* arena;  // Arena allocator for headers
} Headers;

// Query params are also stored as headers. (key/value)
typedef struct Headers QueryParams;

void headers_init(Headers* headers, header_arena* arena);

void headers_append(Headers* headers, const char* name, const char* value);

// Get header value (case insensitive.)
const char* headers_value(Headers* headers, const char* name);

// Get header value. Case sensitive.
const char* headers_value_exact(Headers* headers, const char* name);

// Free header memory used by map.
void headers_free(Headers* headers);

//  ============ Allocation functions ===============
void* h_arena_alloc(header_arena* arena, size_t size);
void h_arena_reset(header_arena* arena);
char* h_arena_alloc_string(header_arena* arena, const char* s);

#endif /* HEADER_H */
