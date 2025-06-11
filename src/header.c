#include "../include/header.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/constants.h"

#define ENTRY_ARRAY_SIZE (NUM_HEADERS * sizeof(headert_t))

void headers_init(Headers* headers, header_arena* arena) {
    headers->count   = 0;
    headers->arena   = arena;
    headers->entries = h_arena_alloc(arena, ENTRY_ARRAY_SIZE);
    assert(headers->entries);
    memset(headers->entries, 0, ENTRY_ARRAY_SIZE);
}

const char* headers_value(Headers* headers, const char* name) {
    for (size_t i = 0; i < headers->count; ++i) {
        if (strcasecmp(name, headers->entries[i].key) == 0) {
            return headers->entries[i].value;
        }
    }
    return NULL;
}

const char* headers_value_exact(Headers* headers, const char* name) {
    for (size_t i = 0; i < headers->count; ++i) {
        if (strcmp(name, headers->entries[i].key) == 0) {
            return headers->entries[i].value;
        }
    }
    return NULL;
}

void headers_append(Headers* headers, const char* name, const char* value) {
    if (headers->count < NUM_HEADERS) {
        headert_t* entry = &headers->entries[headers->count];
        entry->key       = h_arena_alloc_string(headers->arena, name);
        entry->value     = h_arena_alloc_string(headers->arena, value);
        if (entry->key && entry->value) {
            headers->count++;
        }
    }
}

void headers_free(Headers* headers) {
    h_arena_reset(headers->arena);
}

void* h_arena_alloc(header_arena* arena, size_t size) {
    if (arena->allocated + size >= HEADER_ARENA_CAP) {
        return NULL;
    }

    void* ptr = &arena->memory[arena->allocated];
    arena->allocated += size;
    return ptr;
}

void h_arena_reset(header_arena* arena) {
    arena->allocated = 0;
    memset(arena->memory, 0, HEADER_ARENA_CAP);
}

char* h_arena_alloc_string(header_arena* arena, const char* s) {
    size_t len = strlen(s);
    char* ptr  = (char*)h_arena_alloc(arena, len + 1);
    if (!ptr) return NULL;
    strcpy(ptr, s);
    return ptr;
}
