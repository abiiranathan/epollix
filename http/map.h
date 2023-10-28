#ifndef __MAP_H__
#define __MAP_H__

#include <stddef.h>

// Allow user to customize initial map size and load factor threshold
#ifndef INITIAL_MAP_SIZE
#define INITIAL_MAP_SIZE 16
#endif

#ifndef LOAD_FACTOR_THRESHOLD
#define LOAD_FACTOR_THRESHOLD 0.75
#endif

typedef struct {
    void* key;
    void* value;
} entry;

typedef struct {
    entry* entries;
    size_t size;
    size_t capacity;
    unsigned long (*hash)(void*);
} map;

// Function Declarations
map* map_create();
void map_destroy(map* m);
void map_resize(map* m, size_t new_capacity);
void map_set(map* m, void* key, void* value);
void* map_get(map* m, void* key);
void map_remove(map* m, void* key);
void map_set_hash(map* m, unsigned long (*hash)(void*));
char** map_keys(map* m);
size_t map_length(map* m);
size_t map_capacity(map* m);

//  Created by Daniel J. Bernstein .
// It generates hash values by multiplying the current hash by 33
// and adding the next character in the key.
// This process continues for each character in the key,
// resulting in a final hash value
unsigned long djb2_hash(void* key);

typedef struct {
    map* m;
    size_t bucket;
    size_t index;
} map_iterator;

map_iterator* map_iterator_create(map* m);
void map_iterator_destroy(map_iterator* iter);
int map_iterator_has_next(map_iterator* iter);
entry map_iterator_next(map_iterator* iter);

#endif /* __MAP_H__ */
