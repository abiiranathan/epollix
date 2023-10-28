#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "map.h"

unsigned long simple_hash(void* key) {
  // Default hash function
  return (unsigned long)key;
}

unsigned long djb2_hash(void* key) {
  unsigned char* str = (unsigned char*)key;
  unsigned long hash = 5381;
  int c;

  while ((c = *str++) != '\0') {
    hash = ((hash << 5) + hash) + c;  // hash * 33 + c
  }

  return hash;
}

map* map_create() {
  map* m      = malloc(sizeof(map));
  m->entries  = malloc(sizeof(entry) * INITIAL_MAP_SIZE);
  m->size     = 0;
  m->capacity = INITIAL_MAP_SIZE;
  m->hash     = djb2_hash;
  return m;
}

void map_destroy(map* m) {
  free(m->entries);
  free(m);
}

void map_resize(map* m, size_t new_capacity) {
  entry* new_entries = malloc(sizeof(entry) * new_capacity);
  for (size_t i = 0; i < new_capacity; i++) {
    new_entries[i].key   = NULL;
    new_entries[i].value = NULL;
  }

  for (size_t i = 0; i < m->capacity; i++) {
    entry* current = &m->entries[i];
    if (current->key != NULL) {
      size_t index = m->hash(current->key) % new_capacity;
      while (new_entries[index].key != NULL) {
        index = (index + 1) % new_capacity;
      }
      new_entries[index] = *current;
    }
  }

  free(m->entries);
  m->entries  = new_entries;
  m->capacity = new_capacity;
}

void map_set(map* m, void* key, void* value) {
  if ((double)m->size / m->capacity > LOAD_FACTOR_THRESHOLD) {
    map_resize(m, m->capacity * 2);
  }

  size_t index = m->hash(key) % m->capacity;
  while (m->entries[index].key != NULL) {
    if (m->entries[index].key == key) {
      m->entries[index].value = value;
      return;
    }
    index = (index + 1) % m->capacity;
  }

  m->entries[index].key   = key;
  m->entries[index].value = value;
  m->size++;
}

void* map_get(map* m, void* key) {
  size_t index = m->hash(key) % m->capacity;
  while (m->entries[index].key != NULL) {
    if (m->entries[index].key == key) {
      return m->entries[index].value;
    }
    index = (index + 1) % m->capacity;
  }
  return NULL;
}

void map_remove(map* m, void* key) {
  size_t index = m->hash(key) % m->capacity;
  while (m->entries[index].key != NULL) {
    if (m->entries[index].key == key) {
      m->entries[index].key   = NULL;
      m->entries[index].value = NULL;
      m->size--;
      return;
    }
    index = (index + 1) % m->capacity;
  }
}

size_t map_length(map* m) {
  return m->size;
}

size_t map_capacity(map* m) {
  return m->capacity;
}

// Assumes keys are char*
// Must free the keys after.
char** map_keys(map* m) {
  char** keys      = malloc(sizeof(char*) * m->size);
  size_t key_index = 0;

  for (size_t i = 0; i < m->capacity; i++) {
    if (m->entries[i].key != NULL) {
      keys[key_index] = (char*)m->entries[i].key;
      key_index++;
    }
  }
  return keys;
}

void map_set_hash(map* m, unsigned long (*hash)(void*)) {
  m->hash = hash;
}

map_iterator* map_iterator_create(map* m) {
  map_iterator* iter = malloc(sizeof(map_iterator));
  iter->m            = m;
  iter->bucket       = 0;
  iter->index        = 0;
  return iter;
}

void map_iterator_destroy(map_iterator* iter) {
  free(iter);
}

int map_iterator_has_next(map_iterator* iter) {
  while (iter->bucket < iter->m->capacity) {
    if (iter->m->entries[iter->bucket].key != NULL) {
      return 1;
    }
    iter->bucket++;
  }
  return 0;
}

entry map_iterator_next(map_iterator* iter) {
  entry e = {NULL, NULL};

  while (iter->bucket < iter->m->capacity) {
    if (iter->m->entries[iter->bucket].key != NULL) {
      e.key   = iter->m->entries[iter->bucket].key;
      e.value = iter->m->entries[iter->bucket].value;
      iter->bucket++;
      return e;
    }
    iter->bucket++;
  }
  return e;
}

static void mapStrings() {
  map* m = map_create();

  // Set key-value pairs
  map_set(m, "name", "John");
  map_set(m, "age", "30");
  map_set(m, "city", "New York");

  // Get values by keys
  char* name = map_get(m, "name");
  char* age  = map_get(m, "age");
  char* city = map_get(m, "city");

  printf("Name: %s\n", name);
  printf("Age: %s\n", age);
  printf("City: %s\n", city);

  // Remove a key-value pair
  map_remove(m, "age");

  // Iterate over the map
  map_iterator* iter = map_iterator_create(m);
  while (map_iterator_has_next(iter)) {
    entry e = map_iterator_next(iter);
    printf("Key: %s, Value: %s\n", (char*)e.key, (char*)e.value);
  }
  map_iterator_destroy(iter);
  map_destroy(m);
}
