#ifndef MAP_H
#define MAP_H

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Hash function (djb2)
// See. https://theartincode.stanis.me/008-djb2/
__attribute__((always_inline)) inline unsigned long djb2_hash(const char* str) {
  unsigned long hash = 5381;
  int c;
  while ((c = *str++)) {
    hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
  }
  return hash;
}

// Define a macro for creating a hashmap with a specific key and value type
#define DECLARE_HASHMAP(key_type, value_type)                                                      \
  typedef struct {                                                                                 \
    key_type key;                                                                                  \
    value_type value;                                                                              \
  } KeyValuePair_##key_type##_##value_type;                                                        \
                                                                                                   \
  typedef struct {                                                                                 \
    size_t capacity;                                                                               \
    size_t size;                                                                                   \
    KeyValuePair_##key_type##_##value_type* data;                                                  \
  } HashMap_##key_type##_##value_type;                                                             \
                                                                                                   \
  HashMap_##key_type##_##value_type* create_##key_type##_##value_type##_map(size_t capacity) {     \
    HashMap_##key_type##_##value_type* map = malloc(sizeof(HashMap_##key_type##_##value_type));    \
    if (map) {                                                                                     \
      map->capacity = capacity;                                                                    \
      map->size     = 0;                                                                           \
      map->data     = malloc(sizeof(KeyValuePair_##key_type##_##value_type) * capacity);           \
      if (!map->data) {                                                                            \
        free(map);                                                                                 \
        return NULL;                                                                               \
      }                                                                                            \
    }                                                                                              \
    return map;                                                                                    \
  }                                                                                                \
                                                                                                   \
  void destroy_##key_type##_##value_type##_map(HashMap_##key_type##_##value_type* map) {           \
    free(map->data);                                                                               \
    free(map);                                                                                     \
  }                                                                                                \
                                                                                                   \
  void insert_##key_type##_##value_type(HashMap_##key_type##_##value_type* map, key_type key,      \
                                        value_type value) {                                        \
    if (map->size < map->capacity) {                                                               \
      KeyValuePair_##key_type##_##value_type* entry = &map->data[map->size++];                     \
      entry->key                                    = key;                                         \
      entry->value                                  = value;                                       \
    }                                                                                              \
  }                                                                                                \
  value_type* get_##key_type##_##value_type(HashMap_##key_type##_##value_type* map,                \
                                            key_type key) {                                        \
    for (size_t i = 0; i < map->size; ++i) {                                                       \
      if (map->data[i].key == key) {                                                               \
        return &map->data[i].value;                                                                \
      }                                                                                            \
    }                                                                                              \
    return NULL;                                                                                   \
  }                                                                                                \
  void delete_##key_type##_##value_type(HashMap_##key_type##_##value_type* map, key_type key) {    \
    for (size_t i = 0; i < map->size; ++i) {                                                       \
      if (map->data[i].key == key) {                                                               \
        map->data[i] = map->data[map->size - 1];                                                   \
        --map->size;                                                                               \
        return;                                                                                    \
      }                                                                                            \
    }                                                                                              \
  }                                                                                                \
  void clear_##key_type##_##value_type##_map(HashMap_##key_type##_##value_type* map) {             \
    map->size = 0;                                                                                 \
  }                                                                                                \
  key_type* keys_##key_type##_##value_type##_map(HashMap_##key_type##_##value_type* map) {         \
    key_type* keys = malloc(sizeof(key_type) * map->size);                                         \
    if (keys) {                                                                                    \
      for (size_t i = 0; i < map->size; ++i) {                                                     \
        keys[i] = map->data[i].key;                                                                \
      }                                                                                            \
    }                                                                                              \
    return keys;                                                                                   \
  }                                                                                                \
  value_type* values_##key_type##_##value_type##_map(HashMap_##key_type##_##value_type* map) {     \
    value_type* values = malloc(sizeof(value_type) * map->size);                                   \
    if (values) {                                                                                  \
      for (size_t i = 0; i < map->size; ++i) {                                                     \
        values[i] = map->data[i].value;                                                            \
      }                                                                                            \
    }                                                                                              \
    return values;                                                                                 \
  }


#endif /* MAP_H */
