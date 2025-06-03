#ifndef kv_H
#define kv_H

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#include <solidc/cstr.h>

typedef struct {
    cstr* name;
    cstr* value;
} header_t;

#define DEFAULT_CAPACITY 64

typedef struct kv {
    header_t* items;
    size_t count;
    size_t capacity;
} kv;

static inline kv* kv_new(void) {
    kv* arr = (kv*)malloc(sizeof(kv));
    if (!arr) {
        perror("malloc");
        return NULL;
    }
    arr->items = (header_t*)calloc(DEFAULT_CAPACITY, sizeof(header_t));
    if (!arr->items) {
        free(arr);
        perror("calloc");
        return NULL;
    }
    arr->count    = 0;
    arr->capacity = DEFAULT_CAPACITY;
    return arr;
}

// Only resizes if new_capacity > current capacity
static inline bool kv_resize(kv* arr, size_t new_capacity) {
    if (new_capacity <= arr->capacity) return true;
    header_t* new_items = (header_t*)realloc(arr->items, new_capacity * sizeof(header_t));
    if (!new_items) {
        perror("realloc");
        return false;
    }
    arr->items    = new_items;
    arr->capacity = new_capacity;
    return true;
}

// Shrinks capacity to fit current count (if smaller)
static inline bool kv_shrink(kv* arr) {
    if (arr->capacity > arr->count) {
        return kv_resize(arr, arr->count);
    }
    return true;
}

static inline bool kv_append(kv* arr, header_t value) {
    if (arr->count >= arr->capacity) {
        size_t cap = arr->capacity == 0 ? DEFAULT_CAPACITY : arr->capacity;
        // Overflow check.
        if (SIZE_MAX / cap < 2) {
            fprintf(stderr, "Overflow in capacity");
            return false;
        }
        size_t new_capacity = cap * 2;
        if (!kv_resize(arr, new_capacity)) {
            return false;
        };
    }
    arr->items[arr->count++] = value;
    return true;
}

static inline header_t kv_get(const kv* arr, size_t index) {
    if (index >= arr->count) {
        fprintf(stderr, "Index %lu is out of bounds\n", index);
        exit(1);
    }
    return arr->items[index];
}

static inline void kv_remove(kv* arr, size_t index) {
    if (index >= arr->count) {
        fprintf(stderr, "Index %lu is out of bounds\n", index);
        exit(1);
    }
    memmove(&arr->items[index], &arr->items[index + 1], (arr->count - index - 1) * sizeof(header_t));
    arr->count--;
}

static inline void kv_free(kv* arr) {
    if (arr) {
        free(arr->items);
        free(arr);
    }
}

#endif  // kv_H
