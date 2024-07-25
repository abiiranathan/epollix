#ifndef _AUTOMEM_H
#define _AUTOMEM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define autofree __attribute__((cleanup(automem_free)))
#define autoclose __attribute__((cleanup(autoclose_file)))

#ifdef AUTOMEM_IMPL
static inline void automem_free(void* ptr) {
    if (!ptr)
        return;
    void** p = (void**)ptr;
    if (*p) {
        free(*p);
        *p = NULL;
    }
}

static inline void autoclose_file(void* ptr) {
    if (!ptr)
        return;
    FILE** p = (FILE**)ptr;
    if (*p) {
        fclose(*p);
        *p = NULL;
    }
}

#endif  // AUTOMEM_IMPL

#ifdef __cplusplus
}
#endif

#endif  // _AUTOMEM_H