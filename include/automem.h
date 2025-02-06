#ifndef _AUTOMEM_H
#define _AUTOMEM_H

// __attribute__((cleanup(automem_free))) is a GCC extension that allows
// you to specify a cleanup function that will be called when the variable goes out of scope.
// Not supported in C++ and MSVC.
#if !defined(__GNUC__) && !defined(__clang__)
#error "__attribute__(cleanup) is only supported in GCC and Clang compilers."
#endif

#if defined(__cplusplus)
#error "__attribute__(cleanup) is only supported in C."
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
        *p = nullptr;
    }
}

static inline void autoclose_file(void* ptr) {
    if (!ptr)
        return;
    FILE** p = (FILE**)ptr;
    if (*p) {
        fclose(*p);
        *p = nullptr;
    }
}

#endif  // AUTOMEM_IMPL

#endif  // _AUTOMEM_H