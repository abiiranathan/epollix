#ifndef _DEFER_H
#define _DEFER_H

#define DEFER_VERSION 1
#define _DEFER_CONCAT_IMPL(a, b) a##b
#define _DEFER_CONCAT(a, b) _DEFER_CONCAT_IMPL(a, b)

#define autofree __attribute__((cleanup(autofree_var)))
#define autoclose __attribute__((cleanup(autoclose_var)))

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

// Compiler-specific definitions
#if defined(__GNUC__) && !defined(__clang__)
// GCC/ICC
typedef void (*defer_block)(void);
#define defer_block_create(body)                                                                                       \
    ({                                                                                                                 \
        void __fn__(void) body;                                                                                        \
        __fn__;                                                                                                        \
    })
#define defer(body)                                                                                                    \
    defer_block __attribute__((unused)) __attribute((cleanup(do_defer))) _DEFER_CONCAT(__defer, __COUNTER__) =         \
        defer_block_create(body)
#elif defined(__clang__)
// Clang/zig cc
typedef void (^defer_block)(void);
#define defer_block_create(body) ^body
#define defer(body)                                                                                                    \
    defer_block __attribute__((unused)) __attribute__((cleanup(do_defer))) _DEFER_CONCAT(__defer, __COUNTER__) =       \
        defer_block_create(body)
#else
#error "Compiler not compatible with defer library"
#endif

#ifdef DEFER_IMPL
// defer
static inline void do_defer(defer_block* ptr) {
    (*ptr)();
}

// autofree
static inline void autofree_var(void* ptr) {
    free(*(void**)ptr);
}

// autoclose
static inline void autoclose_var(void* ptr) {
    fclose(*(FILE**)ptr);
}

#endif  // DEFER_IMPL

#ifdef __cplusplus
}
#endif

// LICENSE:
//
// MIT License
//
// Copyright (c) 2023 Jonas Everaert
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

#endif
