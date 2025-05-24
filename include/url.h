#ifndef URL_H
#define URL_H

#include <stddef.h>

// Check if the CPU supports AVX2 at runtime.
// Its better to check this at compile-time by checjing
// if __AVX2__ is defined.
// Returns 1 if supported, 0 otherwise.
int has_avx2();

// ======== URI ENCODING ========
// Encode a string for safe use in a URL.
// Returns a pointer to the encoded string.
void url_percent_encode(const char* src, char* dst, size_t dst_size);

// Encode a string for safe use in a URL using SIMD if available, otherwise fallback to scalar implementation.
void url_percent_encode_simd(const char* src, char* dst, size_t dst_size);

// Encode a string for safe use in a URL using scalar implementation.
// This is a fallback for systems without SIMD support.
// Otherwise, use encode_uri_simd.
void url_percent_encode_scalar(const char* src, char* dst, size_t dst_size);
// Encode a string for safe use in a URL using SIMD if available, otherwise fallback to scalar implementation.

// ========== DECODING URI ==========
// Decode a URI-encoded string using SIMD if available, otherwise fallback to scalar implementation.
void url_percent_decode(const char* src, char* dst, size_t dst_size);

// Decode a URI-encoded string using SIMD if available, otherwise fallback to scalar implementation.
void url_percent_decode_simd(const char* src, char* dst, size_t dst_size);

// Decode a URI-encoded string with scalar implementation.
// This is a fallback for systems without SIMD support.
// Otherwise, use decode_uri_simd.
void url_percent_decode_scalar(const char* src, char* dst, size_t dst_size);

#endif /* URL_H */
