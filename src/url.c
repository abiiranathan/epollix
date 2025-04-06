#include "../include/url.h"
#include <ctype.h>
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cpuid.h>

// Check if the CPU supports AVX2
int has_avx2() {
    unsigned int eax, ebx, ecx, edx;

    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;

    int avx_supported = (ecx & bit_AVX) && (ecx & bit_OSXSAVE);
    if (!avx_supported) return 0;

    // Check XCR0 bits to ensure OS supports AVX
    uint32_t xcr0_lo, xcr0_hi;
    __asm__ volatile(".byte 0x0f, 0x01, 0xd0" : "=a"(xcr0_lo), "=d"(xcr0_hi) : "c"(0));
    uint64_t xcr0 = ((uint64_t)xcr0_hi << 32) | xcr0_lo;
    if ((xcr0 & 0x6) != 0x6) return 0;

    // Check for AVX2
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        return (ebx & bit_AVX2) != 0;
    }

    return 0;
}

// ======== URI ENCODING ========
// Encode a string for safe use in a URL.
// Returns a pointer to the encoded string.
void url_percent_encode(const char* src, char* dst, size_t dst_size) {
    if (has_avx2()) {
        url_percent_encode_simd(src, dst, dst_size);
    } else {
        url_percent_encode_scalar(src, dst, dst_size);
    }
}

// Encode a string for safe use in a URL using SIMD if available, otherwise fallback to scalar implementation.
void url_percent_encode_simd(const char* src, char* dst, size_t dst_size) {
    const size_t simd_width = 32;
    const char* s           = src;
    char* d                 = dst;
    size_t remaining        = dst_size - 1;  // Reserve for null-terminator

    const __m256i A     = _mm256_set1_epi8('A');
    const __m256i Z     = _mm256_set1_epi8('Z');
    const __m256i a     = _mm256_set1_epi8('a');
    const __m256i z     = _mm256_set1_epi8('z');
    const __m256i zero9 = _mm256_set1_epi8('0');
    const __m256i nine  = _mm256_set1_epi8('9');
    const __m256i dash  = _mm256_set1_epi8('-');
    const __m256i under = _mm256_set1_epi8('_');
    const __m256i dot   = _mm256_set1_epi8('.');
    const __m256i tilde = _mm256_set1_epi8('~');

    while (*s && remaining > 0) {
        size_t len       = strlen(s);
        size_t chunk_len = (len >= simd_width) ? simd_width : len;
        __m256i chunk    = _mm256_loadu_si256((__m256i*)s);

        // Alphanumeric check
        __m256i is_upper = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, _mm256_sub_epi8(A, _mm256_set1_epi8(1))),
                                            _mm256_cmpgt_epi8(_mm256_add_epi8(Z, _mm256_set1_epi8(1)), chunk));

        __m256i is_lower = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, _mm256_sub_epi8(a, _mm256_set1_epi8(1))),
                                            _mm256_cmpgt_epi8(_mm256_add_epi8(z, _mm256_set1_epi8(1)), chunk));

        __m256i is_digit = _mm256_and_si256(_mm256_cmpgt_epi8(chunk, _mm256_sub_epi8(zero9, _mm256_set1_epi8(1))),
                                            _mm256_cmpgt_epi8(_mm256_add_epi8(nine, _mm256_set1_epi8(1)), chunk));

        __m256i is_safe =
            _mm256_or_si256(_mm256_or_si256(_mm256_cmpeq_epi8(chunk, dash), _mm256_cmpeq_epi8(chunk, under)),
                            _mm256_or_si256(_mm256_cmpeq_epi8(chunk, dot), _mm256_cmpeq_epi8(chunk, tilde)));

        __m256i is_unreserved =
            _mm256_or_si256(_mm256_or_si256(is_upper, is_lower), _mm256_or_si256(is_digit, is_safe));

        uint32_t mask = _mm256_movemask_epi8(is_unreserved);

        for (size_t i = 0; i < chunk_len && remaining > 0; i++) {
            unsigned char c = s[i];
            if ((mask >> i) & 1) {
                *d++ = c;
                remaining--;
            } else if (remaining >= 3) {
                static const char hex[] = "0123456789ABCDEF";
                *d++                    = '%';
                *d++                    = hex[(c >> 4) & 0xF];
                *d++                    = hex[c & 0xF];
                remaining -= 3;
            } else {
                // Not enough space to encode, terminate early
                break;
            }
        }

        s += chunk_len;
    }

    *d = '\0';
}

// Encode a string for safe use in a URL using scalar implementation.
// This is a fallback for systems without SIMD support.
// Otherwise, use encode_uri_simd.
void url_percent_encode_scalar(const char* src, char* dst, size_t dst_size) {
    const char* hex = "0123456789ABCDEF";
    size_t written  = 0;

    while (*src && written + 1 < dst_size) {
        unsigned char c = (unsigned char)*src;

        // Alphanumeric or unreserved characters
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            if (written + 1 >= dst_size) break;
            *dst++ = c;
            written++;
        } else {
            if (written + 3 >= dst_size) break;
            *dst++ = '%';
            *dst++ = hex[c >> 4];
            *dst++ = hex[c & 15];
            written += 3;
        }
        src++;
    }
    *dst = '\0';
}

// ========== DECODING URI ==========

// Decode a URI-encoded string using SIMD if available, otherwise fallback to scalar implementation.
void url_percent_decode(const char* src, char* dst, size_t dst_size) {
    if (has_avx2()) {
        url_percent_decode_simd(src, dst, dst_size);
    } else {
        url_percent_decode_scalar(src, dst, dst_size);
    }
}

// Decode a URI-encoded string using SIMD if available, otherwise fallback to scalar implementation.
void url_percent_decode_simd(const char* src, char* dst, size_t dst_size) {
    const size_t simd_width = 32;                 // AVX2 processes 32 bytes at a time
    const char* end         = src + strlen(src);  // End of the source string
    size_t remaining        = dst_size - 1;       // Reserve space for null terminator

    // Precompute lookup tables for hex conversion (much faster than conditional branches)
    static const uint8_t hex_values[256] = {
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x00-0x0F
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x10-0x1F
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x20-0x2F
        0, 1,  2,  3,  4,  5,  6,  7, 8, 9, 0, 0, 0, 0, 0, 0,  // 0x30-0x3F ('0'-'9')
        0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x40-0x4F ('A'-'F')
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x50-0x5F
        0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x60-0x6F ('a'-'f')
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0x70-0x7F
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0,  // Remaining bytes for full 256 entries
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,  0,  0,  0,  0,  0,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    // Cache frequently used constants as SIMD registers
    const __m256i percent = _mm256_set1_epi8('%');
    const __m256i plus    = _mm256_set1_epi8('+');

    // Main processing loop
    while (src < end && remaining > 0) {
        // Check if we have enough input for a full SIMD chunk
        if (src + simd_width <= end) {
            // Load chunk into SIMD register
            __m256i chunk = _mm256_loadu_si256((__m256i*)src);

            // Find '%' and '+' characters
            __m256i percent_match = _mm256_cmpeq_epi8(chunk, percent);
            __m256i plus_match    = _mm256_cmpeq_epi8(chunk, plus);
            __m256i special_match = _mm256_or_si256(percent_match, plus_match);
            uint32_t mask         = _mm256_movemask_epi8(special_match);

            if (mask == 0) {
                // No '%' or '+' in this chunk - fast copy
                size_t copy_len =
                    (simd_width < remaining) ? simd_width : remaining;  // Ensure we don't write past the buffer
                memcpy(dst, src, copy_len);
                src += copy_len;
                dst += copy_len;
                remaining -= copy_len;

                continue;
            }
        }

        // Slow path or incomplete chunk: process one character at a time
        if (*src == '%' && (end - src) >= 3 && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            // Fast hex decoding using lookup table
            uint8_t high = hex_values[(unsigned char)src[1]];
            uint8_t low  = hex_values[(unsigned char)src[2]];
            *dst         = (char)((high << 4) | low);

            src += 3;
            dst++;
            remaining--;
        } else if (*src == '+') {
            // '+' is decoded as space
            *dst = ' ';
            src++;
            dst++;
            remaining--;
        } else {
            // Regular character
            *dst = *src;
            src++;
            dst++;
            remaining--;
        }
    }
    *dst = '\0';
}

// Decode a URI-encoded string with scalar implementation.
// This is a fallback for systems without SIMD support.
// Otherwise, use decode_uri_simd.
void url_percent_decode_scalar(const char* src, char* dst, size_t dst_size) {
    char a, b;
    size_t written = 0;
    size_t src_len = strlen(src);

    while (*src && written + 1 < dst_size) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
            written++;
        } else if ((*src == '%') && (src_len >= 2) && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a') a -= 'a' - 'A';
            if (a >= 'A') a -= 'A' - 10;
            else a -= '0';
            if (b >= 'a') b -= 'a' - 'A';
            if (b >= 'A') b -= 'A' - 10;
            else b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
            written++;
        } else {
            *dst++ = *src++;
            written++;
        }
    }

    // Null-terminate the destination buffer
    *dst = '\0';
}
