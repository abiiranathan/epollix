#include <ctype.h>
#include <stdint.h>
#include <immintrin.h>
#include <limits.h>
#include <ctype.h>
#include "../include/url.h"
#include "../include/fast_str.h"

static const unsigned char ASCII[256] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
    0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
    0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b,
    0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x5b, 0x5c, 0x5d, 0x5e,
    0x5f, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71,
    0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
    0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa,
    0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
    0xbe, 0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0,
    0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf, 0xe0, 0xe1, 0xe2, 0xe3,
    0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6,
    0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff};

static int fast_strcasecmp_sse(const char* s1, const char* s2) {
    static const unsigned char* const table = ASCII;
    while (1) {
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
        __m128i vec1 = _mm_loadu_si128((const __m128i*)s1);
        __m128i vec2 = _mm_loadu_si128((const __m128i*)s2);
#ifdef __clang__
#pragma clang diagnostic pop
#endif

        // Compare 16 bytes at a time
        __m128i cmp   = _mm_cmpeq_epi8(vec1, vec2);
        unsigned mask = _mm_movemask_epi8(cmp);

        if (mask != 0xFFFF) {
            // Mismatch found
            for (int i = 0; i < 16; i++) {
                unsigned char c1 = table[(unsigned char)s1[i]];
                unsigned char c2 = table[(unsigned char)s2[i]];
                if (c1 != c2) return c1 - c2;
                if (c1 == 0) return 0;
            }
        }

        // Check for null byte
        if (_mm_movemask_epi8(_mm_cmpeq_epi8(vec1, _mm_setzero_si128()))) {
            return 0;
        }

        s1 += 16;
        s2 += 16;
    }
}

// Use AVX/SSE to do case-insensitive char* comparison.
int fast_strcasecmp(const char* s1, const char* s2) {
    if (has_avx2()) {
        while (1) {
// Use AVX2 if available, else fall back to SSE.
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-align"
#endif
            __m256i v1 = _mm256_loadu_si256((const __m256i*)s1);
            __m256i v2 = _mm256_loadu_si256((const __m256i*)s2);
#ifdef __clang__
#pragma clang diagnostic pop
#endif

            // Compare 32 bytes at once
            __m256i cmp   = _mm256_cmpeq_epi8(v1, v2);
            unsigned mask = _mm256_movemask_epi8(cmp);

            if (mask != 0xFFFFFFFF) {
                // Mismatch found, check each byte
                for (int i = 0; i < 32; i++) {
                    unsigned char c1 = (unsigned char)tolower(s1[i]);
                    unsigned char c2 = (unsigned char)tolower(s2[i]);
                    if (c1 != c2) return c1 - c2;
                    if (c1 == 0) return 0;
                }
            }

            // Check for null terminator
            if (_mm256_movemask_epi8(_mm256_cmpeq_epi8(v1, _mm256_setzero_si256()))) {
                return 0;
            }

            s1 += 32;
            s2 += 32;
        }
    } else {
        return fast_strcasecmp_sse(s1, s2);
    }
}

#if 0

#include <string.h>
#include <locale.h>
#include <stdio.h>
#include <time.h>

struct TestCase {
    const char* name;
    int (*cmp)(const char*, const char*);
} cases[] = {
    {.name = "std strcasecmp", strcasecmp},
    {.name = "fast strcasecmp SSE", fast_strcasecmp_sse},
    {.name = "fast strcasecmp AVX2", fast_strcasecmp},
};

#define WARMUP_RUNS    3
#define BENCHMARK_RUNS 1000

static void benchmark_case(const struct TestCase* c) {
    printf("\nBenchmarking %s...\n", c->name);
    printf("------------------------------------------\n");

    // Test cases
    const char* str1 = "Hello, World!";
    const char* str2 = "hello, world!";
    const char* str3 = "Hello, Universe!";

    // Verify correctness first
    int result1 = c->cmp(str1, str2);
    int result2 = c->cmp(str1, str3);
    int result3 = c->cmp(str3, str1);

    printf("Correctness Tests:\n");
    printf("  'Hello' vs 'hello': %d (Expected 0)\n", result1);
    printf("  'Hello' vs 'Universe': %d (Expected >0)\n", result2);
    printf("  'Universe' vs 'Hello': %d (Expected <0)\n", result3);

    // Long string test
    const char* long_str1 = "This is a very long string to test comparison. SIMD should make this faster.";
    const char* long_str2 = "This is a very long string to test comparison. simd should make this faster.";
    printf("  Long string match: %d (Expected 0)\n", c->cmp(long_str1, long_str2));

    // Prepare 1MB test strings
    const size_t very_long_size = 1024 * 1024;
    char* very_long_str1        = malloc(very_long_size);
    char* very_long_str2        = malloc(very_long_size);
    memset(very_long_str1, 'a', very_long_size - 1);
    memset(very_long_str2, 'a', very_long_size - 1);
    very_long_str1[very_long_size - 1] = '\0';
    very_long_str2[very_long_size - 1] = '\0';

    // Change one character to test mismatch case
    very_long_str2[very_long_size / 2] = 'b';

    // Warm-up runs
    for (int i = 0; i < WARMUP_RUNS; i++) {
        c->cmp(very_long_str1, very_long_str2);
    }

    // Actual benchmark
    struct timespec start, end;
    long total_ns = 0;
    long min_ns   = LONG_MAX;
    long max_ns   = 0;

    for (int i = 0; i < BENCHMARK_RUNS; i++) {
        clock_gettime(CLOCK_MONOTONIC, &start);
        c->cmp(very_long_str1, very_long_str2);
        clock_gettime(CLOCK_MONOTONIC, &end);

        long ns = (end.tv_sec - start.tv_sec) * 1000000000 + (end.tv_nsec - start.tv_nsec);

        total_ns += ns;
        if (ns < min_ns) min_ns = ns;
        if (ns > max_ns) max_ns = ns;

        // printf("  Run %d: %ld ns (%d)\n", i + 1, ns, res);
    }

    // Calculate statistics
    double avg_ns     = (double)total_ns / BENCHMARK_RUNS;
    double avg_ms     = avg_ns / 1000000.0;
    double throughput = (very_long_size / (avg_ns / 1000000000.0)) / (1024 * 1024);

    printf("\nResults for %s:\n", c->name);
    printf("  Min:    %ld ns (%.3f ms)\n", min_ns, (double)min_ns / 1000000.0);
    printf("  Max:    %ld ns (%.3f ms)\n", max_ns, (double)max_ns / 1000000.0);
    printf("  Avg:    %.0f ns (%.3f ms)\n", avg_ns, avg_ms);
    printf("  Throughput: %.2f MB/s\n", throughput);

    free(very_long_str1);
    free(very_long_str2);
    printf("------------------------------------------\n");
}

int main() {
    setlocale(LC_ALL, "");

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        benchmark_case(&cases[i]);
    }

    return 0;
}

#endif
