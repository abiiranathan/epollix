#ifndef CPUFEATURES_H
#define CPUFEATURES_H

#include <immintrin.h>
#include <cpuid.h>

#ifdef __cplusplus
extern "C" {
#endif

// CPU feature detection structure
typedef struct {
    bool has_sse2;
    bool has_avx2;
    bool has_avx512f;
    bool has_avx512bw;
} cpu_features_t;

// Global CPU features (initialized once)
static cpu_features_t g_cpu_features = {0};
static bool g_cpu_detected           = false;

// Safe CPU feature detection
static inline void detect_cpu_features(void) {
    if (g_cpu_detected) return;

    unsigned int eax, ebx, ecx, edx;

    // Check for basic CPUID support
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        goto fallback;
    }

    // SSE2 support (bit 26 of EDX)
    g_cpu_features.has_sse2 = (edx & (1 << 26)) != 0;

    // AVX2 support requires multiple checks
    if ((ecx & (1 << 27)) && (ecx & (1 << 28))) {  // OSXSAVE and AVX
        // Check if OS supports AVX state saving
        unsigned long long xcr0;
        __asm__("xgetbv" : "=A"(xcr0) : "c"(0));
        if ((xcr0 & 0x6) == 0x6) {  // XMM and YMM state
            // Check for AVX2
            if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
                g_cpu_features.has_avx2 = (ebx & (1 << 5)) != 0;

                // AVX-512 detection
                if ((xcr0 & 0xE0) == 0xE0) {  // ZMM state support
                    g_cpu_features.has_avx512f  = (ebx & (1 << 16)) != 0;
                    g_cpu_features.has_avx512bw = (ebx & (1 << 30)) != 0;
                }
            }
        }
    }

fallback:
    g_cpu_detected = true;
}

#ifdef __cplusplus
}
#endif

#endif  // CPUFEATURES_H
