#ifndef FAST_STR_H
#define FAST_STR_H

#ifdef __cplusplus
extern "C" {
#endif

// Use AVX/SSE to do case-insensitive char* comparison.
int fast_strcasecmp(const char* s1, const char* s2);

#ifdef __cplusplus
}
#endif

#endif /* FAST_STR_H */
