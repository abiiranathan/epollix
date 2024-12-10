#include <ctype.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>

// Boyer-Moore implementation for strstr
char* strstr(const char* haystack, const char* needle) {
    if (!haystack || !needle) {
        return NULL;
    }

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    // Empty needle matches entire haystack
    if (needle_len == 0)
        return (char*)haystack;

    // Needle is longer than haystack
    if (haystack_len < needle_len)
        return NULL;

    // Build the bad character shift table
    int bad_char_shift[UCHAR_MAX + 1];

    // Default shift is the length of the needle
    for (int i = 0; i <= UCHAR_MAX; i++) {
        bad_char_shift[i] = needle_len;
    }

    for (size_t i = 0; i < needle_len - 1; i++) {
        bad_char_shift[(unsigned char)needle[i]] = needle_len - 1 - i;
    }

    // Search using Boyer-Moore
    size_t offset = 0;
    while (offset <= haystack_len - needle_len) {
        int i = needle_len - 1;

        // Compare characters from the end of the needle
        while (i >= 0 && needle[i] == haystack[offset + i]) {
            i--;
        }

        if (i < 0) {
            // Found match
            return (char*)(haystack + offset);
        }

        // Shift based on bad character rule
        offset += bad_char_shift[(unsigned char)haystack[offset + needle_len - 1]];
    }

    return NULL;  // No match found
}

// Case-insensitive Boyer-Moore strstr
char* boyer_moore_strcasestr(const char* haystack, const char* needle) {
    if (!haystack || !needle) {
        return NULL;
    }

    size_t haystack_len = strlen(haystack);
    size_t needle_len = strlen(needle);

    // Empty needle matches entire haystack
    if (needle_len == 0)
        return (char*)haystack;

    // Needle is longer than haystack
    if (haystack_len < needle_len)
        return NULL;

    // Build the bad character shift table
    int bad_char_shift[UCHAR_MAX + 1];

    // Default shift is the length of the needle
    for (int i = 0; i <= UCHAR_MAX; i++) {
        bad_char_shift[i] = needle_len;
    }

    for (size_t i = 0; i < needle_len - 1; i++) {
        bad_char_shift[(unsigned char)tolower(needle[i])] = needle_len - 1 - i;
        bad_char_shift[(unsigned char)toupper(needle[i])] = needle_len - 1 - i;
    }

    // Search using Boyer-Moore
    size_t offset = 0;
    while (offset <= haystack_len - needle_len) {
        int i = needle_len - 1;

        // Compare characters from the end of the needle
        while (i >= 0 && tolower(needle[i]) == tolower(haystack[offset + i])) {
            i--;
        }

        if (i < 0) {
            // Found match
            return (char*)(haystack + offset);
        }

        // Shift based on bad character rule
        offset += bad_char_shift[(unsigned char)tolower(haystack[offset + needle_len - 1])];
    }

    return NULL;  // No match found
}

// Test the Boyer-Moore strstr implementation
#if 0

#include <stdio.h>

int main() {
    const char* haystack = "This is a simple example for Boyer-Moore strstr implementation.";
    const char* needle = "Boyer-Moore";

    char* result = strstr(haystack, needle);

    if (result) {
        printf("Found at position: %ld\n", result - haystack);
    } else {
        printf("Not found.\n");
    }

    const char* haystack2 = "This is a simple example for Boyer-Moore strstr implementation.";
    const char* needle2 = "BOYER-MOORE";

    char* result2 = boyer_moore_strcasestr(haystack2, needle2);

    if (result2) {
        printf("Found at position: %ld\n", result2 - haystack2);
    } else {
        printf("Not found.\n");
    }

    return 0;
}

#endif