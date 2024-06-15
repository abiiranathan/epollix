#include "../include/headers.h"
#include <strings.h>

Header new_header(const char* name, const char* value) {
    Header header = {0};
    snprintf(header.name, MAX_HEADER_NAME, "%s", name);
    snprintf(header.value, MAX_HEADER_VALUE, "%s", value);
    return header;
}

void header_tostring(const Header* h, char buffer[MAX_HEADER_NAME + MAX_HEADER_VALUE + 4], size_t buffer_size) {
    if (h == NULL || buffer_size < MAX_HEADER_NAME + MAX_HEADER_VALUE + 4) {
        return;
    }
    snprintf(buffer, buffer_size, "%s: %s", h->name, h->value);
}

Header header_fromstring(const char* str) {
    size_t n = 0;  // index of the current character in the string.

    // find the index the first colon in the string.
    while (str[n] != ':' && str[n] != '\0') {
        n++;
    }

    // if the string is empty or the colon is the last character, return an empty header.
    // verify that the header is empty by checking if the name is empty.
    // i.e header.name[0] == '\0'
    if (str[n] == '\0' || n == 0 || n >= MAX_HEADER_NAME) {
        return (Header){0};
    }

    Header header = {0};

    // this will copy the name of the header. This will truncate the name if it is too long.
    snprintf(header.name, MAX_HEADER_NAME, "%s", str);
    header.name[n] = '\0';

    // skip the colon and any leading spaces.
    n++;
    while (str[n] == ' ') {
        n++;
    }

    snprintf(header.value, MAX_HEADER_VALUE, "%s", str + n);
    header.value[MAX_HEADER_VALUE - 1] = '\0';
    return header;
}

const char* find_header(Header* headers, size_t num_headers, const char* name) {
    for (size_t i = 0; i < num_headers; i++) {
        // printf("Comparing %s with %s\n", headers[i].name, name);
        if (strcasecmp(headers[i].name, name) == 0) {
            return headers[i].value;
        }
    }
    return NULL;
}

int find_header_index(Header* headers, size_t num_headers, const char* name) {
    for (size_t i = 0; i < num_headers; i++) {
        if (strcasecmp(headers[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

bool header_valid(const Header* h) {
    // Valid header if the name is not empty.
    // Value can be empty.
    return h->name[0] != '\0';
}

#ifdef TEST_HEADERS
#include <assert.h>
#include <stdio.h>

int main(void) {
    Arena* arena = arena_create(1024, 8);
    Header h = new_header("Content-Type", "application/json");
    char* str = header_tostring(arena, &h);
    assert(strcmp(str, "Content-Type: application/json") == 0);
    printf("Header to string: %s\n", str);

    Header h2 = header_fromstring("Content-Type: application/json");
    printf("Header from string: Name: %s, value: %s\n", h2.name, h2.value);

    assert(strcmp(h2.name, "Content-Type") == 0);
    assert(strcmp(h2.value, "application/json") == 0);
    Header headers[] = {new_header("Content-Type", "application/json"), new_header("Content-Length", "1024")};
    const char* value = headers_loopup(headers, 2, "Content-Type");
    printf("Header lookup: %s\n", value);
    assert(strcmp(value, "application/json") == 0);

    // Try with Host that has 2 colons
    Header h3 = header_fromstring("Host: localhost:8080");
    printf("Header from string: Name: %s, value: %s\n", h3.name, h3.value);
    assert(strcmp(h3.name, "Host") == 0);
    assert(strcmp(h3.value, "localhost:8080") == 0);

    // test with a very long header name
    Header h4 = header_fromstring(
        "This-is-a-very-long-header-name-that-would-overflow-because-it-is-very-long: localhost:8080");
    printf("Header from string: Name: %s, value: %s\n", h4.name, h4.value);
    assert(h4.name[0] == '\0');
    assert(h4.value[0] == '\0');

    arena_destroy(arena);
    return 0;
}

#endif