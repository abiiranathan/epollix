#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../include/logging.h"
#include "../include/mime.h"
#include "../include/fast_str.h"

typedef struct {
    char* filename;
    char* expected_content_type;
} TestCase;

static void run_test(TestCase test) {
    const char* actual_content_type = get_mimetype(test.filename);
    if (fast_strcasecmp(actual_content_type, test.expected_content_type) != 0) {
        LOG_FATAL("Expected: %s, but got: %s", test.expected_content_type, actual_content_type);
    }
}

static void run_tests(TestCase* tests, size_t num_tests) {
    for (size_t i = 0; i < num_tests; i++) {
        run_test(tests[i]);
    }
    puts("mime_test: All tests passed!");
}

int main(void) {
    TestCase tests[] = {
        {"index.html", "text/html"},
        {"style.css", "text/css"},
        {"script.js", "application/javascript"},
        {"data.json", "application/json"},
        {"image.png", "image/png"},
        {"document.pdf", "application/pdf"},
        {"archive.zip", "application/zip"},
        {"movie.MP4", "video/mp4"},
        {"unknownfile.xyz", "application/octet-stream"},  // Test case for unknown file extension
        {"file.with.multiple.dots.txt", "text/plain"},    // Test case for multiple dots
        {"NOEXTENSION", "application/octet-stream"},      // Test case for no extension
        {"CAPITAL.EXT", "application/octet-stream"}       // Test case for unrecognized extension in uppercase
    };

    run_tests(tests, sizeof(tests) / sizeof(tests[0]));
    return 0;
}
