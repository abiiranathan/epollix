#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "../include/logging.h"
#include "../include/mime.h"

typedef struct {
    char* filename;
    char* expected_content_type;
} TestCase;

void run_test(TestCase test) {
    const char* actual_content_type = get_mimetype(test.filename);
    if (strcasecmp(actual_content_type, test.expected_content_type) != 0) {
        LOG_ERROR("Test failed for filename: %s", test.filename);
        LOG_ERROR("Expected: %s, but got: %s", test.expected_content_type, actual_content_type);
    } else {
        LOG_INFO("Test passed for filename: %s", test.filename);
    }
}

void run_tests(TestCase* tests, size_t num_tests) {
    for (size_t i = 0; i < num_tests; i++) {
        run_test(tests[i]);
    }
}

int main(void) {
    init_mime_hashtable();

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

    // Run the tests
    run_tests(tests, sizeof(tests) / sizeof(tests[0]));

    destroy_mime_hashtable();
    return 0;
}
