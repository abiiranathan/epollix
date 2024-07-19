#include "../src/epollix.c"
#include "../include/logging.h"

// test parse request headers
// http_error_t parse_request_headers(request_t* req, const char* header_text, size_t length)

void test_parse_request_headers() {
    request_t* req = (request_t*)malloc(sizeof(request_t));
    LOG_ASSERT(req != NULL, "Failed to allocate memory for request_t");

    req->body = NULL;
    req->content_length = 0;
    req->route = NULL;
    req->query_params = map_create(10, key_compare_char_ptr);
    req->header_count = 0;
    LOG_ASSERT(req->query_params != NULL, "Failed to create map for query_params");

    // Initialize request headers
    req->header_count = 0;
    memset(req->headers, 0, sizeof req->headers);

    const char* header_text = "Host: localhost:8080\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n";
    size_t length = strlen(header_text);
    http_error_t result = parse_request_headers(req, header_text, length);
    LOG_ASSERT(result == http_ok, "Failed to parse request headers");

    LOG_ASSERT(strcmp(req->headers[0].name, "Host") == 0, "Expected Host header");
    LOG_ASSERT(strcmp(req->headers[0].value, "localhost:8080") == 0, "Expected localhost:8080");
    LOG_ASSERT(strcmp(req->headers[1].name, "User-Agent") == 0, "Expected User-Agent header");
    LOG_ASSERT(strcmp(req->headers[1].value, "curl/7.68.0") == 0, "Expected curl/7.68.0");
    LOG_ASSERT(strcmp(req->headers[2].name, "Accept") == 0, "Expected Accept header");
    LOG_ASSERT(strcmp(req->headers[2].value, "*/*") == 0, "Expected */*");

    free(req);

    LOG_INFO("test_parse_request_headers passed");
}

int main(void) {
    test_parse_request_headers();
    return 0;
}