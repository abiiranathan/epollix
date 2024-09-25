#include "../src/epollix.c"
#include "../include/logging.h"
#include "constants.h"

// test parse request headers
// http_error_t parse_request_headers(request_t* req, const char* header_text, size_t length)

void test_parse_request_headers(void) {
    request_t* req = (request_t*)malloc(sizeof(request_t));
    LOG_ASSERT(req != NULL, "Failed to allocate memory for request_t");

    req->body = NULL;
    req->content_length = 0;
    req->route = NULL;
    req->query_params = map_create(10, key_compare_char_ptr);
    req->header_count = 0;
    req->path = NULL;
    req->method = M_GET;
    LOG_ASSERT(req->query_params != NULL, "Failed to create map for query_params");

    const char* header_text = "Host: localhost:8080\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n";
    size_t length = strlen(header_text);
    http_error_t result = parse_request_headers(req, header_text, length);
    LOG_ASSERT(result == http_ok, "Failed to parse request headers");

    LOG_ASSERT(strcmp(req->headers[0]->name, "Host") == 0, "Expected Host header");
    LOG_ASSERT(strcmp(req->headers[0]->value, "localhost:8080") == 0, "Expected localhost:8080");
    LOG_ASSERT(strcmp(req->headers[1]->name, "User-Agent") == 0, "Expected User-Agent header");
    LOG_ASSERT(strcmp(req->headers[1]->value, "curl/7.68.0") == 0, "Expected curl/7.68.0");
    LOG_ASSERT(strcmp(req->headers[2]->name, "Accept") == 0, "Expected Accept header");
    LOG_ASSERT(strcmp(req->headers[2]->value, "*/*") == 0, "Expected */*");

    reset_request(req);

    LOG_INFO("test_parse_request_headers passed");
}

// decode_uri
void test_decode_uri(void) {
    char* encoded = "Hello%20World%21";
    char decoded[100];
    decode_uri(encoded, decoded, sizeof(decoded));
    LOG_ASSERT(strcmp(decoded, "Hello World!") == 0, "Failed to decode URI");

    LOG_INFO("test_decode_uri passed");
}

// encode_uri
void test_encode_uri(void) {
    char* decoded = "Hello World!";
    char* encoded = encode_uri(decoded);
    bool result = strcmp(encoded, "Hello%20World%21") == 0;
    LOG_ASSERT(result, "Failed to encode URI");
    free(encoded);

    LOG_INFO("test_encode_uri passed");
}

// bool set_header(context_t* ctx, const char* name, const char* value)
void test_header_setter_and_getters(void) {
    context_t* ctx = (context_t*)malloc(sizeof(context_t));
    LOG_ASSERT(ctx != NULL, "Failed to allocate memory for context_t");

    bool ok = allocate_headers(ctx);
    LOG_ASSERT(ok, "Failed to allocate headers");
    bool result = set_header(ctx, "Content-Type", "text/html");
    LOG_ASSERT(result, "Failed to set header");

    LOG_ASSERT(strcmp(ctx->headers[0]->name, "Content-Type") == 0, "Expected Content-Type header");
    LOG_ASSERT(strcmp(ctx->headers[0]->value, "text/html") == 0, "Expected text/html");

    const char* value = find_header(ctx->headers, ctx->header_count, "Content-Type");
    LOG_ASSERT(value != NULL, "Failed to find header");

    int index = find_header_index(ctx->headers, ctx->header_count, "Content-Type");
    LOG_ASSERT(index == 0, "Failed to find header index");

    free(ctx);

    LOG_INFO("test_set_header passed");
}

// header_t header_fromstring(const char* str)
void test_header_fromstring(void) {
    const char* header_text = "Content-Type: text/html";
    header_t* header = header_fromstring(header_text);
    LOG_ASSERT(strcmp(header->name, "Content-Type") == 0, "Expected Content-Type header, got %s", header->name);
    LOG_ASSERT(strcmp(header->value, "text/html") == 0, "Expected text/html, got %s", header->value);

    free(header);
    LOG_INFO("test_header_fromstring passed");
}

// bool parse_url_query_params(char* query, map* query_params)
void test_parse_url_query_params(void) {
    map* query_params = map_create(10, key_compare_char_ptr);
    LOG_ASSERT(query_params != NULL, "Failed to create map for query_params");

    char* query = strdup("name=John&age=30&location=USA");
    LOG_ASSERT(query != NULL, "Failed to allocate memory for query");

    bool result = parse_url_query_params(query, query_params);
    LOG_ASSERT(result, "Failed to parse query params");

    const char* name = map_get(query_params, "name");
    LOG_ASSERT(name != NULL, "Failed to get name");
    LOG_ASSERT(strcmp(name, "John") == 0, "Expected John");

    const char* age = map_get(query_params, "age");
    LOG_ASSERT(age != NULL, "Failed to get age");
    LOG_ASSERT(strcmp(age, "30") == 0, "Expected 30");

    const char* location = map_get(query_params, "location");
    LOG_ASSERT(location != NULL, "Failed to get location");
    LOG_ASSERT(strcmp(location, "USA") == 0, "Expected USA");
    LOG_INFO("test_parse_url_query_params passed");

    map_destroy(query_params, true);
    free(query);
}

// test match params in params.c
void test_match_params(void) {
    const char* pattern = "/about/{name}/profile/{id}/";
    const char url[] = "/about/John Doe/profile/123/";

    PathParams pathParams = {0};
    bool matches = match_path_parameters(pattern, url, &pathParams);
    LOG_ASSERT(matches, "Failed to match params");
    LOG_ASSERT(pathParams.match_count == 2, "Expected 2 matches");

    // Get param by name
    const char* name = get_path_param(&pathParams, "name");
    const char* id = get_path_param(&pathParams, "id");

    LOG_ASSERT(name != NULL, "Failed to get name");
    LOG_ASSERT(strcmp(name, "John Doe") == 0, "Expected John Doe");

    LOG_ASSERT(id != NULL, "Failed to get id");
    LOG_ASSERT(strcmp(id, "123") == 0, "Expected 123");

    LOG_INFO("test_match_params passed");
}

int main(void) {
    test_parse_request_headers();
    test_decode_uri();
    test_encode_uri();
    test_header_setter_and_getters();
    test_header_fromstring();
    test_parse_url_query_params();
    test_match_params();

    return 0;
}
