#include <solidc/map.h>
#include <solidc/defer.h>

#include "../include/net.h"
#include "../include/url.h"

// test parse request headers
void test_parse_request_headers(void) {
    const char* header_text = "Host: localhost:8080\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n";
    size_t length           = strlen(header_text);

    Headers* headers = kv_new();
    parse_request_headers(header_text, length, headers);
    LOG_ASSERT(headers, "Failed to parse request headers");

    const char* host_header = headers_value(headers, "Host");
    LOG_ASSERT(host_header != NULL, "Failed to get Host header");
    LOG_ASSERT(strcmp(host_header, "localhost:8080") == 0, "Expected localhost:8080");

    const char* user_agent_header = headers_value(headers, "User-Agent");
    LOG_ASSERT(user_agent_header != NULL, "Failed to get User-Agent header");
    LOG_ASSERT(strcmp(user_agent_header, "curl/7.68.0") == 0, "Expected curl/7.68.0");

    const char* accept_header = headers_value(headers, "Accept");
    LOG_ASSERT(accept_header != NULL, "Failed to get Accept header");
    LOG_ASSERT(strcmp(accept_header, "*/*") == 0, "Expected */*");

    headers_free(headers);
}

// decode_uri
void test_decode_uri_scalar(void) {
    char* encoded = "This%20is%20a%20test:%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25";
    char decoded[100];
    url_percent_decode_scalar(encoded, decoded, sizeof(decoded));
    bool result = strcmp(decoded, "This is a test:/?#[]@!$&'()*+,;=%") == 0;
    LOG_ASSERT(result, "Failed to decode URI");
}

void test_decode_uri_simd(void) {
#ifdef __AVX2__
    char* encoded = "This%20is%20a%20test:%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25";
    char decoded[100];
    url_percent_decode_simd(encoded, decoded, sizeof(decoded));
    bool result = strcmp(decoded, "This is a test:/?#[]@!$&'()*+,;=%") == 0;
    LOG_ASSERT(result, "Failed to decode URI");
#endif
}

// encode_uri
void test_encode_uri_scalar(void) {
    char* decoded = "This is a test:/?#[]@!$&'()*+,;=%";
    char encoded[100];
    url_percent_encode_scalar(decoded, encoded, sizeof(encoded));
    bool result = strcmp(encoded, "This%20is%20a%20test%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25") == 0;
    LOG_ASSERT(result, "Failed to encode URI");
}

void test_encode_uri_simd(void) {
#ifdef __AVX2__
    LOG_INFO("AVX2 not supported, skipping SIMD test");
    return;

    char* decoded = "This is a test:/?#[]@!$&'()*+,;=%";
    char encoded[100];
    url_percent_encode_simd(decoded, encoded, sizeof(encoded));
    bool result = strcmp(encoded, "This%20is%20a%20test%3A%2F%3F%23%5B%5D%40%21%24%26%27%28%29%2A%2B%2C%3B%3D%25") == 0;
    LOG_ASSERT(result, "Failed to encode URI");
#endif
}

// bool parse_url_query_params(char* query, Map* query_params)
void test_parse_url_query_params(void) {
    QueryParams* query_params = kv_new();
    LOG_ASSERT(query_params != nullptr, "Failed to create map for query_params");

    char* query = strdup("name=John&age=30&location=USA");
    LOG_ASSERT(query != nullptr, "Failed to allocate memory for query");
    bool result = parse_url_query_params(query, query_params);
    LOG_ASSERT(result, "Failed to parse query params");

    const char* name = headers_value(query_params, "name");
    LOG_ASSERT(name != nullptr, "Failed to get name");
    LOG_ASSERT(strcmp(name, "John") == 0, "Expected John");

    const char* age = headers_value(query_params, "age");
    LOG_ASSERT(age != nullptr, "Failed to get age");
    LOG_ASSERT(strcmp(age, "30") == 0, "Expected 30");

    const char* location = headers_value(query_params, "location");
    LOG_ASSERT(location != nullptr, "Failed to get location");
    LOG_ASSERT(strcmp(location, "USA") == 0, "Expected USA");

    headers_free(query_params);
    free(query);

    puts("Query Params tests passed\n");
}

// test match params in params.c
void test_match_params(void) {
    const char* pattern = "/about/{name}/profile/{id}/";
    const char url[]    = "/about/John Doe/profile/123/";

    PathParams pathParams = {0};
    bool matches          = match_path_parameters(pattern, url, &pathParams);
    LOG_ASSERT(matches, "Failed to match params");
    LOG_ASSERT(pathParams.match_count == 2, "Expected 2 matches");

    // Get param by name
    const char* name = get_path_param(&pathParams, "name");
    const char* id   = get_path_param(&pathParams, "id");

    LOG_ASSERT(name != nullptr, "Failed to get name");
    LOG_ASSERT(strcmp(name, "John Doe") == 0, "Expected John Doe");

    LOG_ASSERT(id != nullptr, "Failed to get id");
    LOG_ASSERT(strcmp(id, "123") == 0, "Expected 123");
}

int main(void) {
    test_parse_request_headers();

    test_encode_uri_scalar();
    test_decode_uri_scalar();

    test_encode_uri_simd();
    test_decode_uri_simd();

    test_parse_url_query_params();
    test_match_params();
    return 0;
}
