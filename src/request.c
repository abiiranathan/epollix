#include "../include/request.h"
#include "../include/fast_str.h"
#include "../include/middleware.h"
#include "../include/route.h"

#include <cpuid.h>
#include <ctype.h>
#include <errno.h>
#include <immintrin.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <xmmintrin.h>

// Not found route.
Route* notFoundRoute = NULL;

typedef enum { STATE_HEADER_NAME, STATE_HEADER_VALUE, STATE_HEADER_END } HeaderState;

extern void http_error(int client_fd, http_status status, const char* message);

// Create a new request object.
Request* request_new(int client_fd, int epoll_fd) {
    Request* req = (Request*)malloc(sizeof(Request));
    if (!req) {
        return NULL;
    }

    req->client_fd = client_fd;
    req->epoll_fd = epoll_fd;
    req->path = NULL;
    req->method = M_INVALID;
    req->route = NULL;
    req->content_length = 0;
    req->body = NULL;
    req->header_count = 0;
    req->query_params = NULL;

    req->headers = (header_t**)calloc(MAX_REQ_HEADERS, sizeof(header_t*));
    if (!req->headers) {
        free(req);
        return NULL;
    }
    return req;
}

// Clean up resources allocated for the request
void request_destroy(Request* req) {
    if (!req)
        return;

    if (req->path)
        free(req->path);

    if (req->body)
        free(req->body);

    if (req->query_params)
        map_destroy(req->query_params, true);

    for (size_t i = 0; i < req->header_count; ++i) {
        free(req->headers[i]->name);
        free(req->headers[i]->value);
        free(req->headers[i]);
    }

    free(req->headers);
    free(req);
    req = NULL;
}

// Get request header value by name.
const char* get_request_header(Request* req, const char* name) {
    return find_header(req->headers, req->header_count, name);
}

// Get the content type of the request.
const char* get_content_type(Request* req) {
    return get_request_header(req, CONTENT_TYPE_HEADER);
}

const char* get_param(Request* req, const char* name) {
    if (!req->route->params) {
        return NULL;
    }
    return get_path_param(req->route->params, name);
}

// Get the value of a query parameter by name.
const char* get_query_param(Request* req, const char* name) {
    if (!req->query_params) {
        return NULL;
    }

    return map_get(req->query_params, (void*)name);
}

static const char* http_error_string(http_error_t code) {
    switch (code) {
        case http_ok:
            return "success";
        case http_max_headers_exceeded:
            return ERR_TOO_MANY_HEADERS;
        case http_memory_alloc_failed:
            return ERR_MEMORY_ALLOC_FAILED;
    }

    return "success";
}

http_error_t parse_request_headers(Request* req, const char* header_text, size_t length) {
    const char* ptr = header_text;
    const char* end = ptr + length;

    while (ptr < end) {
        if (req->header_count >= MAX_REQ_HEADERS) {
            return http_max_headers_exceeded;
        }

        // Parse header name
        const char* colon = (const char*)memchr(ptr, ':', end - ptr);
        if (!colon)
            break;

        size_t name_len = colon - ptr;
        char* name = malloc(name_len + 1);
        if (!name) {
            return http_memory_alloc_failed;
        }

        memcpy(name, ptr, name_len);
        name[name_len] = '\0';

        // Move to header value
        ptr = colon + 1;
        while (ptr < end && *ptr == ' ')
            ptr++;

        // Parse header value
        const char* eol = (const char*)memchr(ptr, '\r', end - ptr);
        if (!eol || eol + 1 >= end || eol[1] != '\n')
            break;

        size_t value_len = eol - ptr;
        char* value = malloc(value_len + 1);
        if (!value) {
            free(name);
            return http_memory_alloc_failed;
        }

        memcpy(value, ptr, value_len);
        value[value_len] = '\0';

        header_t* header = malloc(sizeof(header_t));
        if (!header) {
            free(name);
            free(value);
            return http_memory_alloc_failed;
        }

        header->name = name;
        header->value = value;
        req->headers[req->header_count++] = header;

        ptr = eol + 2;  // Skip CRLF
    }

    return http_ok;
}

void decode_uri(const char* src, char* dst, size_t dst_size) {
    char a, b;
    // Track the number of characters written to dst
    size_t written = 0;

    while (*src && written + 1 < dst_size) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
            if (a >= 'a')
                a -= 'a' - 'A';
            if (a >= 'A')
                a -= 'A' - 10;
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a' - 'A';
            if (b >= 'A')
                b -= 'A' - 10;
            else
                b -= '0';
            *dst++ = 16 * a + b;
            src += 3;
            written++;
        } else {
            *dst++ = *src++;
            written++;
        }
    }

    // Null-terminate the destination buffer
    *dst = '\0';
}

// percent-encode a string for safe use in a URL.
// Returns an allocated char* that the caller must free after use.
char* encode_uri(const char* str) {
    // Since each character can be encoded as "%XX" (3 characters),
    // we multiply the length of the input string by 3 and add 1 for the null
    // terminator.
    size_t src_len = strlen(str);
    size_t capacity = src_len * 3 + 1;
    char* encoded_str = (char*)malloc(capacity);
    if (encoded_str == NULL) {
        perror("memory allocation failed");
        return NULL;
    }

    const char* hex = "0123456789ABCDEF";  // hexadecimal digits for percent-encoding
    size_t index = 0;                      // position in the encoded string

    // Iterate through each character in the input string
    for (size_t i = 0; i < src_len; i++) {
        unsigned char c = str[i];

        // Check if the character is safe and doesn't need encoding
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            encoded_str[index++] = c;
        } else {
            // If the character needs encoding, add '%' to the encoded string
            encoded_str[index++] = '%';

            // Convert the character to its hexadecimal
            encoded_str[index++] = hex[(c >> 4) & 0xF];  // High nibble
            encoded_str[index++] = hex[c & 0xF];         // Low nibble
        }
    }

    encoded_str[index] = '\0';
    return encoded_str;
}

// Parse the request line (first line of the HTTP request)
static bool parse_request_line(char* headers, char** method, char** uri, char** http_version, char** header_start) {
    *method = headers;
    *uri = strchr(headers, ' ');
    if (!*uri)
        return false;
    **uri = '\0';
    (*uri)++;

    *http_version = strchr(*uri, ' ');
    if (!*http_version)
        return false;
    **http_version = '\0';
    (*http_version)++;

    *header_start = boyer_moore_strstr(*http_version, "\r\n");
    if (!*header_start)
        return false;
    **header_start = '\0';
    *header_start += 2;

    return true;
}

// Parse the Content-Length header
static size_t parse_content_length(const char* header_start, const char* end_of_headers) {
    const char* content_length_header = strcasestr(header_start, "content-length:");
    if (!content_length_header || content_length_header >= end_of_headers) {
        return 0;
    }
    return strtoul(content_length_header + 15, NULL, 10);
}

bool parse_url_query_params(char* query, map* query_params) {
    map* queryParams = map_create(0, key_compare_char_ptr);
    if (!queryParams) {
        LOG_ERROR("Unable to allocate queryParams");
        return false;
    }

    char* key = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;
    bool success = true;

    char* token = strtok_r(query, "&", &save_ptr);
    while (token != NULL) {
        key = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* queryName = strdup(key);
            if (queryName == NULL) {
                perror("strdup");
                success = false;
                break;
            }

            char* queryValue = strdup(value);
            if (queryValue == NULL) {
                free(queryName);
                perror("strdup");
                success = false;
                break;
            }

            map_set(query_params, queryName, queryValue);
        }
        token = strtok_r(NULL, "&", &save_ptr);
    }
    return success;
}

// Parse the URI, extracting path and query parameters
static bool parse_uri(const char* decoded_uri, char** path, char** query, map** query_params) {
    *path = strdup(decoded_uri);
    if (!*path) {
        LOG_ERROR("malloc failed");
        return false;
    }

    *query = strchr(*path, '?');
    if (*query) {
        **query = '\0';
        (*query)++;

        *query_params = map_create(0, key_compare_char_ptr);
        if (!*query_params) {
            free(*path);
            return false;
        }

        if (!parse_url_query_params(*query, *query_params)) {
            free(*path);
            map_destroy(*query_params, true);
            return false;
        }
    } else {
        *query_params = NULL;
    }

    return true;
}

// Allocate memory for the body and read it from the socket
bool allocate_and_read_body(int client_fd, uint8_t** body, size_t body_size, size_t initial_read,
                            const char* initial_body) {
    *body = (uint8_t*)malloc(body_size + 1);
    if (!*body)
        return false;

    // copy the initial body read if any
    if (initial_read > 0) {
        memcpy(*body, initial_body, initial_read);
    }

    size_t total_read = initial_read;

    while (total_read < body_size) {
        ssize_t count = recv(client_fd, *body + total_read, body_size - total_read, 0);
        if (count == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            } else {
                perror("recv");
                free(*body);
                *body = NULL;
                return false;
            }
        } else if (count == 0) {
            break;  // EOF
        }

        total_read += count;
    }

    (*body)[total_read] = '\0';
    return true;
}

// Initialize the request structure with parsed data
void initialize_request(Request* req, uint8_t* body, size_t content_length, map* query_params, HttpMethod httpMethod,
                        const char* http_version, const char* path) {

    req->body = body;
    req->content_length = content_length;
    req->query_params = query_params;
    req->header_count = 0;
    req->method = httpMethod;

    strncpy(req->http_version, http_version, sizeof(req->http_version) - 1);
    req->http_version[sizeof(req->http_version) - 1] = '\0';

    req->path = strdup(path);
    LOG_ASSERT(req->path != NULL, "malloc failed to allocate request path");
}

// Handle the case when a route is not found
bool handle_not_found(Request* req, const char* method, const char* http_version, const char* path) {
    if (notFoundRoute) {
        req->route = notFoundRoute;
        return true;
    } else {
        fprintf(stderr, "%s - %s %s 404 Not Found\n", method, http_version, path);
        http_error(req->client_fd, StatusNotFound, "Not Found\n");
        return false;
    }
}

bool registered = false;
Route* route_notfound(Handler h) {
    if (registered) {
        LOG_FATAL("registration of more than one 404 handler\n");
    }

    notFoundRoute = route_get("__notfound__", h);
    registered = true;
    return notFoundRoute;
}

// Check if the CPU supports AVX
int check_avx() {
    unsigned int eax, ebx, ecx, edx;
    __cpuid(1, eax, ebx, ecx, edx);
    return ecx & bit_AVX;
}

__attribute__((target("avx2"))) inline void fast_bzero(void* ptr, size_t size) {
    // Use standard implementation if vector size is too small
    if (size < 32) {
        memset(ptr, 0, size);
        return;
    }

    char* p = (char*)ptr;
    size_t vec_size = size & ~31ULL;
    size_t rem_size = size & 31ULL;

    __m256i zero = _mm256_setzero_si256();

    for (size_t i = 0; i < vec_size; i += 32) {
        _mm256_storeu_si256((__m256i*)(p + i), zero);
    }

    // Handle remaining bytes
    for (size_t i = 0; i < rem_size; ++i) {
        p[vec_size + i] = 0;
    }
}

// handle the request and send response.
void process_request(Request* req) {
    int client_fd = req->client_fd;

    char headers[4096] = {};

    char* path = NULL;                  // Request path
    char* query = NULL;                 // Query string
    map* query_params = NULL;           // Query parameters
    uint8_t* body = NULL;               // Request body (dynamically allocated)
    size_t total_read = 0;              // Total bytes read
    HttpMethod httpMethod = M_INVALID;  // Http method
    http_error_t code = http_ok;        // Error code
    char decoded_uri[1024] = {};        // Decoded URI (e.g., "/path/to/resource?query=string")
    size_t header_capacity = 0;         // Size of the headers in the buffer (including the initial read)
    size_t body_size = 0;               // Size of the request body (from the Content-Length header)

    ssize_t inital_size = recv(client_fd, headers, sizeof(headers) - 1, MSG_WAITALL);
    if (inital_size <= 0) {
        goto error;
    }
    headers[inital_size] = '\0';

    char *method, *uri, *http_version, *header_start, *end_of_headers;
    if (!parse_request_line(headers, &method, &uri, &http_version, &header_start)) {
        http_error(client_fd, StatusBadRequest, ERR_INVALID_STATUS_LINE);
        goto error;
    }

    httpMethod = method_fromstring(method);
    if (httpMethod == M_INVALID) {
        http_error(client_fd, StatusBadRequest, ERR_INVALID_STATUS_LINE);
        goto error;
    }

    // memmem  is slower than strstr but safer!
    end_of_headers = (char*)memmem(headers, inital_size, "\r\n\r\n", 4);
    if (!end_of_headers) {
        http_error(client_fd, StatusBadRequest, "Invalid Http Payload");
        goto error;
    }

    header_capacity = end_of_headers - headers + 4;
    body_size = parse_content_length(header_start, end_of_headers);

    decode_uri(uri, decoded_uri, sizeof(decoded_uri));

    if (!parse_uri(decoded_uri, &path, &query, &query_params)) {
        http_error(client_fd, StatusInternalServerError, "error parsing query params");
        goto error;
    }

    req->route = default_route_matcher(httpMethod, path);
    if (req->route == NULL && !handle_not_found(req, method, http_version, path)) {
        goto error;
    }

    total_read = inital_size - header_capacity;
    if (!is_safe_method(httpMethod) && body_size > 0) {
        if (!allocate_and_read_body(client_fd, &body, body_size, total_read, headers + header_capacity)) {
            http_error(client_fd, StatusInternalServerError, "Failed to read request body");
            goto error;
        }
    }

    initialize_request(req, body, body_size, query_params, httpMethod, http_version, path);
    code = parse_request_headers(req, header_start, header_capacity - 4);
    if (code != http_ok) {
        http_error(client_fd, StatusRequestHeaderFieldsTooLarge, http_error_string(code));
        goto error;
    }

    free(path);
    return;

error:
    if (path) {
        free(path);
    }
}
