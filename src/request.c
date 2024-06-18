#include "../include/request.h"

#include <assert.h>
#include <solidc/file.h>
#include <stdlib.h>
#include <string.h>

static const char* LF = "\r\n";
static const char* DOUBLE_LF = "\r\n\r\n";
const char* SCHEME = "http";

static size_t parse_int(const char* str) {
    char* endptr;
    size_t value = strtoul(str, &endptr, 10);
    if (*endptr != '\0' || value == ULONG_MAX) {
        return 0;
    }
    return value;
}

static void parse_url_query_params(URL* url) {
    if (url->query == NULL)
        return;

    char* query = strdup(url->query);
    if (!query) {
        return;
    }

    map* queryParams = map_create(0, key_compare_char_ptr);
    if (!queryParams) {
        free(query);
        fprintf(stderr, "Unable to allocate queryParams\n");
        return;
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

            map_set(queryParams, queryName, queryValue);
        }
        token = strtok_r(NULL, "&", &save_ptr);
    }

    free(query);

    if (success) {
        url->queryParams = queryParams;
    } else {
        map_destroy(queryParams, true);
        url->queryParams = NULL;
    }
}

// State machine states
typedef enum { STATE_HEADER_NAME, STATE_HEADER_VALUE, STATE_HEADER_END } HeaderParseState;

void parse_headers(Request* request, char* data, size_t* header_end_idx, size_t* content_length) {
    HeaderParseState state = STATE_HEADER_NAME;
    const char* req_data = data;
    size_t start_pos, endpos;

    char* header_start = strstr(req_data, LF);
    if (header_start == NULL) {
        fprintf(stderr, "cannot parse header start: Invalid HTTP format\n");
        return;
    }

    char* header_end = strstr(req_data, DOUBLE_LF);
    if (header_end == NULL) {
        fprintf(stderr, "cannot parse header end: Invalid HTTP format\n");
        return;
    }

    start_pos = (header_start - req_data) + 1;  // Skip LF

    // Remove possible leading CRLF
    if (req_data[start_pos] == '\r' || req_data[start_pos] == '\n') {
        start_pos += 1;
    }

    // Include End of Header with +2
    endpos = header_end - req_data + 2;
    size_t header_length = endpos - start_pos;
    if (header_length == 0) {
        return;
    }

    size_t count = 0;
    size_t header_name_idx = 0;
    size_t header_value_idx = 0;

    char header_name[MAX_HEADER_NAME] = {0};
    char header_value[MAX_HEADER_VALUE] = {0};

    for (size_t i = start_pos; i <= endpos; i++) {
        if (count >= MAX_REQ_HEADERS) {
            fprintf(stderr, "header_idx is too large. Max headers is %d\n", MAX_REQ_HEADERS);
            break;
        }

        switch (state) {
            case STATE_HEADER_NAME:
                if (header_name_idx >= MAX_HEADER_NAME) {
                    fprintf(stderr, "header name is too long. Max length is %d\n", MAX_HEADER_NAME);
                    while (req_data[i] != '\r' && i < endpos) {
                        i++;
                    }
                    state = STATE_HEADER_END;
                    break;
                }

                if (req_data[i] == ':') {
                    header_name[header_name_idx] = '\0';
                    header_name_idx = 0;

                    while (req_data[++i] == ' ' && i < endpos)
                        ;

                    i--;  // Move back to the first character of the value

                    state = STATE_HEADER_VALUE;
                } else {
                    header_name[header_name_idx++] = req_data[i];
                }
                break;

            case STATE_HEADER_VALUE:
                if (header_value_idx >= MAX_HEADER_VALUE) {
                    fprintf(stderr, "header value is too long. Max length is %d\n", MAX_HEADER_VALUE);
                    while (req_data[i] != '\r' && i < endpos) {
                        i++;
                    }
                    state = STATE_HEADER_END;
                    break;
                }

                // Check for CRLF
                if (req_data[i] == '\r' && i + 1 < endpos && req_data[i + 1] == '\n') {
                    header_value[header_value_idx] = '\0';
                    header_value_idx = 0;
                    request->headers[count++] = new_header(header_name, header_value);
                    state = STATE_HEADER_END;

                    if (strcasecmp(header_name, "Content-Length") == 0) {
                        *content_length = parse_int(header_value);
                    }

                    assert(*(req_data + i) == '\r');
                    assert(*(req_data + i + 1) == '\n');
                } else {
                    header_value[header_value_idx++] = req_data[i];
                }
                break;

            case STATE_HEADER_END:
                if (req_data[i] == '\n') {
                    state = STATE_HEADER_NAME;
                }
                break;
        }
    }

    request->header_length = count;
    *header_end_idx = endpos + 2;  // Skip last CRLF
}

Request* request_parse_http(Arena* arena, cstr* data, HttpInfo* info) {
    size_t header_end_idx = 0;
    size_t content_length = 0;

    Request* request = arena_alloc(arena, sizeof(Request));
    if (!request) {
        fprintf(stderr, "arena_alloc(): error allocating request\n");
        return NULL;
    }

    // Zero the memory of request headers array.
    memset(request->headers, 0, sizeof(Header*) * MAX_REQ_HEADERS);
    request->header_length = 0;
    request->method = info->httpMethod;
    request->body = NULL;
    request->url = NULL;

    parse_headers(request, data->data, &header_end_idx, &content_length);

    // Set body length after parsing headers
    request->body_length = content_length;

    // File alone: 306279
    // CTLEN: 306694
    printf("Content-Length: %zu\n", content_length);

    // Get the Host header and compose the full url
    const char* host = find_header(request->headers, request->header_length, "Host");
    if (!host) {
        fprintf(stderr, "Host header not found in the request\n");
        return NULL;
    }

    char url_string[URL_MAX_LENGTH] = {0};
    int nwritten = snprintf(url_string, sizeof(url_string), "%s://%s%s", SCHEME, host, info->path);

    // Check if the url string was truncated
    if (nwritten >= (int)sizeof(url_string)) {
        fprintf(stderr, "URL must be shorter than %d characters\n", URL_MAX_LENGTH);
        return NULL;
    }

    request->url = url_parse(arena, url_string);
    if (!request->url) {
        fprintf(stderr, "url_parse(): error parsing url\n");
        return NULL;
    }

    // Parse query and path params
    parse_url_query_params(request->url);

    // Allocate the body of the request if any and possible.
    // POST, PUT, PATCH, DELETE
    if (!is_safe_method(info->httpMethod) && content_length > 0) {
        request->body = (char*)arena_alloc(arena, content_length + 1);
        if (!request->body) {
            fprintf(stderr, "arena_alloc(): error allocating request body\n");
            return NULL;
        }

        // header end index is the start of the body
        // content_length is the length of the body
        printf("Header end idx: %zu\n", header_end_idx);
        // printf("%s\n", data->data + header_end_idx);
        memcpy((char*)request->body, data->data + header_end_idx, content_length);
    }

    return request;
}

// Free request and its allocated memory for urls.
// The request itself is allocated in the arena.
void request_destroy(Request* request) {
    if (!request)
        return;
    url_free(request->url);
    request = NULL;
}

// Get the value of the header from the request.
const char* get_content_type(Request* request) {
    return find_header(request->headers, request->header_length, "Content-Type");
}

// Parse the multipart/form-data from the request body using the RUST multipart parser.
// via FFI. It's the caller's responsibility to free the memory allocated by this function.
MultipartCode parse_multipart_form(Request* request, MultipartForm* form) {
    const char* content_type = get_content_type(request);
    if (!content_type) {
        return INVALID_CONTENTTYPE_HEADER;
    }

    char boundary[128] = {0};
    bool success = multipart_parse_boundary_from_header(content_type, boundary, sizeof(boundary));
    if (!success) {
        return INVALID_FORM_BOUNDARY;
    }

    printf("Boundary: %s\n", boundary);

    // write body to file for debugging
    FILE* file = fopen("body.txt", "wb");
    fwrite(request->body, 1, request->body_length, file);
    fclose(file);

    return multipart_parse_form(request->body, request->body_length, boundary, form);
}

// Free the memory allocate with parse_multipart_form.
void free_form_data(MultipartForm* form) {
    multipart_free_form(form);
}

// ========== URLENCODED FORM DATA FUNCTIONS =============
// Parse the urlencoded form data from the request body.
URLEncodedFormData* parse_urlencoded_form(Request* request) {
    const char* content_type = get_content_type(request);
    if (content_type == NULL || strncmp(content_type, "application/x-www-form-urlencoded", 33) != 0) {
        fprintf(stderr, "Content-Type is not application/x-www-form-urlencoded\n");
        return NULL;
    }

    URLEncodedFormData* form_data = (URLEncodedFormData*)malloc(sizeof(URLEncodedFormData));
    if (form_data == NULL) {
        fprintf(stderr, "Error allocating URLEncodedFormData\n");
        return NULL;
    }

    form_data->data = map_create(32, key_compare_char_ptr);
    if (form_data->data == NULL) {
        free(form_data);
        fprintf(stderr, "Error allocating map for URLEncodedFormData\n");
        return NULL;
    }

    char* body = strdup(request->body);
    if (!body) {
        free_urlencoded_form_data(form_data);
        fprintf(stderr, "Error allocating memory for URLEncodedFormData\n");
        return NULL;
    }

    char* key = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;
    char* token = strtok_r(body, "&", &save_ptr);

    while (token != NULL) {
        key = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* field_name = strdup(key);
            if (field_name == NULL) {
                free_urlencoded_form_data(form_data);
                fprintf(stderr, "strdup failed on field %s\n", key);
                return NULL;
            }

            char* field_value = strdup(value);
            if (field_value == NULL) {
                free(field_name);
                free_urlencoded_form_data(form_data);
                fprintf(stderr, "strdup for value failed on field %s\n", key);
                return NULL;
            }

            if (map_get(form_data->data, field_name) == NULL) {
                // don't overwrite existing keys
                map_set(form_data->data, field_name, field_value);
            } else {
                free(field_name);
                free(field_value);
            }
        }

        token = strtok_r(NULL, "&", &save_ptr);
    }

    free(body);
    return form_data;
}

// Free the memory allocated with parse_urlencoded_form.
void free_urlencoded_form_data(URLEncodedFormData* form_data) {
    map_destroy(form_data->data, true);
    free(form_data);
}

// Get the value of the key from the URLEncodedFormData.
const char* get_urlencoded_value(URLEncodedFormData* form_data, const char* key) {
    return map_get(form_data->data, (char*)key);
}
