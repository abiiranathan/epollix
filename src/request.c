#include "../include/request.h"
#include "../include/method.h"
#include "../include/url.h"

#include <assert.h>
#include <solidc/cstr.h>
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
    request->body_length = content_length;
    request->url = NULL;
    request->multipart = NULL;

    parse_headers(request, data->data, &header_end_idx, &content_length);

    // Get the Host header and compose the full url
    const char* host = find_header(request->headers, request->header_length, "Host");
    if (!host) {
        fprintf(stderr, "Host header not found in the request\n");
        return NULL;
    }

    if (!is_safe_method(info->httpMethod)) {
        MultipartForm* multipart = arena_alloc(arena, sizeof(MultipartForm));
        if (!multipart) {
            fprintf(stderr, "arena_alloc(): error allocating MultipartForm form\n");
            return NULL;
        }

        request->multipart = multipart;
        memset(request->multipart->files, 0, MAX_UPLOAD_FILES * sizeof(FileHeader));
        request->multipart->num_files = 0;
        request->multipart->error = FE_SUCCESS;
        request->multipart->form = NULL;
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
        memcpy((char*)request->body, data->data + header_end_idx, content_length);
    }

    return request;
}

// ========== FORM AND FILE PROCESSING===================
typedef enum {
    STATE_BOUNDARY,
    STATE_HEADER,
    STATE_KEY,
    STATE_VALUE,
    STATE_FILENAME,
    STATE_FILE_MIME_HEADER,
    STATE_MIMETYPE,
    STATE_FILE_BODY,
    STATE_END
} State;

const char* CONTENT_TYPE_URLENCODE = "application/x-www-form-urlencoded";
const char* CONTENT_TYPE_MULTIPART = "multipart/form-data";

static inline void set_form_error(FormError* error, FormError value) {
    if (error != NULL) {
        *error = value;
    }
}

// Get the error message for the given error
const char* get_form_error(FormError error) {
    switch (error) {
        case FE_SUCCESS:
            return "Success";
        case FE_EMPTY_REQUEST_BODY:
            return "Request body is required and is empty";
        case FE_MISSING_CONTENT_TYPE:
            return "Missing Content-Type header";
        case FE_INVALID_CONTENT_TYPE:
            return "Invalid Content-Type header";
        case FE_METHOD_NOT_ALLOWED:
            return "Method not allowed";
        case FE_MEMORY_ALLOCATION_FAILED:
            return "Memory allocation failed";
        case FE_INVALID_BOUNDARY:
            return "Invalid boundary";
        case FE_FILE_TOO_BIG:
            return "File exceeds maximum allowed size";
        default:
            return "Unknown error";
    }
}

static void parse_multipart_form_data_helper(Request* request, char* data, char* boundary) {
    // Set the form
    map* form = map_create(32, key_compare_char_ptr);
    if (!form) {
        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
        return;
    }
    request->multipart->form = form;

    State state = STATE_BOUNDARY;
    const char* ptr = data;
    const char* key_start = NULL;
    const char* value_start = NULL;

    char key[MAX_FILE_HEADER_FIELDNAME] = {0};
    char value[MAX_FORM_TEXT_LENGTH] = {0};
    char filename[MAX_FILE_HEADER_FILENAME] = {0};
    char mimetype[MAX_FILE_HEADER_MIME] = {0};

    // Current file in State transitions
    FileHeader header = {.filesize = 0, .start_pos = 0};

    size_t boundary_length = strlen(boundary);
    while (*ptr != '\0') {
        switch (state) {
            case STATE_BOUNDARY:
                if (strncmp(ptr, boundary, boundary_length) == 0) {
                    state = STATE_HEADER;
                    ptr += boundary_length;

                    while (*ptr == '-' || *ptr == '\r' || *ptr == '\n') {
                        ptr++;  // Skip extra characters after boundary
                    }
                } else {
                    ptr++;
                }
                break;

            case STATE_HEADER:
                if (strncmp(ptr, "Content-Disposition:", 20) == 0) {
                    ptr = strstr(ptr, "name=\"") + 6;
                    key_start = ptr;
                    state = STATE_KEY;
                } else {
                    ptr++;
                }
                break;

            case STATE_KEY:
                if (*ptr == '"' && key_start != NULL) {
                    size_t key_length = ptr - key_start;
                    if (key_length >= MAX_FILE_HEADER_FIELDNAME) {
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }
                    strncpy(key, key_start, key_length);
                    key[key_length] = '\0';  // Ensure null-termination

                    if (strncmp(ptr, "\"; filename=\"", 13) == 0) {
                        strncpy(header.field_name, key, key_length);
                        header.field_name[key_length] = '\0';  // Ensure null-termination
                        ptr = strstr(ptr, "; filename=\"") + 12;
                        key_start = ptr;
                        state = STATE_FILENAME;
                    } else {
                        while (*ptr != '\n') {
                            ptr++;
                        }
                        ptr++;
                        if (*ptr == '\r' && *(ptr + 1) == '\n') {
                            ptr += 2;
                        }
                        value_start = ptr;
                        state = STATE_VALUE;
                    }
                } else {
                    ptr++;
                }
                break;

            case STATE_VALUE:
                if ((strncmp(ptr, "\r\n--", 4) == 0 || strncmp(ptr, boundary, boundary_length) == 0) &&
                    value_start != NULL) {
                    size_t value_length = ptr - value_start;
                    if (value_length >= MAX_FORM_TEXT_LENGTH) {
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }
                    strncpy(value, value_start, value_length);
                    value[value_length] = '\0';  // Ensure null-termination
                    map_set(request->multipart->form, strdup(key), strdup(value));
                    state = STATE_BOUNDARY;
                    while (*ptr == '\r' || *ptr == '\n') {
                        ptr++;  // Skip CRLF characters
                    }
                } else {
                    ptr++;
                }
                break;

            case STATE_FILENAME:
                if (*ptr == '"' && key_start != NULL) {
                    size_t filename_length = ptr - key_start;
                    if (filename_length >= MAX_FILE_HEADER_FILENAME) {
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }
                    strncpy(filename, key_start, filename_length);
                    filename[filename_length] = '\0';  // Ensure null-termination
                    strncpy(header.filename, filename, filename_length);
                    header.filename[filename_length] = '\0';  // Ensure null-termination
                    while (*ptr != '\n') {
                        ptr++;
                    }
                    ptr++;
                    if (*ptr == '\r' && *(ptr + 1) == '\n') {
                        ptr += 2;
                    }
                    state = STATE_FILE_MIME_HEADER;
                } else {
                    ptr++;
                }
                break;

            case STATE_FILE_MIME_HEADER:
                if (strncmp(ptr, "Content-Type: ", 14) == 0) {
                    ptr = strstr(ptr, "Content-Type: ") + 14;
                    state = STATE_MIMETYPE;
                } else {
                    ptr++;
                }
                break;

            case STATE_MIMETYPE: {
                size_t mimetype_len = 0;
                value_start = ptr;
                while (*ptr != '\r' && *ptr != '\n') {
                    mimetype_len++;
                    ptr++;
                }
                if (mimetype_len >= MAX_FILE_HEADER_MIME) {
                    set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                    return;
                }
                strncpy(mimetype, value_start, mimetype_len);
                mimetype[mimetype_len] = '\0';  // Ensure null-termination
                strncpy(header.mimetype, mimetype, mimetype_len);
                header.mimetype[mimetype_len] = '\0';  // Ensure null-termination
                while (*ptr != '\n') {
                    ptr++;
                }
                ptr++;
                while (*ptr == '\r' && *(ptr + 1) == '\n') {
                    ptr += 2;
                }
                if (mimetype[0] == '\0' || memcmp(ptr, boundary, boundary_length) == 0) {
                    state = STATE_BOUNDARY;
                } else {
                    state = STATE_FILE_BODY;
                }
            } break;

            case STATE_FILE_BODY:
                header.start_pos = ptr - data;
                size_t endpos = 0;
                char* endptr = strstr(ptr, boundary);
                if (endptr == NULL) {
                    set_form_error(&request->multipart->error, FE_INVALID_BOUNDARY);
                    return;
                } else {
                    endpos = endptr - data;
                }

                // remove CRLF from the end of the file
                endpos -= 2;

                size_t file_size = endpos - header.start_pos;  // Skip CRLF
                header.filesize = file_size;
                if (file_size > MAX_FILE_SIZE || request->multipart->num_files >= MAX_UPLOAD_FILES) {
                    set_form_error(&request->multipart->error, FE_FILE_TOO_BIG);
                    return;
                }
                request->multipart->files[request->multipart->num_files++] = header;
                while (*ptr == '\r' && *(ptr + 1) == '\n') {
                    ptr += 2;
                }
                state = STATE_BOUNDARY;
                break;

            case STATE_END:
                break;
        }
    }
}

// Parse form data from the request body if the content type is application/x-www-form-urlencoded
static void parse_urlencoded(Request* request) {
    const char* content_type = find_header(request->headers, request->header_length, "Content-Type");
    if (content_type == NULL) {
        set_form_error(&request->multipart->error, FE_MISSING_CONTENT_TYPE);
        return;
    }

    if (strncmp(content_type, CONTENT_TYPE_URLENCODE, strlen(CONTENT_TYPE_URLENCODE)) != 0) {
        set_form_error(&request->multipart->error, FE_INVALID_CONTENT_TYPE);
        return;
    }

    map* form = map_create(32, key_compare_char_ptr);
    char* key = NULL;
    char* value = NULL;
    char *save_ptr, *save_ptr2;

    char* body = strdup(request->body);
    if (!body) {
        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
        return;
    }

    char* token = strtok_r(body, "&", &save_ptr);
    while (token != NULL) {
        key = strtok_r(token, "=", &save_ptr2);
        value = strtok_r(NULL, "=", &save_ptr2);

        if (key != NULL && value != NULL) {
            char* field_name = strdup(key);
            assert(field_name != NULL);

            char* field_value = strdup(value);
            assert(field_value != NULL);

            if (map_get(form, field_name) == NULL) {
                // don't overwrite existing keys
                map_set(form, field_name, field_value);
            } else {
                free(field_name);
                free(field_value);
            }
        }

        token = strtok_r(NULL, "&", &save_ptr);
    }
}

// Parse form data from the request body based on the content type
void parse_form(Request* request) {
    if (request->body == NULL || request->multipart == NULL) {
        set_form_error(&request->multipart->error, FE_EMPTY_REQUEST_BODY);
        return;
    }

    if (is_safe_method(request->method)) {
        set_form_error(&request->multipart->error, FE_METHOD_NOT_ALLOWED);
        return;
    }

    const char* content_type_header = find_header(request->headers, request->header_length, "Content-Type");
    if (content_type_header == NULL) {
        set_form_error(&request->multipart->error, FE_MISSING_CONTENT_TYPE);
        return;
    }

    if (strncmp(content_type_header, CONTENT_TYPE_URLENCODE, strlen(CONTENT_TYPE_URLENCODE)) == 0) {
        parse_urlencoded(request);
        return;
    }

    char content_type[FORM_BOUNDARY_SIZE] = {0};
    char boundary[FORM_BOUNDARY_SIZE] = {0};

    char* body = strdup(request->body);
    if (!body) {
        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
        return;
    }

    if (sscanf(content_type_header, "%127[^;]; boundary=%127s", content_type, boundary) == 2) {
        if (strncmp(content_type, CONTENT_TYPE_MULTIPART, strlen(CONTENT_TYPE_MULTIPART)) == 0) {
            // Browsers have diferrent behavior for the boundary.
            // Some browsers add extra "--" at the start of the boundary.
            // So, we need to check for both cases.
            // This is the case with Google Chrome
            if (strncmp(body, "------", 6) == 0 && strncmp(boundary, "------", 6) != 0) {
                char new_boundary[132] = "--";
                strncat(new_boundary, boundary, FORM_BOUNDARY_SIZE);
                parse_multipart_form_data_helper(request, body, new_boundary);
            } else {
                parse_multipart_form_data_helper(request, body, boundary);
            }
        }
    } else {
        set_form_error(&request->multipart->error, FE_INVALID_CONTENT_TYPE);
    }

    free(body);
}

// Get the file contents from the file header.
char* get_file_contents(FileHeader header, Request* req) {
    if (req->body == NULL)
        return NULL;

    if (header.start_pos == 0 || header.filesize == 0) {
        fprintf(stderr, "FileHeader is not valid\n");
        return NULL;
    }

    char* bytes = malloc(header.filesize);
    if (!bytes) {
        perror("malloc");
        return NULL;
    }

    memcpy(bytes, req->body + header.start_pos, header.filesize);
    // we don't null-terminate the file contents
    // as it may contain binary data
    return bytes;
}

// Save file.
bool save_file_to_disk(const char* filename, FileHeader header, Request* req) {
    if (req->body == NULL)
        return false;

    if (header.start_pos == 0 || header.filesize == 0) {
        fprintf(stderr, "FileHeader is not valid\n");
        return false;
    }

    // Use cross-platform file_open from solidc
    FILE* f = fopen(filename, "w");
    if (!f) {
        perror("fopen");
        return false;
    }

    char* data = (char*)get_file_contents(header, req);
    if (!data) {
        fclose(f);
        return false;
    }

    size_t w = fwrite(data, 1, header.filesize, f);
    fclose(f);
    free(data);

    if (w < header.filesize) {
        perror("write");
    }
    return w == header.filesize;
}

// Free elements allocated in multipart.
// multipart itself is allocated in the arena and should not be freed.
static void multipart_free(MultipartForm* multipart) {
    if (multipart == NULL)
        return;

    if (multipart->form) {
        // Free the map and all keys and values representing fields
        map_destroy(multipart->form, true);
        multipart->form = NULL;
    }
}

// get_form_files returns a FileHeader(s) matching a given name.
void get_form_files(const char* field_name, Request* request, FileHeader headers[MAX_UPLOAD_FILES],
                    size_t num_files[static 1]) {

    size_t index = 0;
    for (size_t i = 0; i < (request->multipart->num_files && i < MAX_UPLOAD_FILES); i++) {
        char* name = request->multipart->files[i].field_name;
        size_t file_size = request->multipart->files[i].filesize;

        if (strcmp(name, field_name) == 0 && file_size > 0) {
            FileHeader h;
            h = (FileHeader){.filesize = file_size, .start_pos = request->multipart->files[i].start_pos};
            strcpy(h.field_name, name);
            strcpy(h.mimetype, request->multipart->files[i].mimetype);
            strcpy(h.filename, request->multipart->files[i].filename);

            headers[index++] = h;
            (*num_files)++;
        }
    }
}

// Free elements allocated in multipart.
// multipart itself is allocated in the arena and should not be freed.
// Free request URL elements and multipart form if any.
void request_destroy(Request* request) {
    if (!request)
        return;
    url_free(request->url);

    if (request->multipart)
        multipart_free(request->multipart);

    // No need to free req body as it's allocated in the arena.
    request = NULL;
}
