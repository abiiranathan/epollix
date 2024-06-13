#include "request.h"

#include <assert.h>
#include <solidc/cstr.h>
#include <solidc/file.h>
#include <stdlib.h>
#include <string.h>

#include "method.h"
#include "url.h"

static const char* LF = "\r\n";
static const char* DOUBLE_LF = "\r\n\r\n";
const char* SCHEME = "http";

#define FORM_BOUNDARY_SIZE 128
#define HEADER_CAPACITY 32

static size_t parse_int(const char* str) {
    char* endptr;
    size_t value = strtoul(str, &endptr, 10);
    if (*endptr != '\0' || value == ULONG_MAX) {
        return 0;
    }
    return value;
}

Header** parse_headers(Arena* arena, cstr* data, size_t* num_headers, size_t* header_end_idx, HttpMethod method,
                       size_t* content_length) {
    char* header_start = NULL;
    char* header_end = NULL;
    size_t start_pos, end_pos;

    const char* req_data = data->data;

    // Parse headers from the request
    if ((header_start = strstr(req_data, LF)) == NULL) {
        fprintf(stderr, "cannot parse header start: Invalid HTTP format\n");
        return NULL;
    }

    if ((header_end = strstr(req_data, DOUBLE_LF)) == NULL) {
        fprintf(stderr, "cannot parse header end: Invalid HTTP format\n");
        return NULL;
    }

    // Get the position in request data for start of headers
    start_pos = (header_start - req_data) + 2;   // Skip LF
    end_pos = header_end - req_data;             // Up to DOUBLE_LF(start of body)
    size_t header_length = end_pos - start_pos;  // Length of the header substring

    cstr* headerSegment = cstr_substr(arena, data, start_pos, header_length);
    if (headerSegment == NULL) {
        fprintf(stderr, "cstr_substr(): error parsing header substring\n");
        return NULL;
    }

    size_t num_splits;
    cstr** header_lines = cstr_split_at(arena, headerSegment, LF, HEADER_CAPACITY, &num_splits);
    if (header_lines == NULL) {
        fprintf(stderr, "cstr_split_at(): error parsing header lines\n");
        return NULL;
    }

    bool safe_http_method = is_safe_method(method);
    Header** headers = arena_alloc(arena, sizeof(Header*) * MAX_REQ_HEADERS);
    if (headers == NULL) {
        fprintf(stderr, "arena_alloc(): error allocating headers\n");
        return NULL;
    }

    size_t header_index = 0;
    bool content_length_found = false;
    if (num_splits > 0) {
        for (size_t i = 0; (i < num_splits && i < MAX_REQ_HEADERS); i++) {
            Header* header = header_fromstring(arena, header_lines[i]);
            if (header == NULL) {
                fprintf(stderr, "header_fromstring(): error parsing header: %s\n", header_lines[i]->data);
                continue;
            }

            headers[header_index++] = header;

            // Skip getting content-length if already found
            if (content_length_found) {
                continue;
            }

            // No point getting content-length on GET, OPTIONS methods...
            if (!safe_http_method && strcasecmp(header->name->data, "Content-Length") == 0) {
                size_t value = parse_int(header->value->data);
                if (value == 0) {
                    fprintf(stderr, "Invalid Content-Length header\n");
                    return NULL;
                }
                *content_length = value;
                content_length_found = true;
            }
        }
    }

    if (!content_length_found && !safe_http_method) {
        fprintf(stderr, "Content-Length header not found in request\n");
        return NULL;
    }

    *header_end_idx = end_pos;
    *num_headers = header_index;
    return headers;
}

Request* request_parse_http(Arena* arena, cstr* data, HttpInfo* info) {
    size_t header_end_idx = 0;
    size_t content_length = 0;
    size_t num_headers = 0;

    Request* request = arena_alloc(arena, sizeof(Request));
    if (!request) {
        fprintf(stderr, "arena_alloc(): error allocating request\n");
        return NULL;
    }

    // Parse the headers
    request->headers = parse_headers(arena, data, &num_headers, &header_end_idx, info->httpMethod, &content_length);
    if (!request->headers || num_headers == 0) {
        fprintf(stderr, "parse_headers(): error parsing headers\n");
        return NULL;
    }

    request->method = info->httpMethod;
    request->header_length = num_headers;
    request->body = NULL;
    request->body_length = content_length;
    request->url = NULL;
    request->multipart = NULL;

    if (!is_safe_method(info->httpMethod)) {
        MultipartForm* multipart = arena_alloc(arena, sizeof(MultipartForm));
        if (!multipart) {
            fprintf(stderr, "arena_alloc(): error allocating MultipartForm form\n");
            return NULL;
        }

        request->multipart = multipart;
        request->multipart->files = NULL;
        request->multipart->num_files = 0;
        request->multipart->error = FE_SUCCESS;
        request->multipart->form = NULL;
    }

    // Get the Host header and compose the full url
    cstr* host = headers_loopup(request->headers, num_headers, "host");
    if (!host) {
        fprintf(stderr, "Host header not found\n");
        return NULL;
    }

    char url_string[URL_MAX_LENGTH] = {0};
    int nwritten = snprintf(url_string, sizeof(url_string), "%s://%s%s", SCHEME, host->data, info->path);
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

    // Allocate the body of the request if any and possible.
    // POST, PUT, PATCH, DELETE
    if (!is_safe_method(info->httpMethod) && content_length > 0) {
        request->body = (char*)arena_alloc(arena, content_length + 1);
        if (!request->body) {
            fprintf(stderr, "arena_alloc(): error allocating request body\n");
            return NULL;
        }

        size_t body_offset = header_end_idx + 4;  // Skip DOBLE LF after headers
        memcpy((char*)request->body, data->data + body_offset, content_length);
    }

    return request;
}

const char* find_req_header(Request* req, const char* name, int* index) {
    for (size_t i = 0; i < req->header_length; i++) {
        if (strcasecmp(name, req->headers[i]->name->data) == 0) {
            if (index) {
                *index = i;
            }
            return req->headers[i]->value->data;
        }
    }
    return NULL;
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

    // Set the files, with default capacity of 4
    size_t file_capacity = 4;
    request->multipart->files = calloc(file_capacity, sizeof(FileHeader));
    if (!request->multipart->files) {
        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
        return;
    }

    State state = STATE_BOUNDARY;
    const char* ptr = data;
    const char* key_start = NULL;
    const char* value_start = NULL;
    char* key = NULL;
    char* value = NULL;
    char* filename = NULL;
    char* mimetype = NULL;

    // Current file in State transitions
    FileHeader header = {.filesize = 0, .start_pos = 0};

    size_t boundary_length = strlen(boundary);
    while (*ptr != '\0') {
        switch (state) {
            case STATE_BOUNDARY:
                if (strncmp(ptr, boundary, boundary_length) == 0) {
                    state = STATE_HEADER;
                    ptr += boundary_length;
                    while (*ptr == '-' || *ptr == '\r' || *ptr == '\n')
                        ptr++;  // Skip extra characters after boundary
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
                if (*ptr == '"') {
                    size_t key_length = ptr - key_start;
                    key = (char*)malloc(key_length + 1);
                    if (!key) {
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }
                    strncpy(key, key_start, key_length);
                    key[key_length] = '\0';

                    // Check if we have a filename="name" next in case its a file.
                    if (strncmp(ptr, "\"; filename=\"", 13) == 0) {
                        // Store the field name in header
                        header.field_name = key;

                        // Switch state to process filename
                        ptr = strstr(ptr, "; filename=\"") + 12;
                        key_start = ptr;
                        state = STATE_FILENAME;
                    } else {
                        // Move to the end of the line
                        while (*ptr != '\n')
                            ptr++;

                        ptr++;  // Skip the newline character

                        // consume the leading CRLF before value
                        if (*ptr == '\r' && *(ptr + 1) == '\n')
                            ptr += 2;

                        value_start = ptr;
                        state = STATE_VALUE;
                    }
                } else {
                    ptr++;
                }
                break;
            case STATE_VALUE:
                if (strncmp(ptr, "\r\n--", 4) == 0 || strncmp(ptr, boundary, boundary_length) == 0) {
                    size_t value_length = ptr - value_start;
                    value = (char*)malloc(value_length + 1);
                    if (!value) {
                        free(key);
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }
                    strncpy(value, value_start, value_length);
                    value[value_length] = '\0';

                    // Save the key-value pair
                    char* key_copy = strdup(key);
                    char* value_copy = strdup(value);
                    if (!key_copy || !value_copy) {
                        if (key_copy)
                            free(key_copy);
                        if (value_copy)
                            free(value_copy);
                        free(key);
                        free(value);
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }

                    // printf("Key: %s, Value: %s\n\n", key_copy, value_copy);

                    map_set(request->multipart->form, key_copy, value_copy);

                    free(key);
                    free(value);

                    state = STATE_BOUNDARY;
                    while (*ptr == '\r' || *ptr == '\n')
                        ptr++;  // Skip CRLF characters
                } else {
                    ptr++;
                }
                break;
            case STATE_FILENAME:
                if (*ptr == '"') {
                    size_t filename_length = ptr - key_start;

                    filename = (char*)malloc(filename_length + 1);
                    if (!filename) {
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                        return;
                    }

                    strncpy(filename, key_start, filename_length);
                    filename[filename_length] = '\0';
                    header.filename = filename;

                    // printf("parsed filename: %s\n", filename);

                    // Move to the end of the line
                    while (*ptr != '\n')
                        ptr++;

                    ptr++;  // Skip the newline character

                    // consume the leading CRLF before value
                    if (*ptr == '\r' && *(ptr + 1) == '\n')
                        ptr += 2;

                    state = STATE_FILE_MIME_HEADER;
                    // puts("[ENTERING STATE_FILE_MIME_HEADER]");
                    // printf("ptr: %s\n", ptr);
                } else {
                    ptr++;
                }
                break;
            case STATE_FILE_MIME_HEADER: {
                if (strncmp(ptr, "Content-Type: ", 14) == 0) {
                    ptr = strstr(ptr, "Content-Type: ") + 14;
                    state = STATE_MIMETYPE;
                    // printf("Processing mimtype starting at: %s\n", ptr);
                } else {
                    ptr++;
                }
            } break;
            case STATE_MIMETYPE: {
                size_t mimetype_len = 0;
                value_start = ptr;

                while (*ptr != '\r' && *ptr != '\n') {
                    mimetype_len++;
                    ptr++;
                }

                // puts("[EXITING MIME LOOP]");
                // printf("Mime length: %zu\n", mimetype_len);
                // printf("ptr: %s\n", ptr);

                mimetype = (char*)malloc(mimetype_len + 1);
                if (!mimetype) {
                    set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                    return;
                }

                // text/csv
                strncpy(mimetype, value_start, mimetype_len);
                mimetype[mimetype_len] = '\0';
                header.mimetype = mimetype;
                // printf("Mime type: %s\n", mimetype);

                // Move to the end of the line
                while (*ptr != '\n')
                    ptr++;

                ptr++;  // Skip the newline character

                // consume the leading CRLF before bytes of the file
                while (((*ptr == '\r' && *(ptr + 1) == '\n'))) {
                    ptr += 2;
                }

                // If it's an empty filename or the file is empty
                // We use memcmp to handle bytes properly.
                if (mimetype[0] == '\0' || mimetype[1] == ' ' || memcmp(ptr, boundary, boundary_length) == 0) {
                    free(filename);
                    free(mimetype);
                    state = STATE_BOUNDARY;
                } else {
                    // If the file is empty skip it
                    state = STATE_FILE_BODY;
                }
            } break;
            case STATE_FILE_BODY:
                header.start_pos = ptr - data;
                size_t endpos = 0;

                // endoffset for the file data
                // we can't do pointer arithmentic with binary data :)
                // Apparently strstr is binary safe!
                char* endptr = strstr(ptr, boundary);
                if (endptr == NULL) {
                    // Likely this is a binary file.
                    FILE* fp = fopen("temp.png", "wb");

                    while (*ptr) {
                        fputc(*ptr, fp);
                        ptr++;
                    }
                    fclose(fp);
                    return;
                } else {
                    endpos = endptr - data;
                }

                printf("==== START POS: %zu\n", header.start_pos);
                printf("====   END POS: %zu\n", endpos);
                printf("==== FILE SIZE: %zu\n", endpos - header.start_pos);

                // Compute the file size
                size_t file_size = endpos - header.start_pos;
                header.filesize = file_size;
                if (file_size > MAX_FILE_SIZE) {
                    fprintf(stderr, "File %s exeeds maximum file size of %d\n", header.filename, MAX_FILE_SIZE);
                    set_form_error(&request->multipart->error, FE_FILE_TOO_BIG);
                }

                //  ========= Ensure enough memory for files
                if (request->multipart->num_files >= file_capacity) {
                    file_capacity *= 2;
                    FileHeader* new_headers = realloc(request->multipart->files, file_capacity);

                    if (new_headers == NULL) {
                        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);

                        // Free already allocated files memory
                        fprintf(stderr, "unable to realloc memory for files\n");
                        for (size_t i = 0; i < request->multipart->num_files; i++) {
                            free(request->multipart->files[i].filename);
                            free(request->multipart->files[i].field_name);
                        }
                        free(request->multipart->files);
                        return;
                    }

                    // Memory reallocation was successful
                    request->multipart->files = new_headers;
                }

                request->multipart->files[request->multipart->num_files++] = header;

                // consume the trailing CRLF before the next boundary
                while (((*ptr == '\r' && *(ptr + 1) == '\n'))) {
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
    int i = -1;
    const char* content_type = find_req_header(request, "Content-Type", &i);
    if (content_type == NULL || i == -1) {
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

    // TODO: modify body of request to save memory
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
            if (field_name == NULL) {
                set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                return;
            }
            char* field_value = strdup(value);
            if (field_value == NULL) {
                set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
                return;
            }

            map_set(form, field_name, field_value);
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

    char* body = strdup(request->body);
    if (!body) {
        set_form_error(&request->multipart->error, FE_MEMORY_ALLOCATION_FAILED);
        return;
    }

    if (is_safe_method(request->method)) {
        set_form_error(&request->multipart->error, FE_METHOD_NOT_ALLOWED);
        return;
    }

    int i = -1;
    const char* ct_header = find_req_header(request, "Content-Type", &i);
    if (ct_header == NULL || i == -1) {
        set_form_error(&request->multipart->error, FE_MISSING_CONTENT_TYPE);
        return;
    }

    if (strncmp(ct_header, CONTENT_TYPE_URLENCODE, strlen(CONTENT_TYPE_URLENCODE)) == 0) {
        parse_urlencoded(request);
        return;
    }

    char content_type[FORM_BOUNDARY_SIZE] = {0};
    char boundary[FORM_BOUNDARY_SIZE] = {0};

    if (sscanf(ct_header, "%127[^;]; boundary=%127s", content_type, boundary) == 2) {
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
    bytes[header.filesize] = '\0';
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
    FILE* f = fopen(filename, "wb");
    if (!f) {
        perror("fopen");
        return false;
    }

    char* data = (char*)get_file_contents(header, req);
    if (!data) {
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
    if (multipart->form) {
        // Free the map and all keys and values representing fields
        map_destroy(multipart->form, true);
    }

    if (multipart->files) {
        for (size_t i = 0; i < multipart->num_files; i++) {
            free(multipart->files[i].filename);
            free(multipart->files[i].field_name);
        }
        free(multipart->files);
    }
}

// get_form_files returns a FileHeader(s) matching a given name.
FileHeader* get_form_files(const char* field_name, Request* request, size_t num_files[static 1]) {
    int matches = 0;
    for (size_t i = 0; i < request->multipart->num_files; i++) {
        const char* name = request->multipart->files[i].field_name;
        size_t file_size = request->multipart->files[i].filesize;
        if (strcmp(name, field_name) == 0 && file_size > 0) {
            matches++;
        }
    }

    if (matches == 0) {
        *num_files = 0;
        return NULL;
    }

    FileHeader* headers = calloc(matches, sizeof(FileHeader));
    if (!headers) {
        perror("calloc");
        return NULL;
    }

    size_t index = 0;
    for (size_t i = 0; i < request->multipart->num_files; i++) {
        char* name = request->multipart->files[i].field_name;
        size_t file_size = request->multipart->files[i].filesize;

        if (strcmp(name, field_name) == 0 && file_size > 0) {
            headers[index++] = (FileHeader){
                .field_name = name,
                .filesize = file_size,
                .filename = request->multipart->files[i].filename,
                .mimetype = request->multipart->files[i].mimetype,
                .start_pos = request->multipart->files[i].start_pos,
            };
        }
    }

    *num_files = matches;
    return headers;
}

// Free elements allocated in multipart.
// multipart itself is allocated in the arena and should not be freed.
// Free request URL elements and multipart form if any.
void request_destroy(Request* request) {
    url_free(request->url);
    multipart_free(request->multipart);

    // No need to free req body as it's allocated in the arena.
}
