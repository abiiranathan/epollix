// ========================================================================================
// Licence: MIT                                                                           #
// File: multipart.c                                                                      #
// This file implements a finite state machine for parsing multipart/form-data            #
// from http request body.                                                                #
// I implemented this as part of my project called epollix for a web server with epoll.   #
// Find it on github at https://github.com/abiiranathan/epollix.git                       #
//                                                                                        #
// Author: Dr. Abiira Nathan                                                              #
// Date: 17 June 2024                                                                     #
//=========================================================================================
#ifndef _GNU_SOURCE
#define _GNU_SOURCE  // for memmem
#endif

#include "../include/multipart.h"
#include "../include/logging.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

// Helper function to double the capacity of files allocated in the form.
static FileHeader** realloc_files(MultipartForm* form);

// Helper function to double the capacity of fields allocated in the form.
static FormField* realloc_fields(MultipartForm* form);

static bool insert_header(MultipartForm* form, FileHeader header) {
    if (form->num_files >= INITIAL_FILE_CAPACITY) {
        if (!realloc_files(form)) {
            LOG_ERROR("Failed to reallocate files");
            return false;
        }
    }

    FileHeader* new_header = (FileHeader*)malloc(sizeof(FileHeader));
    if (!new_header) {
        LOG_ERROR("Failed to allocate memory for file header");
        return false;
    }

    // Copy the header into the new memory
    *new_header = header;

    form->files[form->num_files] = new_header;
    form->num_files++;
    return true;
}

/**
 * Parse a multipart form from the request body.
 * @param data: Request body (with out headers). Its not assumed to be null-terminated.
 * @param size: Content-Length(size of data in bytes)
 * @param boundary: Null-terminated string for the form boundary.
 * @param form: Pointer to MultipartForm struct to store the parsed form data. It is assumed
 * to be initialized well and not nullptr.
 * You can use the function parse_multipart_boundary or parse_multipart_boundary_from_header helpers
 * to get the boundary.
 * 
 * @returns: MultipartCode enum value indicating the success or failure of the operation.
 * Use the multipart_error_message function to get the error message if the code
 * is not MULTIPART_OK.
 * */
MultipartCode multipart_parse_form(const char* data, size_t size, char* boundary, MultipartForm* form) {
    size_t boundary_length = strlen(boundary);

    // Temporary variables to store state of the FSM.
    const char* ptr = data;

    const char* key_start            = nullptr;
    const char* value_start          = nullptr;
    char key[MAX_FIELD_NAME_SIZE]    = {0};
    char value[MAX_VALUE_SIZE]       = {0};
    char filename[MAX_FILENAME_SIZE] = {0};
    char mimetype[MAX_MIMETYPE_SIZE] = {0};

    // Initial state
    State state = STATE_BOUNDARY;

    // Allocate initial memory for files and fields.
    form->files = (FileHeader**)malloc(INITIAL_FILE_CAPACITY * sizeof(FileHeader*));
    if (!form->files) {
        LOG_ERROR("Failed to allocate memory for files");
        return MEMORY_ALLOC_ERROR;
    }

    // zero out the memory
    memset(form->files, 0, INITIAL_FILE_CAPACITY * sizeof(FileHeader*));

    // Initialize the number of files and fields to 0.
    form->num_files = 0;

    // Current file in State transitions
    FileHeader header = {0};

    // Allocate memory for fields
    form->fields = (FormField*)malloc(INITIAL_FIELD_CAPACITY * sizeof(FormField));
    if (!form->fields) {
        LOG_ERROR("Failed to allocate memory for fields");
        return MEMORY_ALLOC_ERROR;
    }

    form->num_fields = 0;
    memset(form->fields, 0, INITIAL_FIELD_CAPACITY * sizeof(FormField));

    MultipartCode code = MULTIPART_OK;

    // Start parsing the form data
    while (ptr < data + size) {
        switch (state) {
            case STATE_BOUNDARY: {
                if (strncmp(ptr, boundary, boundary_length) == 0) {
                    state = STATE_HEADER;
                    ptr += boundary_length;
                    while (*ptr == '-' || *ptr == '\r' || *ptr == '\n')
                        ptr++;  // Skip extra characters after boundary
                } else {
                    ptr++;
                }
            } break;
            case STATE_HEADER: {
                if (strncmp(ptr, "Content-Disposition:", 20) == 0) {
                    ptr = sstrstr(ptr, "name=\"", size - (ptr - data));
                    if (!ptr) {
                        code = INVALID_FORM_BOUNDARY;
                        goto cleanup;
                    }
                    ptr += 6;  // Skip name=\"
                    key_start = ptr;
                    state     = STATE_KEY;
                } else {
                    ptr++;
                }
            } break;
            case STATE_KEY:
                if (*ptr == '"' && key_start != nullptr) {
                    size_t key_length = ptr - key_start;
                    if (key_length >= MAX_FIELD_NAME_SIZE) {
                        code = FIELD_NAME_TOO_LONG;
                        goto cleanup;
                    }

                    memset(key, 0, MAX_FIELD_NAME_SIZE);
                    strncpy(key, key_start, key_length);
                    key[key_length] = '\0';

                    if (strncmp(ptr, "\"; filename=\"", 13) == 0) {
                        strncpy(header.field_name, key, MAX_FIELD_NAME_SIZE);
                        ptr = sstrstr(ptr, "\"; filename=\"", size - (ptr - data));
                        if (!ptr) {
                            code = INVALID_FORM_BOUNDARY;
                            goto cleanup;
                        }
                        ptr += 13;  // Skip "; filename=\""
                        key_start = ptr;
                        state     = STATE_FILENAME;
                    } else {
                        // Move to the end of the line
                        while (*ptr != '\n')
                            ptr++;

                        ptr++;  // Skip the newline character

                        // consume the leading CRLF before value
                        if (*ptr == '\r' && *(ptr + 1) == '\n') ptr += 2;

                        value_start = ptr;
                        state       = STATE_VALUE;
                    }
                } else {
                    ptr++;
                }
                break;
            case STATE_VALUE:
                if ((strncmp(ptr, "\r\n--", 4) == 0 || strncmp(ptr, boundary, boundary_length) == 0) &&
                    value_start != nullptr) {
                    size_t value_length = ptr - value_start;
                    if (value_length >= MAX_VALUE_SIZE) {
                        code = VALUE_TOO_LONG;
                        goto cleanup;
                    }

                    memset(value, 0, MAX_VALUE_SIZE);
                    strncpy(value, value_start, value_length);
                    value[value_length] = '\0';

                    // Check if we have enough capacity for fields
                    if (form->num_fields >= INITIAL_FIELD_CAPACITY) {
                        if (!realloc_fields(form)) {
                            LOG_ERROR("Failed to reallocate fields");
                            code = MEMORY_ALLOC_ERROR;
                            goto cleanup;
                        }
                    }

                    FormField field = {0};
                    strncpy(field.name, key, MAX_FIELD_NAME_SIZE);
                    strncpy(field.value, value, MAX_VALUE_SIZE);
                    form->fields[form->num_fields++] = field;

                    // reset the key and value
                    memset(key, 0, MAX_FIELD_NAME_SIZE);
                    memset(value, 0, MAX_VALUE_SIZE);

                    while (*ptr == '\r' || *ptr == '\n')
                        ptr++;  // Skip CRLF characters

                    // Reset state and process the next field if any
                    state = STATE_BOUNDARY;
                } else {
                    ptr++;
                }
                break;
            case STATE_FILENAME: {
                if (*ptr == '"' && key_start != nullptr) {
                    size_t filename_length = ptr - key_start;
                    if (filename_length >= MAX_FILENAME_SIZE) {
                        code = FILENAME_TOO_LONG;
                        goto cleanup;
                    }

                    memset(filename, 0, MAX_FILENAME_SIZE);
                    strncpy(filename, key_start, filename_length);
                    filename[filename_length] = '\0';

                    // copy into current header
                    strncpy(header.filename, filename, MAX_FILENAME_SIZE);

                    // Move to the end of the line
                    while (*ptr != '\n')
                        ptr++;

                    ptr++;  // Skip the newline character

                    // consume the leading CRLF before value if available
                    bool is_look_ahead_in_bounds = (ptr + 1) < (data + size);
                    if (is_look_ahead_in_bounds && *ptr == '\r' && *(ptr + 1) == '\n') ptr += 2;

                    // We expect the next line to be Content-Type
                    state = STATE_FILE_MIME_HEADER;
                } else {
                    ptr++;
                }
            } break;
            case STATE_FILE_MIME_HEADER: {
                if (strncmp(ptr, "Content-Type: ", 14) == 0) {
                    ptr = sstrstr(ptr, "Content-Type: ", size - (ptr - data));
                    if (!ptr) {
                        code = INVALID_FORM_BOUNDARY;
                        goto cleanup;
                    }
                    ptr += 14;  // Skip "Content-Type: "
                    state = STATE_MIMETYPE;
                } else {
                    ptr++;
                }
            } break;
            case STATE_MIMETYPE: {
                size_t mimetype_len = 0;    // Length of the mimetype
                value_start         = ptr;  // store the start of the mimetype

                // Compute the length of the mimetype as we advance the pointer
                while (*ptr != '\r' && *ptr != '\n') {
                    mimetype_len++;
                    ptr++;
                }

                if (mimetype_len >= MAX_MIMETYPE_SIZE) {
                    code = MIMETYPE_TOO_LONG;
                    goto cleanup;
                }

                // Copy the mimetype into the allocated memory
                memset(mimetype, 0, MAX_MIMETYPE_SIZE);
                strncpy(mimetype, value_start, mimetype_len);
                mimetype[mimetype_len] = '\0';

                // Copy the mimetype into the current header
                strncpy(header.mimetype, mimetype, MAX_MIMETYPE_SIZE);

                // Move to the end of the line
                while (*ptr != '\n')
                    ptr++;

                ptr++;  // Skip the newline character

                // consume the leading CRLF before bytes of the file
                // Make sure the look ahead is within bounds
                while (((*ptr == '\r' && ((ptr + 1) < (data + size)) && *(ptr + 1) == '\n'))) {
                    ptr += 2;  // skip CRLF
                }

                // No file content if the next line is a boundary
                if (memcmp(ptr, boundary, boundary_length) == 0) {
                    // If the file was never provided,the filename will be empty
                    // That's not an error.
                    if (strcmp(filename, "") == 0) {
                        state = STATE_BOUNDARY;
                        break;
                    }

                    // We have empty file body
                    code = EMPTY_FILE_CONTENT;
                    goto cleanup;
                }

                state = STATE_FILE_BODY;

            } break;
            case STATE_FILE_BODY: {
                header.offset       = ptr - data;
                size_t endpos       = 0;
                size_t haystack_len = size - header.offset;

                // Apparently strstr can't be used with binary data!!
                // I spen't days here trying to figgit with binary files :)
                char* endptr = (char*)memmem(ptr, haystack_len, boundary, boundary_length);
                if (endptr == nullptr) {
                    code = INVALID_FORM_BOUNDARY;
                    goto cleanup;
                }

                // Compute the end of file contents so we determine file size.
                endpos = endptr - data;

                // Compute the file size
                size_t file_size = endpos - header.offset;

                // Validate the file size
                if (file_size > MAX_FILE_SIZE) {
                    code = MAX_FILE_SIZE_EXCEEDED;
                    goto cleanup;
                }

                // Set the file size.
                header.size = file_size;

                // set the header field name
                strncpy(header.field_name, key, MAX_FIELD_NAME_SIZE);

                // Check if we have enough capacity for files
                if (form->num_files >= INITIAL_FILE_CAPACITY) {
                    if (!realloc_files(form)) {
                        LOG_ERROR("Failed to reallocate files");
                        code = MEMORY_ALLOC_ERROR;
                        goto cleanup;
                    }
                }

                // Insert a new file header into the form
                if (!insert_header(form, header)) {
                    code = MEMORY_ALLOC_ERROR;
                    goto cleanup;
                }

                // Reset the header
                memset(&header, 0, sizeof(FileHeader));

                // consume the trailing CRLF before the next boundary
                // Make sure the look ahead is within bounds
                while (((*ptr == '\r' && ((ptr + 1) < (data + size)) && *(ptr + 1) == '\n'))) {
                    ptr += 2;
                }
                state = STATE_BOUNDARY;

            } break;
            default:
                // This is unreachable but just in case, we don't want an infinite-loop
                // Crash and burn!!
                LOG_FATAL("default: unreachable state\n");
        }
    }

cleanup:
    if (code != MULTIPART_OK) multipart_free_form(form);
    return code;
}

// A simple implementation of strstr that takes a length parameter.
// and does not search beyond the length. This avoids dependence on
// both the haystack and needle being null-terminated.
// Shamelessly copied verbatim from:
// https://stackoverflow.com/questions/8584644/strstr-for-a-string-that-is-not-null-terminated
char* sstrstr(const char* haystack, const char* needle, size_t length) {
    size_t needle_length = strlen(needle);
    size_t i;
    for (i = 0; i < length; i++) {
        if (i + needle_length > length) {
            return nullptr;
        }
        if (strncmp(&haystack[i], needle, needle_length) == 0) {
            return (char*)&haystack[i];
        }
    }
    return nullptr;
}

// Parses the form boundary from the request body and copies it into the boundary buffer.
// size if the sizeof(boundary) buffer.
// body is the request body and is not assumed to be null-terminated. The boundary is assumed to be
// within the first 64 bytes of the body.
// Returns: true on success, false if the size is small or no boundary found.
bool multipart_parse_boundary(const char* body, char* boundary, size_t size) {
    // Search within the first 64 bytes for the boundary
    // This is a reasonable assumption since the boundary is usually within the first few bytes.
    char* boundary_end = sstrstr(body, "\r\n", 64);
    if (!boundary_end) {
        LOG_ERROR("Unable to determine the boundary in body: %s", body);
        return false;
    }

    size_t length         = boundary_end - body;
    size_t total_capacity = length + 1;
    if (size <= total_capacity) {
        LOG_ERROR("boundary buffer is smaller than %ld bytes", length + 1);
        return false;
    }

    strncpy(boundary, body, length);
    boundary[length] = '\0';
    return true;
}

// Parses the form boundary from the content-type header that is expected to be a nullptr-terminated string.
// Note that this boundary must always be -- shorter than what's in the body, so it's prefixed for you.
// Returns true if successful, otherwise false(Invalid Content-Type, no boundary).
bool multipart_parse_boundary_from_header(const char* content_type, char* boundary, size_t size) {
    if (!content_type || !boundary) {
        LOG_ERROR("content_type or boundary is nullptr");
        return false;
    }

    const char* prefix  = "--";
    size_t prefix_len   = strlen(prefix);
    size_t total_length = strlen(content_type);

    if (strncasecmp(content_type, "multipart/form-data", 19) != 0) {
        LOG_ERROR("content type is missing multipart/form-data in header");
        return false;
    }

    char* start   = sstrstr(content_type, "boundary=", total_length);
    size_t length = total_length - ((start + 9) - content_type);

    // Account for prefix and null terminater
    if (size <= length + prefix_len + 1) {
        LOG_ERROR("buffer size for boundary is too small");
        return false;
    }

    memcpy(boundary, prefix, prefix_len);  // ignore null terminator
    strncpy(boundary + prefix_len, (start + 9), length);
    boundary[length + prefix_len] = '\0';
    return true;
}

void multipart_free_form(MultipartForm* form) {
    if (!form) return;

    if (form->files) {
        for (size_t i = 0; i < form->num_files; i++) {
            free(form->files[i]);
            form->files[i] = nullptr;
        }

        free(form->files);
        form->files = nullptr;
    }

    if (form->fields) {
        free(form->fields);
        form->fields = nullptr;
    }

    form->num_files  = 0;
    form->num_fields = 0;
    form             = nullptr;
}

// =============== Fields API ========================
// Get the value of a field by name.
// Returns nullptr if the field is not found.
const char* multipart_get_field_value(const MultipartForm* form, const char* name) {
    for (size_t i = 0; i < form->num_fields; i++) {
        if (strcmp(form->fields[i].name, name) == 0) {
            return form->fields[i].value;
        }
    }
    return nullptr;
}

// =============== File API ==========================

// Get the first file matching the field name.
FileHeader* multipart_get_file(const MultipartForm* form, const char* field_name) {
    for (size_t i = 0; i < form->num_files; i++) {
        if (strcmp(form->files[i]->field_name, field_name) == 0) {
            return form->files[i];
        }
    }
    return nullptr;
}

size_t* multipart_get_files(const MultipartForm* form, const char* field_name, size_t* count) {
    size_t num_files = 0;
    for (size_t i = 0; i < form->num_files; i++) {
        if (strcmp(form->files[i]->field_name, field_name) == 0) {
            num_files++;
        }
    }

    if (num_files == 0) {
        *count = 0;
        return nullptr;
    }

    size_t* indices = (size_t*)malloc(num_files * sizeof(size_t));
    if (!indices) {
        perror("Failed to allocate memory for files");
        return nullptr;
    }

    size_t j = 0;
    for (size_t i = 0; i < form->num_files; i++) {
        if (strcmp(form->files[i]->field_name, field_name) == 0) {
            indices[j] = i;
            j++;
        }
    }
    *count = num_files;
    return indices;
}

// Save file writes the file to the file system.
// @param: file is the FileHeader that has the correct offset and file size.
// @param:  body is the request body. (Must not have been modified) since the file offset is relative to it.
// @param: path is the path to save the file to.
//
// Returns: true on success, false on failure.
bool multipart_save_file(const FileHeader* file, const char* body, const char* path) {
    FILE* f = fopen(path, "wb");
    if (!f) {
        perror("Failed to open file for writing");
        return false;
    }

    size_t n = fwrite(body + file->offset, 1, file->size, f);
    if (n != file->size) {
        perror("Failed to write file to disk");
        fclose(f);
        return false;
    }

    fclose(f);
    return true;
}

// Returns the const char* representing the error message.
const char* multipart_error_message(MultipartCode error) {
    switch (error) {
        case MEMORY_ALLOC_ERROR:
            return "Memory allocation failed";
        case INVALID_FORM_BOUNDARY:
            return "Invalid form boundary";
        case MAX_FILE_SIZE_EXCEEDED:
            return "Maximum file size exceeded";
        case FIELD_NAME_TOO_LONG:
            return "Field name too long";
        case FILENAME_TOO_LONG:
            return "Filename too long";
        case MIMETYPE_TOO_LONG:
            return "Mimetype too long";
        case VALUE_TOO_LONG:
            return "Value too long";
        case EMPTY_FILE_CONTENT:
            return "Empty file content";
        default:
            return "Multipart OK";
    }
}

static FileHeader** realloc_files(MultipartForm* form) {
    size_t new_capacity    = form->num_files * 2;
    FileHeader** new_files = (FileHeader**)realloc(form->files, new_capacity * sizeof(FileHeader*));
    if (!new_files) {
        perror("Failed to reallocate memory for files");
        return nullptr;
    }
    form->files = new_files;
    return form->files;
}

static FormField* realloc_fields(MultipartForm* form) {
    size_t new_capacity   = form->num_fields * 2;
    FormField* new_fields = (FormField*)realloc(form->fields, new_capacity * sizeof(FormField));
    if (!new_fields) {
        perror("Failed to reallocate memory for fields");
        return nullptr;
    }
    form->fields = new_fields;
    return form->fields;
}
