#ifndef __MULTIPART_H__
#define __MULTIPART_H__

#include <stdbool.h>
#include <stddef.h>

// Constants that can be overriden
#ifndef INITIAL_FIELD_CAPACITY
#define INITIAL_FIELD_CAPACITY 16
#endif

#ifndef INITIAL_FILE_CAPACITY
#define INITIAL_FILE_CAPACITY 2
#endif

// 10MB is the default maximum file size.
#ifndef MAX_FILE_SIZE
#define MAX_FILE_SIZE 10 * 1024 * 1024
#endif

// Define maximum values for field_name, filename and mimetype and value.
#ifndef MAX_FIELD_NAME_SIZE
#define MAX_FIELD_NAME_SIZE 64
#endif

#ifndef MAX_FILENAME_SIZE
#define MAX_FILENAME_SIZE 128
#endif

#ifndef MAX_MIMETYPE_SIZE
#define MAX_MIMETYPE_SIZE 128
#endif

#ifndef MAX_VALUE_SIZE
#define MAX_VALUE_SIZE 2048
#endif

typedef enum {
    STATE_BOUNDARY,
    STATE_HEADER,
    STATE_KEY,
    STATE_VALUE,
    STATE_FILENAME,
    STATE_FILE_MIME_HEADER,
    STATE_MIMETYPE,
    STATE_FILE_BODY,
} State;

// FileHeader is a representation of a file parsed from the form.
// It helps us avoid copying file contents but can save the file from
// it's offset and size.
typedef struct FileHeader {
    size_t offset;  // Offset from the body of request as passed to parse_multipart.
    size_t size;    // Computed file size.

    char filename[MAX_FILENAME_SIZE];      // Value of filename in Content-Disposition
    char mimetype[MAX_MIMETYPE_SIZE];      // Content-Type of the file.
    char field_name[MAX_FIELD_NAME_SIZE];  // Name of the field the file is associated with.
} FileHeader;

// Represents a field with its value in a form.
typedef struct FormField {
    char name[MAX_FIELD_NAME_SIZE];  // Field name
    char value[MAX_VALUE_SIZE];      // Value associated with the field.
} FormField;

typedef struct MultipartForm {
    FileHeader** files;  // The array of file headers
    size_t num_files;    // The number of files processed.

    FormField* fields;  // Array of form field structs.
    size_t num_fields;  // The number of fields.
} MultipartForm;

typedef enum {
    MULTIPART_OK,
    MEMORY_ALLOC_ERROR,
    INVALID_FORM_BOUNDARY,
    MAX_FILE_SIZE_EXCEEDED,
    FIELD_NAME_TOO_LONG,
    FILENAME_TOO_LONG,
    MIMETYPE_TOO_LONG,
    VALUE_TOO_LONG,
    EMPTY_FILE_CONTENT,
} MultipartCode;

/**
 * Parse a multipart form from the request body.
 * @param data: Request body (with out headers)
 * @param size: Content-Length(size of data in bytes)
 * @param boundary: Null-terminated string for the form boundary.
 * @param form: Pointer to MultipartForm struct to store the parsed form data. It is assumed
 * to be initialized well and not NULL.
 * You can use the function multipart_parse_boundary or multipart_parse_boundary_from_header helpers
 * to get the boundary.
 * 
 * @returns: MultipartCode enum value indicating the success or failure of the operation.
 * Use the multipart_error_message function to get the error message if the code
 * is not MULTIPART_OK.
 * */
MultipartCode multipart_parse_form(const char* data, size_t size, char* boundary, MultipartForm* form);

// Free memory allocated by parse_multipart_form
void multipart_free_form(MultipartForm* form);

// Returns the const char* representing the error message.
const char* multipart_error_message(MultipartCode error);

// Parses the form boundary from the request body and copies it into the boundary buffer.
// size if the sizeof(boundary) buffer.
// Returns: true on success, false if the size is small or no boundary found.
bool multipart_parse_boundary(const char* body, char* boundary, size_t size);

// Parses the form boundary from the content-type header.
// Note that this boundary must always be -- shorter than what's in the body, so it's prefixed with -- for you.
// Returns true if successful, otherwise false(Invalid Content-Type, no boundary).
bool multipart_parse_boundary_from_header(const char* content_type, char* boundary, size_t size);

// =============== Fields API ========================
// Get the value of a field by name.
// Returns NULL if the field is not found.
const char* multipart_get_field_value(const MultipartForm* form, const char* name);

// =============== File API ==========================

// Get the first file matching the field name.
FileHeader* multipart_get_file(const MultipartForm* form, const char* field_name);

// Get all files indices matching the field name.
// We return indices because we can have multiple files with the same field name but we
// want to avoid double free and dangling pointers if we keep a reference to the files in another array.
//
// @param: form is the MultipartForm struct pointer.
// @param: count is pointer the number of files found and will be updated.
// Not that the array will be allocated and must be freed by the caller with glibc's free.
size_t* multipart_get_files(const MultipartForm* form, const char* field_name, size_t count[static 1]);

// Save file writes the file to the file system.
// @param: file is the FileHeader that has the correct offset and file size.
// @param:  body is the request body. (Must not have been modified) since the file offset is relative to it.
// @param: path is the path to save the file to.
//
// Returns: true on success, false on failure.
bool multipart_save_file(const FileHeader* file, const char* body, const char* path);

// A simple implementation of strstr that takes a length parameter.
// and does not search beyond the length. This avoids dependence on
// both the haystack and needle being null-terminated.
// Shamelessly copied verbatim from:
// https://stackoverflow.com/questions/8584644/strstr-for-a-string-that-is-not-null-terminated
char* sstrstr(const char* haystack, const char* needle, size_t length);

#endif  // __MULTIPART_H__