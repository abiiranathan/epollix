#ifndef REQUEST_H
#define REQUEST_H

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <solidc/cstr.h>
#include <solidc/map.h>

#include "headers.h"
#include "method.h"
#include "url.h"

// maximum number of request headers
#ifndef MAX_REQ_HEADERS
#define MAX_REQ_HEADERS 36
#endif

// The size of the boundary string for multipart/form-data
#define FORM_BOUNDARY_SIZE 128

// Maximum size of the URL.
#ifndef URL_MAX_LENGTH
#define URL_MAX_LENGTH 2048
#endif

// Maximum File size is 100 MB
#ifndef MAX_FILE_SIZE
#define MAX_FILE_SIZE 100 * 1024 * 1024
#endif

// Maximum request body size is 500 MB
#ifndef MAX_BODY_SIZE
#define MAX_BODY_SIZE 1 * 1024 * 1024 * 500
#endif

#ifndef MAX_UPLOAD_FILES
#define MAX_UPLOAD_FILES 4
#endif

#define MAX_FILE_HEADER_FILENAME 64
#define MAX_FILE_HEADER_MIME 128
#define MAX_FILE_HEADER_FIELDNAME 128
#define MAX_FORM_TEXT_LENGTH 2048

extern const char* SCHEME;  // default scheme is "http" defined in request.c

typedef struct HttpInfo {
    char method[16];
    char http_version[24];
    char path[1024];
    HttpMethod httpMethod;
} HttpInfo;

typedef struct FileHeader {
    size_t start_pos;
    size_t filesize;
    char filename[MAX_FILE_HEADER_FILENAME];
    char mimetype[MAX_FILE_HEADER_MIME];
    char field_name[MAX_FILE_HEADER_FIELDNAME];
} FileHeader;

typedef enum {
    FE_SUCCESS,
    FE_EMPTY_REQUEST_BODY,
    FE_MISSING_CONTENT_TYPE,
    FE_INVALID_CONTENT_TYPE,
    FE_METHOD_NOT_ALLOWED,
    FE_MEMORY_ALLOCATION_FAILED,
    FE_FILE_TOO_BIG,
    FE_INVALID_BOUNDARY,
} FormError;

typedef struct MultipartForm {
    map* form;                           // A hash map containing all form fields.
    FormError error;                     // An error code if parsing the form failed.
    FileHeader files[MAX_UPLOAD_FILES];  // The array of file headers
    size_t num_files;                    // The number of files processed.
} MultipartForm;

typedef struct Request {
    char http_version[12];  // HTTP version of the request. e.g HTTP/1.1, HTTP/2.0, HTTP/3.0
    HttpMethod method;      // enum for the request method.
    URL* url;               // URL for this request

    size_t header_length;             // Number of headers parsed from the request.
    Header headers[MAX_REQ_HEADERS];  // array of headers with length(MAX_REQ_HEADERS).

    const char* body;    // Body of request if not (GET/OPTIONS) and provided or NULL;
    size_t body_length;  // Size of the request body.

    MultipartForm* multipart;  // Struct containing form and file information
} Request;

// parse Request from the received data from the socket.
// The http method, path, headers and request body will be populated.
// Query strings are not yet implemented.
Request* request_parse_http(Arena* arena, cstr* data, HttpInfo* info);

// Free memory used by the request, headers and body. Passing NULL does nothing.
void request_destroy(Request* request);

const char* getWebContentType(char* fileExtension);

// Parse multipart/form-data or url encoded form
// from the request body based on the content type
// If an error occurs, request.multipart may be NULL or request.multipart.error code will
// indicate the error. use get_form_error helpper to return the error as a const char*;
void parse_form(Request* request);

// Get the error message for the given error
const char* get_form_error(FormError error);

// Get the file contents from the file header. You are responsible for freeing this memory.
// The returned data may not be null terminated.
char* get_file_contents(FileHeader header, Request* req);

// Save file from the Header.
// This is memory efficient because it does not read the body into memory first.
// Although it might be slow for large files as it uses fputc to write
// to write character by character.
// If you want to handle bytes yourself, call get_file_contents.
bool save_file_to_disk(const char* filename, FileHeader header, Request* req);

void get_form_files(const char* field_name, Request* request, FileHeader headers[MAX_UPLOAD_FILES],
                    size_t num_files[static 1]);

#endif /* REQUEST_H */
