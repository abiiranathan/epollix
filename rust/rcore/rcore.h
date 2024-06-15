#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * Represents a field with name and value.
 */
typedef struct FormField {
  const char *name;
  const char *value;
} FormField;

/**
 * Represents a file with filename, content type, content, and content length.
 */
typedef struct MultipartFile {
  const char *filename;
  const char *content_type;
  uint8_t *content;
  uintptr_t content_length;
  const char *field_name;
} MultipartFile;

/**
 * Represents a form data with fields and files.
 */
typedef struct FormData {
  struct FormField *fields;
  uintptr_t field_count;
  struct MultipartFile *files;
  uintptr_t file_count;
} FormData;

/**
 * Parses the multipart form data from the given body.
 * Returns a pointer to the parsed form data. If the body is null, returns a pointer to an empty form data.
 * Likewise if the boundary is not found, returns a pointer to an empty form data that must be freed.
 * The caller is responsible for freeing the form data by calling `free_multipart_form_data`.
 */
struct FormData *parse_multipart_form_data(const char *body);

/**
 * Frees the given form data. If the form data is null, does nothing.
 */
void free_multipart_form_data(struct FormData *data);
