#include "str.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>

typedef struct Str {
  size_t length;    // Actual string length(minus null terminater)
  size_t capacity;  // Allocated capacity
  bool in_arena;    // Whether allocated in arena
  char data[];      // Flexible Array member
} Str;

arena_t* arena_create(size_t size) {
  arena_t* arena = malloc(sizeof(arena_t));
  if (arena) {
    arena->base = malloc(size);
    if (!arena->base) {
      printf("could not allocate arena");
      free(arena);
      return NULL;
    }
    arena->size = size;
    arena->used = 0;
  }
  return arena;
}

void* arena_alloc(arena_t* arena, size_t size) {
  if (arena->used + size > arena->size) {
    return NULL;
  }

  void* ptr = arena->base + arena->used;
  arena->used += size;
  return ptr;
}

void arena_free(arena_t* arena) {
  if (!arena)
    return;

  if (arena->base) {
    free(arena->base);
  }
  free(arena);
}

Str* str_new(const char* str) {
  if (str == NULL) {
    return NULL;
  }

  size_t len = strlen(str);

  // Allocate memory for the Str struct and the string data
  Str* string = (Str*)malloc(sizeof(Str) + (len + 1) * sizeof(char));

  if (string == NULL) {
    return NULL;
  }

  string->length   = len;
  string->capacity = len;
  string->in_arena = false;
  strcpy(string->data, str);
  return string;
}

Str* str_new_witharena(const char* str, arena_t* arena) {
  if (str == NULL || arena == NULL) {
    return NULL;
  }

  size_t len = strlen(str);

  // Ensure there is enough space in the arena
  if (arena->used + sizeof(Str) + (len + 1) > arena->size) {
    return NULL;  // Arena is full
  }

  // Allocate memory for the Str struct and the string data from the arena
  Str* string = (Str*)(arena->base + arena->used);

  string->length   = len;
  string->capacity = len;
  string->in_arena = true;
  strcpy(string->data, str);

  // Update the arena's used size
  arena->used += sizeof(Str) + (len + 1);

  return string;
}

Str* str_new_with_cap(size_t cap) {
  Str* new_str = (Str*)malloc(sizeof(Str) + cap + 1);

  if (new_str != NULL) {
    new_str->length   = 0;
    new_str->capacity = cap;
    new_str->data[0]  = '\0';
    new_str->in_arena = false;
  }
  return new_str;
}

Str* str_new_with_cap_arena(size_t cap, arena_t* arena) {
  // Ensure there is enough space in the arena
  if (arena->used + sizeof(Str) + (cap + 1) > arena->size) {
    return NULL;  // Arena is full
  }

  // Allocate memory for the Str struct and the string data from the arena
  Str* string = (Str*)(arena->base + arena->used);

  string->length   = 0;
  string->capacity = cap;
  string->in_arena = true;
  string->data[0]  = '\0';

  // Update the arena's used size
  arena->used += sizeof(Str) + (cap);

  return string;
}

void str_free(Str* string) {
  if (string == NULL) {
    return;
  }

  if (!string->in_arena) {
    free(string);
  }
}

int str_compare(const Str* str1, const char* str2) {
  if (str1 == NULL || str2 == NULL) {
    return -1;
  }
  return strcmp(str1->data, str2);
}

const char* str_data(const Str* str) {
  return str->data;
}

Str* str_copy(const Str* str) {
  if (str == NULL) {
    return NULL;
  }

  // Allocate memory for the new Str struct
  Str* copy = (Str*)malloc(sizeof(Str) + (str->length + 1) * sizeof(char));

  if (copy == NULL) {
    return NULL;
  }

  // Copy the string data and other properties
  copy->length   = str->length;
  copy->capacity = str->length;
  strcpy(copy->data, str->data);
  return copy;
}

bool str_concat(char* dest, size_t dest_size, const char* src, const char* part) {

  size_t src_len  = strlen(src);
  size_t part_len = strlen(part);

  // Check if the combined length of src and part fits in dest_size
  if (src_len + part_len >= dest_size) {
    printf("Not enough space in destination buffer\n");
    return false;
  }

  strcpy(dest, src);                             // Copy src to dest
  strncat(dest, part, dest_size - src_len - 1);  // Concatenate part to dest

  return true;
}

size_t str_length(const Str* str) {
  if (str == NULL) {
    return -1;
  }

  return str->length;
}

const char* str_at(const Str* str, size_t index) {
  if (str == NULL || index >= str->length) {
    return NULL;
  }

  return str->data + index;
}

bool str_contains(const Str* str, const char* substring) {
  if (str == NULL || substring == NULL) {
    return false;
  }
  return strstr(str->data, substring) != NULL;
}

bool str_is_empty(const Str* str) {
  if (str == NULL) {
    return true;
  }

  return str->length == 0;
}

int str_find(const Str* str, const char* substring) {
  if (str == NULL || substring == NULL) {
    return -1;
  }
  return strstr(str->data, substring) - str->data;
}

bool str_replace(char* dest, size_t dest_size, const char* src, const char* old_str,
                 const char* new_str) {
  if (dest == NULL || src == NULL || old_str == NULL || new_str == NULL || dest_size == 0) {
    return false;  // Invalid input
  }

  // Find the first occurrence of old_str in src
  char* substr = strstr(src, old_str);

  if (substr == NULL) {
    // If old_str is not found, simply copy src to dest
    strncpy(dest, src, dest_size - 1);
    dest[dest_size - 1] = '\0';
  } else {
    size_t before_len  = substr - src;  // Length before old_str
    size_t new_str_len = strlen(new_str);
    size_t after_len   = strlen(substr + strlen(old_str));  // Length after old_str

    // Check if the resulting string will fit in dest
    if (before_len + new_str_len + after_len >= dest_size) {
      fprintf(stderr, "Not enough space in the destination buffer\n");
      return false;
    }

    // Copy the part before old_str to dest
    strncpy(dest, src, before_len);
    dest[before_len] = '\0';

    // Append new_str to dest
    strncat(dest, new_str, dest_size - strlen(dest) - 1);

    // Append the part after old_str to dest
    strncat(dest, substr + strlen(old_str), dest_size - strlen(dest) - 1);
  }

  return true;
}

bool str_replace_all(char* dest, size_t dest_size, const char* src, const char* old_str,
                     const char* new_str) {
  if (dest == NULL || src == NULL || old_str == NULL || new_str == NULL || dest_size == 0) {
    return false;  // Invalid input
  }

  size_t dest_len    = 0;
  size_t src_len     = strlen(src);
  size_t old_str_len = strlen(old_str);
  size_t new_str_len = strlen(new_str);

  for (size_t i = 0; i < src_len;) {
    // Find the next occurrence of old_str
    char* substr = strstr(src + i, old_str);

    if (substr == NULL) {
      // No more occurrences found, copy the rest of src to dest
      strncpy(dest + dest_len, src + i, dest_size - dest_len);
      dest[dest_size - 1] = '\0';
      break;
    } else {
      size_t before_len = substr - (src + i);  // Length before old_str

      // Check if the resulting string will fit in dest
      if (dest_len + before_len + new_str_len >= dest_size) {
        return false;  // Not enough space in the destination buffer
      }

      // Append the part before old_str to dest
      strncpy(dest + dest_len, src + i, before_len);
      dest_len += before_len;

      // Append new_str to dest
      strncpy(dest + dest_len, new_str, new_str_len + 1);
      dest_len += new_str_len;

      i += before_len + old_str_len;  // Move past the old_str
    }
  }
  return true;
}

void str_to_upper(Str* str) {
  if (str == NULL) {
    return;
  }

  for (size_t i = 0; i < str->length; i++) {
    str->data[i] = toupper(str->data[i]);
  }
}

void str_to_lower(Str* str) {
  if (str == NULL) {
    return;
  }

  for (size_t i = 0; i < str->length; i++) {
    str->data[i] = tolower(str->data[i]);
  }
}

char** str_split(const Str* str, const char* delimiter, size_t* num_substrings) {
  *num_substrings      = 0;
  const char* data     = str->data;
  size_t data_len      = str->length;
  size_t delimiter_len = strlen(delimiter);

  // Create an initial capacity for substrings
  size_t capacity   = 10;
  char** substrings = (char**)malloc(capacity * sizeof(char*));

  const char* start = data;
  char* end;

  while ((end = strstr(start, delimiter)) != NULL) {
    // If we exceed the current capacity, resize the substrings array
    if (*num_substrings >= capacity) {
      capacity *= 2;
      substrings = (char**)realloc(substrings, capacity * sizeof(char*));
    }

    size_t substring_len        = end - start;
    substrings[*num_substrings] = (char*)malloc(substring_len + 1);
    strncpy(substrings[*num_substrings], start, substring_len);
    substrings[*num_substrings][substring_len] = '\0';

    (*num_substrings)++;

    // Move the start pointer beyond the delimiter
    start = end + delimiter_len;
  }

  // Handle the last substring after the last delimiter
  size_t last_substring_len = data_len - (start - data);
  if (last_substring_len > 0) {
    // Ensure enough capacity for the last substring
    if (*num_substrings >= capacity) {
      capacity += 1;  // Increment capacity
      substrings = (char**)realloc(substrings, capacity * sizeof(char*));
    }

    substrings[*num_substrings] = (char*)malloc(last_substring_len + 1);
    strcpy(substrings[*num_substrings], start);

    (*num_substrings)++;
  }

  // Trim the substrings array to its actual size
  substrings = (char**)realloc(substrings, (*num_substrings) * sizeof(char*));
  return substrings;
}

char** str_split_max(const Str* str, const char* delimiter, size_t* num_substrings,
                     size_t max_split) {
  *num_substrings      = 0;
  const char* data     = str->data;
  size_t data_len      = str->length;
  size_t delimiter_len = strlen(delimiter);

  // Create an initial capacity for substrings
  size_t capacity   = 10;
  char** substrings = (char**)malloc(capacity * sizeof(char*));

  const char* start = data;
  char* end;

  while ((end = strstr(start, delimiter)) != NULL && (*num_substrings) < max_split) {
    // If we exceed the current capacity, resize the substrings array
    if (*num_substrings >= capacity) {
      capacity *= 2;
      substrings = (char**)realloc(substrings, capacity * sizeof(char*));
    }

    size_t substring_len        = end - start;
    substrings[*num_substrings] = (char*)malloc(substring_len + 1);
    strncpy(substrings[*num_substrings], start, substring_len);
    substrings[*num_substrings][substring_len] = '\0';

    (*num_substrings)++;

    // Move the start pointer beyond the delimiter
    start = end + delimiter_len;
  }

  if (*num_substrings < max_split) {
    // Handle the last substring after the last delimiter
    size_t last_substring_len = data_len - (start - data);
    if (last_substring_len > 0) {
      // Ensure enough capacity for the last substring
      if (*num_substrings >= capacity) {
        capacity += 1;  // Increment capacity
        substrings = (char**)realloc(substrings, capacity * sizeof(char*));
      }

      substrings[*num_substrings] = (char*)malloc(last_substring_len + 1);
      strcpy(substrings[*num_substrings], start);

      (*num_substrings)++;
    }
  }

  // Trim the substrings array to its actual size
  substrings = (char**)realloc(substrings, (*num_substrings) * sizeof(char*));
  return substrings;
}

void str_free_substrings(char** substrings, int num_substrings) {
  if (!substrings) {
    return;
  }

  for (int i = 0; i < num_substrings; i++) {
    free(substrings[i]);
  }
  free(substrings);
}

bool str_match(const Str* str, const char* regex) {
  if (str == NULL || regex == NULL) {
    return false;
  }

  regex_t re;
  int ret = regcomp(&re, regex, REG_EXTENDED | REG_NOSUB);
  if (ret != 0) {
    char error_msg[100];
    regerror(ret, &re, error_msg, sizeof(error_msg));
    printf("Error compiling regex: %s\n", error_msg);
    return false;
  }

  int matches = regexec(&re, str->data, 0, NULL, 0);
  if (matches != 0) {
    char error_msg[100];
    regerror(matches, &re, error_msg, sizeof(error_msg));
    printf("Error executing regex: %s\n", error_msg);
  }

  regfree(&re);

  return matches == 0;
}

void str_to_camel_case(Str* str) {
  if (str == NULL) {
    return;
  }

  char* data               = str->data;
  int dest_index           = 0;
  int capitalize_next_char = 1;

  // Process the string and convert to camel case
  while (data[dest_index] != '\0') {
    if (data[dest_index] == ' ' || data[dest_index] == '_') {
      capitalize_next_char = 1;
    } else if (capitalize_next_char) {
      data[dest_index]     = toupper(data[dest_index]);
      capitalize_next_char = 0;
    }

    dest_index++;
  }

  // Remove spaces and underscores from the string
  int j = 0;
  for (dest_index = 0; data[dest_index] != '\0'; dest_index++) {
    if (data[dest_index] != ' ' && data[dest_index] != '_') {
      data[j] = data[dest_index];
      j++;
    }
  }
  data[j] = '\0';

  // Update the length of the string
  str->length = j;
}

void str_to_title_case(Str* str) {
  if (str == NULL) {
    return;
  }

  char* data    = str->data;
  size_t length = str->length;

  if (length > 0) {
    data[0] = toupper(data[0]);
  }

  for (size_t i = 1; i < length; i++) {
    if (data[i - 1] == ' ') {
      data[i] = toupper(data[i]);
    } else {
      data[i] = tolower(data[i]);
    }
  }
}

void str_to_snake_case(Str* str) {
  size_t length = str->length;
  char* data    = str->data;

  // Convert first character to lowercase
  data[0] = tolower(data[0]);

  size_t space_count = 0;

  for (size_t i = 1; i < length; i++) {
    // Check if current character is a space
    if (isspace(data[i])) {
      space_count++;
      continue;  // Skip spaces
    }

    // Check if current character is uppercase
    if (isupper(data[i])) {
      // Insert underscore before uppercase character
      memmove(&data[i + 1 - space_count], &data[i - space_count], length - i + space_count);
      data[i - space_count] = '_';
      length++;

      i++;  // Skip the inserted underscore
    }

    // Convert the character to lowercase
    data[i - space_count] = tolower(data[i]);
  }

  // Trim the string to the new length
  data[length - space_count] = '\0';
}

bool str_insert(char* dest, size_t buffer_size, const char* src, const char* part, size_t index) {
  if (index > strlen(src)) {
    return false;  // Invalid input
  }

  size_t src_len  = strlen(src);
  size_t part_len = strlen(part);

  // Check if the resulting string will fit in dest
  if (src_len + part_len >= buffer_size) {
    fprintf(stderr, "Not enough space in the destination buffer\n");
    return false;
  }

  // Copy the part of the source string before the index to dest
  strncpy(dest, src, index);
  dest[index] = '\0';  // Null-terminate the part before the index

  // Append the inserted part to dest
  strncat(dest, part, buffer_size - strlen(dest) - 1);

  // Append the remaining part of the source string to dest
  strncat(dest, src + index, buffer_size - strlen(dest) - 1);

  return true;
}

void str_remove(Str* s, size_t index, size_t count) {
  if (s == NULL || index >= s->length || count == 0) {
    return;  // Invalid input or nothing to remove
  }

  // Ensure the index and count are within bounds
  if (index + count > s->length) {
    count = s->length - index;
  }

  // Move the characters after the removed portion to the left
  memmove(s->data + index, s->data + index + count, s->length - index - count + 1);

  // Update the string length
  s->length -= count;
  // Null-terminate the string
  s->data[s->length] = '\0';
}

bool str_join(const char** substrings, int count, char delimiter, char* buffer, size_t bufsize) {

  size_t substr_len = 0;
  for (int i = 0; i < count; i++) {
    substr_len += strlen(substrings[i]);
  }

  // Account for delimiter characters, except last
  // If we are joining with '\0', count is 0
  size_t joined_length = substr_len + (delimiter ? (count - 1) : 0);

  // Check if the joined string fits within the buffer
  if (joined_length >= bufsize) {
    printf("buffer size(%zu) is too small\n", bufsize);
    return false;
  }

  char* current = buffer;
  for (int i = 0; i < count; i++) {
    size_t sub_len = strlen(substrings[i]);
    memcpy(current, substrings[i], sub_len);
    current += sub_len;

    if (delimiter != '\0' && i < count - 1) {
      *current++ = delimiter;
    }
  }
  *current = '\0';  // Terminate the joined string
  return true;
}

bool str_substring(const Str* s, size_t start, size_t end, char* substring, size_t bufsize) {

  // Bounds check on s.
  if (start > s->length || end > s->length) {
    return false;
  }

  // Check buffer is big enough
  size_t len = end - start;
  if (len >= bufsize) {
    printf("buffer size(%zu) is too small. Truncating substring\n", bufsize);
    // Adjust length to fit within buffer size
    len = bufsize - 1;
    memcpy(substring, s->data + start, len);
    substring[len] = '\0';
    return false;
  }

  memcpy(substring, s->data + start, len);
  substring[len] = '\0';
  return true;
}

void str_reverse(Str* s) {
  if (s == NULL) {
    return;
  }

  char* data    = s->data;
  size_t length = s->length;

  for (size_t i = 0; i < length / 2; i++) {
    char temp            = data[i];
    data[i]              = data[length - i - 1];
    data[length - i - 1] = temp;
  }
}

int str_startswith(const Str* s, const char* prefix) {
  if (s == NULL || prefix == NULL) {
    return 0;
  }

  size_t prefix_length = strlen(prefix);
  if (prefix_length > s->length) {
    return 0;
  }

  return strncmp(s->data, prefix, prefix_length) == 0;
}

int str_endswith(const Str* s, const char* suffix) {
  if (s == NULL || suffix == NULL) {
    return 0;
  }

  size_t suffix_length = strlen(suffix);
  if (suffix_length > s->length) {
    return 0;
  }

  return strncmp(s->data + s->length - suffix_length, suffix, suffix_length) == 0;
}

char* regex_sub_match(const char* str, const char* regex, int capture_group) {
  regex_t compiled_regex;
  regmatch_t matches[2];
  int result;

  if (regcomp(&compiled_regex, regex, REG_EXTENDED) != 0) {
    printf("Regex compilation failed\n");
    return NULL;
  }

  result = regexec(&compiled_regex, str, 2, matches, 0);
  if (result != 0) {
    printf("Regex matching failed\n");
    regfree(&compiled_regex);
    return NULL;
  }

  if (matches[capture_group].rm_so == -1) {
    printf("Capture group not found\n");
    regfree(&compiled_regex);
    return NULL;
  }

  int start      = matches[capture_group].rm_so;
  int end        = matches[capture_group].rm_eo;
  int sub_length = end - start;

  char* sub_match = malloc((sub_length + 1) * sizeof(char));
  if (sub_match == NULL) {
    printf("Memory allocation failed\n");
    regfree(&compiled_regex);
    return NULL;
  }

  strncpy(sub_match, str + start, sub_length);
  sub_match[sub_length] = '\0';

  regfree(&compiled_regex);
  return sub_match;
}

#ifdef USE_PCRE_REGEX

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

char* regex_sub_match_pcre(const char* str, const char* regex, int capture_group) {
  pcre2_code* compiled_regex;
  pcre2_match_data* match_data;
  PCRE2_SPTR subject = (PCRE2_SPTR)str;
  PCRE2_SPTR pattern = (PCRE2_SPTR)regex;
  int error_code;
  PCRE2_SIZE error_offset;

  compiled_regex =
    pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &error_code, &error_offset, NULL);
  if (compiled_regex == NULL) {
    printf("PCRE2 regex compilation failed\n");
    return NULL;
  }

  match_data = pcre2_match_data_create_from_pattern(compiled_regex, NULL);
  if (match_data == NULL) {
    printf("Failed to create match data\n");
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  int result = pcre2_match(compiled_regex, subject, strlen(str), 0, 0, match_data, NULL);

  if (result < 0) {
    printf("PCRE2 regex matching failed\n");
    pcre2_match_data_free(match_data);
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  if (result < capture_group + 1) {
    printf("Capture group not found\n");
    pcre2_match_data_free(match_data);
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  PCRE2_SIZE* offsets = pcre2_get_ovector_pointer(match_data);

  PCRE2_SIZE start      = offsets[capture_group * 2];
  PCRE2_SIZE end        = offsets[capture_group * 2 + 1];
  PCRE2_SIZE sub_length = end - start;

  char* sub_match = malloc((sub_length + 1) * sizeof(char));
  if (sub_match == NULL) {
    printf("Memory allocation failed\n");
    pcre2_match_data_free(match_data);
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  strncpy(sub_match, str + start, sub_length);
  sub_match[sub_length] = '\0';

  pcre2_match_data_free(match_data);
  pcre2_code_free(compiled_regex);
  return sub_match;
}

char** regex_sub_matches_pcre(const char* str, const char* regex, int num_capture_groups,
                              int* num_matches) {

  pcre2_code* compiled_regex;
  pcre2_match_data* match_data;
  PCRE2_SPTR subject = (PCRE2_SPTR)str;
  PCRE2_SPTR pattern = (PCRE2_SPTR)regex;
  int error_code;
  PCRE2_SIZE error_offset;

  compiled_regex =
    pcre2_compile(pattern, PCRE2_ZERO_TERMINATED, 0, &error_code, &error_offset, NULL);
  if (compiled_regex == NULL) {
    printf("PCRE2 regex compilation failed\n");
    return NULL;
  }

  match_data = pcre2_match_data_create_from_pattern(compiled_regex, NULL);
  if (match_data == NULL) {
    printf("Failed to create match data\n");
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  int result = pcre2_match(compiled_regex, subject, strlen(str), 0, 0, match_data, NULL);

  if (result < 0) {
    printf("PCRE2 regex matching failed\n");
    pcre2_match_data_free(match_data);
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  int match_count = result / num_capture_groups;
  *num_matches    = match_count;

  char** sub_matches = malloc(match_count * num_capture_groups * sizeof(char*));
  if (sub_matches == NULL) {
    printf("Memory allocation failed\n");
    pcre2_match_data_free(match_data);
    pcre2_code_free(compiled_regex);
    return NULL;
  }

  PCRE2_SIZE* offsets = pcre2_get_ovector_pointer(match_data);

  for (int i = 0; i < match_count; i++) {
    for (int j = 0; j < num_capture_groups; j++) {
      PCRE2_SIZE start      = offsets[(i * num_capture_groups + j) * 2];
      PCRE2_SIZE end        = offsets[(i * num_capture_groups + j) * 2 + 1];
      PCRE2_SIZE sub_length = end - start;

      sub_matches[i * num_capture_groups + j] = malloc((sub_length + 1) * sizeof(char));
      if (sub_matches[i * num_capture_groups + j] == NULL) {
        printf("Memory allocation failed\n");
        pcre2_match_data_free(match_data);
        pcre2_code_free(compiled_regex);
        for (int k = 0; k < i * num_capture_groups + j; k++) {
          free(sub_matches[k]);
        }
        free(sub_matches);
        return NULL;
      }

      strncpy(sub_matches[i * num_capture_groups + j], str + start, sub_length);
      sub_matches[i * num_capture_groups + j][sub_length] = '\0';
    }
  }

  pcre2_match_data_free(match_data);
  pcre2_code_free(compiled_regex);
  return sub_matches;
}

#endif