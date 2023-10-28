#include "headers.h"

bool header_tostring(const Header* h, char* buffer, size_t buffer_len) {
  if (buffer_len < strlen(h->name) + strlen(h->value) + 3) {  // ": " && null byte
    fprintf(stderr, "buffer_len is too small\n");
    return false;
  }
  snprintf(buffer, buffer_len, "%s: %s", h->name, h->value);
  return true;
}

bool header_fromstring(const char* str, Header* header) {
  size_t max_length = HEADER_KEY_LENGTH + HEADER_VALUE_LENGTH;
  size_t len        = strlen(str);

  if (len > max_length) {
    fprintf(stderr, "Header string is too long.\n");
    return false;
  }

  const char* colon_space = strstr(str, ": ");

  if (!colon_space) {
    fprintf(stderr, "Invalid header string format.\n");
    return false;
  }

  size_t name_len  = colon_space - str;
  size_t value_len = len - (name_len + 2);

  if (name_len >= HEADER_KEY_LENGTH || value_len >= HEADER_VALUE_LENGTH) {
    fprintf(stderr, "Header name or value is too long to fit in the designated buffer.\n");
    return false;
  }

  strncpy(header->name, str, sizeof(header->name));
  header->name[name_len] = '\0';

  strncpy(header->value, colon_space + 2, sizeof(header->value));
  header->value[value_len] = '\0';
  return true;
}

char* headers_loopup(Header* headers, size_t num_headers, const char* name) {
  for (size_t i = 0; i < num_headers; i++) {
    if (strcasecmp(headers[i].name, name) == 0) {
      return headers[i].value;
    }
  }
  return NULL;
}

bool new_header(const char* name, const char* value, Header* header) {
  size_t name_len  = strlen(name);
  size_t value_len = strlen(value);

  if (name_len >= HEADER_KEY_LENGTH || value_len >= HEADER_VALUE_LENGTH) {
    fprintf(stderr, "Header name or value is too long to fit in the designated buffer.\n");
    return false;
  }

  strncpy(header->name, name, sizeof(header->name));
  header->name[name_len] = '\0';

  strncpy(header->value, value, sizeof(header->value));
  header->value[value_len] = '\0';
  return true;
}


#if 0
int main(void) {
  const char* h1   = "Content-Type: application/json";
  Header h2        = {"Content-Length", "1024"};
  Header header    = {0};
  char buffer[100] = {0};

  if (!header_fromstring(h1, &header)) {
    return 1;
  }

  printf("Parsed Header 1: %s: %s\n", header.name, header.value);

  if (!header_tostring(&h2, buffer, sizeof(buffer))) {
    return 2;
  }

  printf("Header to string: %s\n", buffer);
}
#endif