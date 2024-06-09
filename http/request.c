
#include <assert.h>
#include <solidc/cstr.h>
#include <stdlib.h>
#include <strings.h>

#include "method.h"
#include "request.h"
#include "url.h"

static const char* LF = "\r\n";
static const char* DOUBLE_LF = "\r\n\r\n";
char* SCHEME = "http";

static size_t parse_int(const char* str) {
  char* endptr;
  size_t value = strtoul(str, &endptr, 10);
  if (*endptr != '\0' || value == ULONG_MAX) {
    return 0;
  }
  return value;
}

Header** parse_headers(Arena* arena, cstr* data, size_t* num_headers, size_t* header_end_idx,
                       HttpMethod method, size_t* content_length) {
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
  start_pos = (header_start - req_data) + 2;  // skip LF
  end_pos = header_end - req_data;
  size_t header_length = end_pos - start_pos;

  cstr* header_substring = cstr_substr(arena, data, start_pos, header_length);
  if (header_substring == NULL) {
    fprintf(stderr, "cstr_substr(): error parsing header substring\n");
    return NULL;
  }

  size_t n;
  cstr** header_lines = cstr_split_at(arena, header_substring, LF, 32, &n);
  if (header_lines == NULL) {
    fprintf(stderr, "cstr_split_at(): error parsing header lines\n");
    return NULL;
  }

  bool is_safe = is_safe_method(method);
  Header** headers = arena_alloc(arena, sizeof(Header*) * MAX_REQ_HEADERS);
  if (headers == NULL) {
    fprintf(stderr, "arena_alloc(): error allocating headers\n");
    return NULL;
  }

  size_t header_index = 0;
  if (n > 0) {
    for (size_t i = 0; (i < n && i < MAX_REQ_HEADERS); i++) {
      Header* header = header_fromstring(arena, header_lines[i]);
      if (header == NULL) {
        fprintf(stderr, "header_fromstring(): error parsing header: %s\n", header_lines[i]->data);
        continue;
      }

      headers[header_index++] = header;

      // No point getting content-length on GET, OPTIONS methods...
      if (!is_safe && strcasecmp(header->name->data, "Content-Length") == 0) {
        size_t value = parse_int(header->value->data);
        if (value == 0) {
          fprintf(stderr, "Invalid Content-Length header\n");
          return NULL;
        }
        *content_length = value;
      }
    }
  }


  *header_end_idx = end_pos;
  *num_headers = header_index;
  return headers;
}

Request* request_parse_http(Arena* arena, cstr* data) {
  char method_str[10] = {0};
  char path[256] = {0};
  size_t header_end_idx = 0;
  size_t content_length = 0;
  size_t num_headers = 0;

  int n = sscanf(data->data, "%9s %255s", method_str, path);
  assert(n == 2);

  // If the method is not valid, this will return M_INVALID;
  HttpMethod method = method_fromstring(method_str);
  assert(method != M_INVALID);

  Request* request = arena_alloc(arena, sizeof(Request));
  assert(request);

  // Parse the headers
  request->headers =
    parse_headers(arena, data, &num_headers, &header_end_idx, method, &content_length);
  assert(request->headers);
  assert(num_headers > 0);

  request->method = method;
  request->header_length = num_headers;
  request->body = NULL;
  request->body_length = content_length;
  request->url = NULL;

  // Get the Host header and compose the full url
  cstr* host = headers_loopup(request->headers, num_headers, "host");
  assert(host);

  char url_string[1024];
  snprintf(url_string, 1024, "%s://%s%s", SCHEME, host->data, path);

  request->url = url_parse(arena, url_string);
  assert(request->url);

  // Allocate the body of the request if any and possible.
  // POST, PUT, PATCH, DELETE
  if (!is_safe_method(method) && content_length > 0) {
    request->body = (char*)arena_alloc(arena, content_length + 1);
    assert(request->body);

    // Skip the headers and get the body, copy the body to the request
    size_t body_offset = header_end_idx + 4;  // Skip DOBLE LF
    memcpy((char*)request->body, data->data + body_offset, content_length);
  }

  return request;
}

void request_destroy(Request* request) {
  url_free(request->url);

  if (request->body) {
    free((void*)request->body);
  }
}

const char* find_req_header(Request* req, const char* name, int* index) {
  if (!req || !name || !index) {
    return NULL;
  }

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
