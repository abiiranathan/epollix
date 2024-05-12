
#include <assert.h>
#include <solidc/str.h>
#include <strings.h>

#include "method.h"
#include "request.h"
#include "url.h"

static const char* LF = "\r\n";
static const char* DOUBLE_LF = "\r\n\r\n";
char* SCHEME = "http";

bool parse_headers(const char* req_data, Header* headers, size_t* num_headers,
                   size_t* header_end_idx, HttpMethod method, size_t* content_length) {
  char* header_start = NULL;
  char* header_end = NULL;
  char** header_lines = NULL;
  char* header_substring = NULL;
  size_t start_pos, end_pos;

  // Parse headers from the request
  if ((header_start = strstr(req_data, LF)) == NULL) {
    fprintf(stderr, "cannot parse header start: Invalid HTTP format\n");
    return false;
  }

  if ((header_end = strstr(req_data, DOUBLE_LF)) == NULL) {
    fprintf(stderr, "cannot parse header end: Invalid HTTP format\n");
    return false;
  }

  // Get the position in request data for start of headers
  start_pos = (header_start - req_data) + 2;  // skip LF
  end_pos = header_end - req_data;
  header_substring = string_substr(req_data, start_pos, end_pos);
  if (header_substring == NULL) {
    fprintf(stderr, "unable to extract header substr from request data\n");
    return NULL;
  }

  size_t n;
  header_lines = string_split(header_substring, LF, &n);
  // Split the header lines by LF
  if (header_lines == NULL) {
    fprintf(stderr, "cannot split header lines\n");
    free(header_substring);
    return false;
  }
  free(header_substring);

  bool is_safe = is_safe_method(method);
  size_t valid_headers = 0;

  if (n > 0) {
    for (size_t i = 0; (i < n && i < MAX_REQ_HEADERS); i++) {
      Header header;
      if (header_fromstring(header_lines[i], &header)) {
        headers[valid_headers++] = header;

        // No point getting content-length on GET, OPTIONS methods...
        if (!is_safe && strcasecmp(header.name, "Content-Length") == 0) {
          *content_length = atoi(header.value);
        }
      }
    }
  }

  string_split_free(header_lines, n);
  *header_end_idx = end_pos;
  *num_headers = valid_headers;
  return true;
}

Request* request_parse_http(Arena* arena, const char* req_data) {
  char method_str[10] = {0};
  char path[256] = {0};

  // Parse the request line
  size_t header_end_idx = 0, content_length = 0, num_headers = 0;
  if (sscanf(req_data, "%9s %255s", method_str, path) != 2) {
    fprintf(stderr, "error parsing request line\n");
    return NULL;
  }

  // If the method is not valid, this will return M_INVALID;
  HttpMethod method = method_fromstring(method_str);
  if (method == M_INVALID) {
    fprintf(stderr, "Unknown HTTP method\n");
    return NULL;
  }

  Request* request = arena_alloc(arena, sizeof(Request));
  if (!request) {
    fprintf(stderr, "unable to allocate Request struct\n");
    return NULL;
  }


  // Parse the headers
  memset(request->headers, 0, sizeof(Header) * MAX_REQ_HEADERS);
  if (!parse_headers(req_data, request->headers, &num_headers, &header_end_idx, method,
                     &content_length)) {
    fprintf(stderr, "unable to parse headers\n");
    return NULL;
  }

  if (num_headers == 0) {
    fprintf(stderr, "no headers found\n");
    return NULL;
  }

  // // log the request headers
  // for (size_t i = 0; i < num_headers; i++) {
  //   printf("Header: %s: %s\n", request->headers[i].name, request->headers[i].value);
  // }

  request->method = method;
  request->header_length = num_headers;
  request->body = NULL;
  request->body_length = content_length;
  request->url = NULL;

  // Get the Host header and compose the full url
  char* host = headers_loopup(request->headers, num_headers, "host");
  if (!host) {
    fprintf(stderr, "Host header must be set for proper URL parsing\n");
    return NULL;
  }

  char url_string[1024];
  snprintf(url_string, 1024, "%s://%s%s", SCHEME, host, path);

  request->url = url_parse(url_string);
  if (!request->url) {
    fprintf(stderr, "Unable to parse request URL\n");
    return NULL;
  }

  // Allocate the body of the request if any and possible.
  // POST, PUT, PATCH, DELETE
  if (!is_safe_method(method) && content_length > 0) {
    request->body = (char*)arena_alloc(arena, content_length + 1);
    if (!request->body) {
      perror("unable to allocate request->body");
      return NULL;
    }

    size_t body_offset = header_end_idx + 4;  // Skip DOBLE LF
    memcpy((char*)request->body, req_data + body_offset, content_length);
  }

  return request;
}

void request_destroy(Request* request) {
  url_free(request->url);
  if (request->body) {
    free((void*)request->body);
  }
  // Do not free request as it is allocated in the arena.
}

const char* find_req_header(Request* req, const char* name, int* index) {
  if (index) {
    *index = -1;
  }

  if (!req)
    return NULL;

  for (size_t i = 0; i < req->header_length; i++) {
    if (strcasecmp(name, req->headers[i].name) == 0) {
      if (index) {
        *index = i;
      }
      return req->headers[i].value;
    }
  }
  return NULL;
}
