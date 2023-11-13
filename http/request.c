#include "request.h"
#include "method.h"

#include <assert.h>
#include "str.h"
#include "url.h"


static const char* LF        = "\r\n";
static const char* DOUBLE_LF = "\r\n\r\n";
char* SCHEME                 = "http";

size_t parse_headers(const char* req_data, Header* headers, size_t* header_end_idx,
                     HttpMethod method, size_t* content_length) {
  size_t num_headers = 0;
  memset(headers, 0, sizeof(Header) * MAX_REQ_HEADERS);

  // Parse headers from the request
  char* header_start = strstr(req_data, LF);
  if (!header_start) {
    fprintf(stderr, "cannot parse header start: Invalid HTTP format\n");
    return -1;
  }

  size_t header_start_idx = (header_start - req_data) + 2;  // skip LF
  char* header_end        = strstr(req_data, DOUBLE_LF);
  if (!header_end) {
    fprintf(stderr, "cannot parse header end: Invalid HTTP format\n");
    return -1;
  }

  *header_end_idx      = header_end - req_data;
  size_t header_length = *header_end_idx - header_start_idx;

  char* header_substring = malloc(header_length + 1);
  if (!header_substring) {
    fprintf(stderr, "cannot allocate header_substring\n");
    return -1;
  }

  memcpy(header_substring, req_data + header_start_idx, header_length);
  header_substring[header_length] = '\0';

  // Parse headers from substring and update num_headers.
  Str* hsubstr = str_new(header_substring);
  if (!hsubstr) {
    return -1;
  }
  // Free header substring
  free(header_substring);

  char** header_lines = str_split(hsubstr, "\r\n", &num_headers);
  str_free(hsubstr);

  bool is_safe = is_safe_method(method);
  if (num_headers > 0) {
    size_t invalid_headers = 0;
    for (size_t i = 0; (i < num_headers && i < MAX_REQ_HEADERS); i++) {
      Header h;
      if (header_fromstring(header_lines[i], &h)) {
        headers[i] = h;
        if (!is_safe) {
          if (strcmp(h.name, "Content-Length") == 0 || strcmp(h.name, "content-length") == 0) {
            *content_length = atoi(h.value);
          }
        }
      } else {
        invalid_headers++;
      }
    }

    str_free_substrings(header_lines, num_headers);
    num_headers -= invalid_headers;
  }

  return num_headers;
}

Request* request_parse_http(const char* req_data) {
  char method_str[10] = {0};
  char path[256]      = {0};

  size_t header_end_idx = 0, content_length = 0, num_headers = 0;
  // Parse the request line
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

  Request* request = malloc(sizeof(Request));
  if (!request) {
    fprintf(stderr, "unable to allocate Request struct\n");
    return NULL;
  }

  num_headers = parse_headers(req_data, request->headers, &header_end_idx, method, &content_length);
  request->method        = method;
  request->header_length = num_headers;
  request->body          = NULL;
  request->body_length   = content_length;
  request->url           = NULL;

  // Get the Host header and compose the full url
  char* host = headers_loopup(request->headers, num_headers, "Host");
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
    request->body = (char*)malloc(content_length + 1);

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
  if (!request)
    return;

  // Free request URL parts
  url_free(request->url);

  // free request body if any
  if (request->body) {
    free((void*)request->body);
    request->body = NULL;
  }

  // free request
  free(request);
  request = NULL;
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


#if 0
void assert_string_equal(const char* s, const char* s2) {
  assert(strcmp(s, s2) == 0);
}

int main(void) {
  const char* http_request =
    "POST /submit-data HTTP/1.1\r\n"
    "Host: www.example.com\r\n"
    "Content-Type: application/json\r\n"
    "Accept: application/json\r\n"
    "Content-Length: 25\r\n\r\n"      // Specify the content length
    "{\"data\": \"Hello, World!\"}";  // Request body

  Request* req = request_parse_http(http_request);
  assert(req != NULL);
  assert(req->method == M_POST);
  assert_string_equal(req->url->path, "/submit-data");
  assert(req->header_length == 4);

  // Print the components
  printf("Scheme: %s\n", req->url->scheme);
  printf("Host: %s\n", req->url->host);
  printf("Port: %s\n", req->url->port);
  printf("Path: %s\n", req->url->path);
  printf("Query: %s\n", req->url->query);
  printf("Fragment: %s\n", req->url->fragment);

  for (size_t i = 0; i < req->header_length; i++) {
    char buf[1024];
    header_tostring(&req->headers[i], buf, 1024);
    printf("%s\n", buf);
  }

  assert(req->body_length == 25);
  assert_string_equal(req->body, "{\"data\": \"Hello, World!\"}");
  request_destroy(req);

  const char* url = "http://www.example.com/path/to/page?query=123#section";
  URL* parsedUrl  = url_parse(url);

  // Print the components
  printf("Scheme: %s\n", parsedUrl->scheme);
  printf("Host: %s\n", parsedUrl->host);
  printf("Port: %s\n", parsedUrl->port);
  printf("Path: %s\n", parsedUrl->path);
  printf("Query: %s\n", parsedUrl->query);
  printf("Fragment: %s\n", parsedUrl->fragment);

  url_free(parsedUrl);
}
#endif
