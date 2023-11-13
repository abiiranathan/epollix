#include "http.h"
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PATTERN_LENGTH 256
static Route routeTable[MAX_ROUTES];
static int numRoutes = 0;

// Helper function to register a new route
Route* registerRoute(HttpMethod method, const char* pattern, RouteHandler handler, RouteType type) {
  if (numRoutes == MAX_ROUTES) {
    fprintf(stderr, "Number of routes %d exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
    exit(1);
  }

  Route* route   = &routeTable[numRoutes];
  route->method  = method;
  route->handler = handler;
  route->type    = type;
  memset(route->dirname, 0, sizeof(route->dirname));

  char anchoredPattern[MAX_PATTERN_LENGTH] = {0};

  if (type == NormalRoute) {
    if (strchr(pattern, '^') == NULL && strchr(pattern, '$') == NULL) {
      snprintf(anchoredPattern, sizeof(anchoredPattern), "^%s$", pattern);
    } else if (strchr(pattern, '^') == NULL) {
      snprintf(anchoredPattern, sizeof(anchoredPattern), "^%s", pattern);
    } else if (strchr(pattern, '$') == NULL) {
      snprintf(anchoredPattern, sizeof(anchoredPattern), "%s$", pattern);
    } else {
      strncpy(anchoredPattern, pattern, sizeof(anchoredPattern) - 1);
      anchoredPattern[strlen(pattern) - 1] = '\0';
    }
    route->pattern = strdup(anchoredPattern);
  } else {
    route->pattern = strdup(pattern);
  }

  // Compile the pattern
  int error_code;
  PCRE2_SIZE error_offset;
  route->compiledPattern = pcre2_compile((PCRE2_SPTR)route->pattern, PCRE2_ZERO_TERMINATED, 0,
                                         &error_code, &error_offset, NULL);

  numRoutes++;
  return route;
}

void OPTIONS_ROUTE(const char* pattern, RouteHandler handler) {
  registerRoute(M_OPTIONS, pattern, handler, NormalRoute);
}

void GET_ROUTE(const char* pattern, RouteHandler handler) {
  registerRoute(M_GET, pattern, handler, NormalRoute);
}

void POST_ROUTE(const char* pattern, RouteHandler handler) {
  registerRoute(M_POST, pattern, handler, NormalRoute);
}

void PUT_ROUTE(const char* pattern, RouteHandler handler) {
  registerRoute(M_PUT, pattern, handler, NormalRoute);
}

void PATCH_ROUTE(const char* pattern, RouteHandler handler) {
  registerRoute(M_PATCH, pattern, handler, NormalRoute);
}

void DELETE_ROUTE(const char* pattern, RouteHandler handler) {
  registerRoute(M_DELETE, pattern, handler, NormalRoute);
}

Route* matchExactRoute(HttpMethod method, const char* path) {
  for (int i = 0; i < numRoutes; i++) {
    if (method == routeTable[i].method && strcmp(path, routeTable[i].pattern) == 0 &&
        routeTable[i].type == NormalRoute) {
      return &routeTable[i];
    }

    // Match static routes
    if (strncmp(path, routeTable[i].pattern, strlen(routeTable[i].pattern)) == 0 &&
        routeTable[i].type == StaticRoute) {
      return &routeTable[i];
    }
  }
  return NULL;
}

Route* matchBestRoute(HttpMethod method, const char* path) {
  Route* bestMatch       = NULL;
  size_t bestMatchLength = 0;
  size_t subject_length  = strlen(path);

  for (int i = 0; i < numRoutes; i++) {
    if (routeTable[i].type == NormalRoute) {

      // Use pre-compiled PCRE2 pattern
      int rc;
      pcre2_match_data* match_data = NULL;
      if (routeTable[i].compiledPattern == NULL) {
        fprintf(stderr, "Error: Compiled pattern is NULL for %s\n", routeTable[i].pattern);
        continue;
      }

      match_data = pcre2_match_data_create_from_pattern(routeTable[i].compiledPattern, NULL);
      if (match_data == NULL) {
        printf("Failed to create match data for pattern: %s\n", routeTable[i].pattern);
        return NULL;
      }

      rc = pcre2_match(routeTable[i].compiledPattern, (PCRE2_SPTR)path, subject_length, 0, 0,
                       match_data, NULL);

      if (rc >= 0 && routeTable[i].method == method) {
        size_t matchLength =
          pcre2_get_ovector_pointer(match_data)[1] - pcre2_get_ovector_pointer(match_data)[0];

        if (matchLength == subject_length) {  // Ensure the match covers the entire string
          if (matchLength > bestMatchLength) {
            bestMatch       = &routeTable[i];
            bestMatchLength = matchLength;
          }
        }
      }

      pcre2_match_data_free(match_data);
    } else if (routeTable[i].type == StaticRoute) {
      // Match static route
      if (strncmp(path, routeTable[i].pattern, strlen(routeTable[i].pattern)) == 0 &&
          routeTable[i].type == StaticRoute) {
        bestMatch = &routeTable[i];
        break;
      }
    } else {
      fprintf(stderr, "Unknown route type\n");
      return NULL;
    }
  }

  printf("Best match: %s\n", bestMatch->pattern);
  return bestMatch;
}

void router_cleanup() {
  // Cleanup compiled patterns
  for (int i = 0; i < numRoutes; i++) {
    if (routeTable[i].compiledPattern != NULL) {
      pcre2_code_free(routeTable[i].compiledPattern);
      free(routeTable[i].pattern);
    }
  }
}

// Function to decode URL-encoded strings.
void urldecode(char* dst, size_t dst_size, const char* src) {
  char a, b;
  size_t written = 0;  // Track the number of characters written to dst

  while (*src && written + 1 < dst_size) {  // Ensure there's space for at least one more character
    if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) {
      if (a >= 'a')
        a -= 'a' - 'A';
      if (a >= 'A')
        a -= 'A' - 10;
      else
        a -= '0';
      if (b >= 'a')
        b -= 'a' - 'A';
      if (b >= 'A')
        b -= 'A' - 10;
      else
        b -= '0';
      *dst++ = 16 * a + b;
      src += 3;
      written++;
    } else {
      *dst++ = *src++;
      written++;
    }
  }

  // Null-terminate the destination buffer
  *dst = '\0';
}

// Function to encode a string for use in a URL
char* url_encode(const char* str) {
  // Since each character can be encoded as "%XX" (3 characters),
  // we multiply the length of the input string by 3 and add 1 for the null terminator.
  char* encoded_str = malloc((strlen(str) * 3) + 1);

  if (encoded_str == NULL) {
    perror("url_encode(): Memory allocation failed");
    return NULL;
  }

  // Define a string of hexadecimal digits for percent-encoding
  const char* hex = "0123456789ABCDEF";

  // Initialize an index to keep track of the position in the encoded string
  size_t index = 0;

  // Iterate through each character in the input string
  for (size_t i = 0; i < strlen(str); i++) {
    unsigned char c = str[i];

    // Check if the character is safe and doesn't need encoding
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
        c == '_' || c == '.' || c == '~') {
      encoded_str[index++] = c;
    } else {
      // If the character needs encoding, add '%' to the encoded string
      encoded_str[index++] = '%';

      // Convert the character to its hexadecimal
      // representation and append it to the encoded string
      encoded_str[index++] = hex[(c >> 4) & 0xF];  // High nibble
      encoded_str[index++] = hex[c & 0xF];         // Low nibble
    }
  }

  // Null-terminate the encoded string
  encoded_str[index] = '\0';

  // Return the URL-encoded string
  return encoded_str;
}

// Function to expand the tilde (~) character in a path to
// the user's home directory
char* expandVar(const char* path) {
  const char *homeDir, *tildePosition;
  char* expandedPath;

  if ((homeDir = getenv("HOME")) != NULL && ((tildePosition = strchr(path, '~')) != NULL)) {
    size_t expandedLength = strlen(homeDir) + strlen(tildePosition + 1);
    if ((expandedPath = (char*)malloc(expandedLength + 1))) {
      strcpy(expandedPath, homeDir);
      strcat(expandedPath, tildePosition + 1);
      return expandedPath;
    } else {
      perror("malloc");
    };
  }
  return NULL;
}

static int is_directory(const char* path) {
  struct stat path_stat;
  stat(path, &path_stat);
  return S_ISDIR(path_stat.st_mode);
}

static int is_file(const char* path) {
  struct stat path_stat;
  stat(path, &path_stat);
  return S_ISREG(path_stat.st_mode);
}

// Define a handler function for serving static files
static void staticFileHandler(Context* ctx) {
  const char* dirname       = ctx->route->dirname;
  const char* requestedPath = ctx->request->url->path;

  // trim prefix(context.route.pattern) from requested path
  // e.g /static -> /
  // Trim the prefix from the requested path
  const char* trimmedPath = requestedPath + strlen(ctx->route->pattern);

  // Build the full file path by concatenating the requested path with the directory path
  char fullFilePath[MAX_PATH_SIZE];
  snprintf(fullFilePath, MAX_PATH_SIZE, "%s%s", dirname, trimmedPath);

  char decodedPath[MAX_PATH_SIZE];
  urldecode(decodedPath, sizeof(decodedPath), fullFilePath);

  printf("[STATIC]: %s\n", decodedPath);

  // If it's a directory, append /index.html to decoded path
  if (is_directory(decodedPath)) {
    // temporary buffer to hold the concatenated path
    char tempPath[MAX_PATH_SIZE + 16];

    if (decodedPath[strlen(decodedPath) - 1] == '/') {
      snprintf(tempPath, sizeof(tempPath), "%sindex.html", decodedPath);
    } else {
      snprintf(tempPath, sizeof(tempPath), "%s/index.html", decodedPath);
    }

    // Check if the resulting path is within bounds
    if (strlen(tempPath) < MAX_PATH_SIZE) {
      strcpy(decodedPath, tempPath);
    } else {
      // Handle the case where the concatenated path exceeds the buffer size
      fprintf(stderr, "Error: Concatenated path exceeds buffer size\n");
      char* response = "File Not Found\n";
      set_header(ctx->response, "Content-Type", "text/html");
      set_status(ctx->response, StatusNotFound);
      send_response(ctx, response, strlen(response));
      return;
    }
  }

  // Get the file extension
  char *ptr, *start = decodedPath, *last = NULL;
  while ((ptr = strstr(start, "."))) {
    last = ptr;
    start++;
  }

  // Use the stat function to check if the file exists
  struct stat fileStat;
  if (stat(decodedPath, &fileStat) == 0) {
    if (last) {
      const char* contentType = getWebContentType(decodedPath);
      if (contentType) {
        set_header(ctx->response, "Content-Type", contentType);
      }
    }

    printf("[STATIC]: sending file %s\n", decodedPath);
    send_file(ctx, decodedPath);
    return;
  }

  // Send 404
  char* response = "File Not Found\n";
  set_header(ctx->response, "Content-Type", "text/html");
  set_status(ctx->response, StatusNotFound);
  send_response(ctx, response, strlen(response));
}

void STATIC_DIR(const char* pattern, char* dir) {
  if (strlen(dir) + 1 >= MAX_DIRNAME) {
    fprintf(stderr, "dirname is too long to fit in %d bytes\n", MAX_DIRNAME);
    exit(1);
  }

  char* dirname = expandVar(dir);
  if (dirname == NULL) {
    fprintf(stderr, "unable to find HOME environment variable\n");
    exit(1);
  }

  // Check that dirname exists
  if (access(dirname, F_OK) == -1) {
    fprintf(stderr, "dirname: %s does not exist\n", dirname);
    exit(1);
  }

  size_t dirname_len = strlen(dirname);

  if (dirname[dirname_len - 1] == '/') {
    dirname[dirname_len - 1] = '\0';
  }

  Route* route = registerRoute(M_GET, pattern, staticFileHandler, StaticRoute);
  route->type  = StaticRoute;
  strncpy(route->dirname, dirname, MAX_DIRNAME - 1);
  route->dirname[strlen(dirname)] = '\0';
  free(dirname);
}

// ======================== HTTP RESPONSE ================

typedef struct Response {
  bool chunked;                      // Chunked transfer encoding
  bool stream_complete;              // Chunked transfer completed
  int status;                        // Status code
  char statusText[64];               // Http StatusText
  void* data;                        // Response data
  ssize_t content_length;            // Content-Length
  ssize_t header_count;              // Number of headers
  Header headers[MAX_RESP_HEADERS];  // Headers array

  // track if headers are already sent.
  bool headers_sent;
  // track if headers are already sent
  bool body_sent;

  //   Client file descriptor.
  int client_fd;
} Response;

Response* alloc_response(int client_fd) {
  Response* res = malloc(sizeof(Response));
  if (res) {
    res->status          = 200;
    res->body_sent       = false;
    res->chunked         = false;
    res->header_count    = 0;
    res->stream_complete = false;
    res->body_sent       = false;
    res->data            = NULL;
    res->content_length  = 0;
    res->client_fd       = client_fd;
    set_header(res, "Content-Type", "text/plain");
  }

  // Set default headers
  return res;
}

void response_destroy(Response* res) {
  if (res == NULL)
    return;

  res->data = NULL;
  free(res);
  res = NULL;
}

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go
const char* StatusText(int statusCode) {
  switch (statusCode) {
    case StatusContinue:
      return "Continue";
    case StatusSwitchingProtocols:
      return "Switching Protocols";
    case StatusProcessing:
      return "Processing";
    case StatusEarlyHints:
      return "Early Hints";
    case StatusOK:
      return "OK";
    case StatusCreated:
      return "Created";
    case StatusAccepted:
      return "Accepted";
    case StatusNonAuthoritativeInfo:
      return "Non-Authoritative Information";
    case StatusNoContent:
      return "No Content";
    case StatusResetContent:
      return "Reset Content";
    case StatusPartialContent:
      return "Partial Content";
    case StatusMultiStatus:
      return "Multi-Status";
    case StatusAlreadyReported:
      return "Already Reported";
    case StatusIMUsed:
      return "IM Used";
    case StatusMultipleChoices:
      return "Multiple Choices";
    case StatusMovedPermanently:
      return "Moved Permanently";
    case StatusFound:
      return "Found";
    case StatusSeeOther:
      return "See Other";
    case StatusNotModified:
      return "Not Modified";
    case StatusUseProxy:
      return "Use Proxy";
    case StatusTemporaryRedirect:
      return "Temporary Redirect";
    case StatusPermanentRedirect:
      return "Permanent Redirect";
    case StatusBadRequest:
      return "Bad Request";
    case StatusUnauthorized:
      return "Unauthorized";
    case StatusPaymentRequired:
      return "Payment Required";
    case StatusForbidden:
      return "Forbidden";
    case StatusNotFound:
      return "Not Found";
    case StatusMethodNotAllowed:
      return "Method Not Allowed";
    case StatusNotAcceptable:
      return "Not Acceptable";
    case StatusProxyAuthRequired:
      return "Proxy Authentication Required";
    case StatusRequestTimeout:
      return "Request Timeout";
    case StatusConflict:
      return "Conflict";
    case StatusGone:
      return "Gone";
    case StatusLengthRequired:
      return "Length Required";
    case StatusPreconditionFailed:
      return "Precondition Failed";
    case StatusRequestEntityTooLarge:
      return "Request Entity Too Large";
    case StatusRequestURITooLong:
      return "Request URI Too Long";
    case StatusUnsupportedMediaType:
      return "Unsupported Media Type";
    case StatusRequestedRangeNotSatisfiable:
      return "Requested Range Not Satisfiable";
    case StatusExpectationFailed:
      return "Expectation Failed";
    case StatusTeapot:
      return "I'm a teapot";
    case StatusMisdirectedRequest:
      return "Misdirected Request";
    case StatusUnprocessableEntity:
      return "Unprocessable Entity";
    case StatusLocked:
      return "Locked";
    case StatusFailedDependency:
      return "Failed Dependency";
    case StatusTooEarly:
      return "Too Early";
    case StatusUpgradeRequired:
      return "Upgrade Required";
    case StatusPreconditionRequired:
      return "Precondition Required";
    case StatusTooManyRequests:
      return "Too Many Requests";
    case StatusRequestHeaderFieldsTooLarge:
      return "Request Header Fields Too Large";
    case StatusUnavailableForLegalReasons:
      return "Unavailable For Legal Reasons";
    case StatusInternalServerError:
      return "Internal Server Error";
    case StatusNotImplemented:
      return "Not Implemented";
    case StatusBadGateway:
      return "Bad Gateway";
    case StatusServiceUnavailable:
      return "Service Unavailable";
    case StatusGatewayTimeout:
      return "Gateway Timeout";
    case StatusHTTPVersionNotSupported:
      return "HTTP Version Not Supported";
    case StatusVariantAlsoNegotiates:
      return "Variant Also Negotiates";
    case StatusInsufficientStorage:
      return "Insufficient Storage";
    case StatusLoopDetected:
      return "Loop Detected";
    case StatusNotExtended:
      return "Not Extended";
    case StatusNetworkAuthenticationRequired:
      return "Network Authentication Required";
    default:
      return "";
  }
}

void set_status(Response* res, int statusCode) {
  res->status = statusCode;
}

static void write_headers(Response* res) {
  // don't send headers more than once.
  char status_line[128];    // HTTP/1.1 StatusCode StatusText \r\n
  size_t response_len = 0;  // Keep track of size of headers.

  // Calculate the total response length
  for (int i = 0; i < res->header_count; i++) {
    // 4 accounts for ": " and "\r\n"
    response_len += strlen(res->headers[i].name) + strlen(res->headers[i].value) + 4;
  }
  response_len += 4;  // Account for an additional "\r\n" before the body

  // Allocate memory for header response and http status
  char headerResponse[MAX_RESP_HEADERS * sizeof(Header)] = {0};
  headerResponse[0]                                      = '\0';

  // Set default status code
  if (res->status == 0) {
    res->status = 200;
  }

  strcpy(res->statusText, StatusText(res->status));
  snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u %s\r\n", res->status, res->statusText);
  strcat(headerResponse, status_line);

  // Add headers
  for (int i = 0; i < res->header_count; i++) {
    strcat(headerResponse, res->headers[i].name);
    strcat(headerResponse, ": ");
    strcat(headerResponse, res->headers[i].value);
    strcat(headerResponse, "\r\n");
  }

  // Add an additional line break before the body
  strcat(headerResponse, "\r\n");

  // Send the response headers
  int bytes_sent = send(res->client_fd, headerResponse, strlen(headerResponse), 0);
  if (bytes_sent == -1) {
    perror("send");
    return;
  }

  res->headers_sent = true;
}

// returns number of bytes sent.
// -1 for error and 0 if response if chunked transfer encoding is not set.
static ssize_t send_chunk_size(Response* res, ssize_t size) {
  // Handle the case of chunked transfer encoding
  if (res->chunked) {
    char chunkSize[128];
    sprintf(chunkSize, "%zx\r\n", size);
    int sent = send(res->client_fd, chunkSize, strlen(chunkSize), 0);
    if (sent == -1) {
      perror("send");
    }
    return sent;
  }
  return 0;
}

static bool send_end_of_chunk(Response* res) {
  if (!res->chunked)
    return true;  // nothing to do.

  // Send end of chunk: Send the chunk's CRLF (carriage return and line feed)
  if (send(res->client_fd, "\r\n", 2, 0) == -1) {
    perror("send");
    fprintf(stderr, "error send end of chunk sentinel\n");
    return false;
  };
  res->stream_complete = true;
  return true;
}

static bool send_end_of_request(Response* res) {
  if (!res->chunked || res->stream_complete) {
    return true;
  }

  // Signal the end of the response with a zero-size chunk
  if (send(res->client_fd, "0\r\n\r\n", 5, 0) == -1) {
    perror("send");
    fprintf(stderr, "error send end of end of the response sentinel\n");
    return false;
  };

  res->stream_complete = true;
  return true;
}

const char* find_resp_header(Response* res, const char* name, int* index) {
  if (index) {
    *index = -1;
  }

  if (!res)
    return NULL;

  for (int i = 0; i < res->header_count; i++) {
    if (strcasecmp(name, res->headers[i].name) == 0) {
      if (index) {
        *index = i;
      }
      return res->headers[i].value;
    }
  }

  return NULL;
}

void enable_chunked_transfer(Response* res) {
  if (!res->stream_complete) {
    set_header(res, "Transfer-Encoding", "chunked");
    res->chunked = true;
  }
}

void set_header(Response* res, const char* name, const char* value) {
  if (res->header_count >= MAX_RESP_HEADERS) {
    fprintf(stderr, "Exceeded max response headers: %d\n", MAX_RESP_HEADERS);
    return;
  }

  // check if this header already exists
  int index;
  Header h;
  find_resp_header(res, name, &index);

  if (index == -1) {
    // Header does not exist, append it
    if (new_header(name, value, &h)) {
      res->headers[res->header_count++] = h;
    }
  } else {
    // Replace existine header
    if (new_header(name, value, &h)) {
      res->headers[index] = h;
    }
  }
}

int send_response(Context* ctx, void* data, ssize_t content_length) {
  Response* res = ctx->response;

  res->data            = data;
  res->content_length  = content_length;
  int total_bytes_sent = 0;

  char content_len_str[20];
  if (snprintf(content_len_str, sizeof(content_len_str), "%ld", res->content_length) < 0) {
    perror("snprintf");
    return -1;
  }

  set_header(res, "Content-Length", content_len_str);
  write_headers(res);

  total_bytes_sent = send(res->client_fd, res->data, res->content_length, 0);
  if (total_bytes_sent == -1) {
    perror("send");
    return -1;
  }

  if (!send_end_of_request(res)) {
    perror("send_end_of_request failed\n");
  }
  return total_bytes_sent;
}

bool send_chunk(Response* res, void* data, ssize_t chunk_size) {
  if (!res->chunked) {
    fprintf(stderr, "call to send_chunk before calling enable_chunked_transfer()");
    return false;
  }

  // send headers if not already sent
  write_headers(res);

  // send chunk size
  ssize_t sent_bytes;
  if ((sent_bytes = send_chunk_size(res, chunk_size)) == -1) {
    return false;
  };

  // send chunk
  ssize_t chunk_size_sent = send(res->client_fd, data, chunk_size, 0);
  if (chunk_size_sent != -1) {
    return send_end_of_chunk(res);
  }

  perror("send");
  return false;
}

static void write_range_headers(Response* res, ssize_t start, ssize_t end, off64_t file_size) {
  char content_len[24];
  snprintf(content_len, sizeof(content_len), "%ld", end - start + 1);
  set_header(res, "Accept-Ranges", "bytes");
  set_header(res, "Content-Length", content_len);

  char content_range_str[50];
  snprintf(content_range_str, sizeof(content_range_str), "bytes %ld-%ld/%ld", start, end,
           file_size);
  set_header(res, "Content-Range", content_range_str);

  // Set the appropriate status code for partial content
  set_status(res, StatusPartialContent);
}

int send_file(Context* ctx, const char* filename) {
  Response* res = ctx->response;

  // Guess content-type if not already set
  if (!find_resp_header(res, "Content-Type", NULL)) {
    char mime[96];
    if (get_mime_type(filename, sizeof(mime), mime)) {
      set_header(res, "Content-Type", mime);
    }
  }

  ssize_t start, end;
  const char* range_header = NULL;
  bool valid_range         = false;
  bool has_end_range       = false;

  range_header = find_req_header(ctx->request, "Range", NULL);
  if (range_header) {
    if (strstr(range_header, "bytes=") != NULL) {
      if (sscanf(range_header, "bytes=%ld-%ld", &start, &end) == 2) {
        valid_range   = true;
        has_end_range = true;
      } else if (sscanf(range_header, "bytes=%ld-", &start) == 1) {
        valid_range   = true;
        has_end_range = false;
      };
    }
  }

  // Open the file with ftello64 for large file support
  FILE* file = fopen64(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Unable to open the file\n");
    perror("fopen64");
    set_status(res, StatusInternalServerError);
    write_headers(res);
    return -1;
  }

  // determine file size.
  fseeko64(file, 0, SEEK_END);
  off64_t file_size = ftello64(file);
  fseeko64(file, 0, SEEK_SET);

  // Set appropriate headers for partial content
  if (valid_range) {
    if (start >= file_size) {
      printf("The requested range is outside of the file size\n");
      set_status(res, StatusRequestedRangeNotSatisfiable);
      write_headers(res);
      return -1;
    }

    ssize_t range_chunk_size = (4 * 1024 * 1024) - 1;  // send 4MB
    if (!has_end_range && start >= 0) {
      if (start == 0) {
        end = 1023;  // send first 400 bytes
      } else {
        end = start + range_chunk_size;
        if (end >= file_size) {
          end = file_size - 1;  // End of range
        }
      }
    } else if (start < 0) {
      start = file_size + start;  // filesize - start(from end of file)
      end   = start + range_chunk_size;
      if (end >= file_size) {
        end = file_size - 1;  // End of range
      }
    } else if (end < 0) {
      end = file_size + end;
      if (end >= file_size) {
        end = file_size - 1;  // End of range
      }
    }

    // Sanity checks
    if (start < 0 || end < 0 || end >= file_size) {
      printf("The requested range is outside of the file size\n");
      set_status(res, StatusRequestedRangeNotSatisfiable);
      write_headers(res);
      return -1;
    }

    write_range_headers(res, start, end, file_size);

    // Move file position to the start of the requested range
    if (fseeko64(file, start, SEEK_SET) != 0) {
      set_status(res, StatusRequestedRangeNotSatisfiable);
      perror("fseeko64");
      fclose(file);
      return -1;
    }
  } else {
    // Normal NON-RANGE REQUESTS
    char content_len_str[24];
    if (snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size) < 0) {
      perror("snprintf");
      return -1;
    }
    set_header(res, "Content-Length", content_len_str);
  }

  set_header(res, "Connection", "close");
  write_headers(res);

  // Read and send the file in chunks
  ssize_t total_bytes_sent = 0;
  char buffer[BUFSIZ];
  ssize_t chunk_size;
  ssize_t buffer_size = sizeof(buffer);

  // If it's a valid range request, adjust the buffer size
  if (valid_range) {
    // Ensure the buffer size doesn't exceed the remaining bytes in the requested range
    off64_t remaining_bytes = (end - start + 1);
    buffer_size =
      remaining_bytes < (off64_t)sizeof(buffer) ? remaining_bytes : (off64_t)sizeof(buffer);
  }

  while ((chunk_size = fread(buffer, 1, buffer_size, file)) > 0) {
    ssize_t body_bytes_sent;  // total body bytes
    ssize_t sent = 0;         // total_bytes for this chunk

    while (sent < chunk_size) {
      body_bytes_sent = send(res->client_fd, buffer + sent, chunk_size - sent, 0);

      if (body_bytes_sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          // Handle non-blocking case, e.g., retry the send later
          continue;
        } else {
          perror("send");
          fclose(file);
          return -1;
        }
      } else if (body_bytes_sent == 0) {
        // Connection closed by peer
        fclose(file);
        return total_bytes_sent;
      } else {
        sent += body_bytes_sent;
        total_bytes_sent += body_bytes_sent;
      }
    }

    // If it's a range request, and we've sent the requested range, break out of the loop
    if (valid_range && total_bytes_sent >= (end - start + 1)) {
      break;
    }

    // Update the remaining bytes based on the data sent to the client.
    if (valid_range) {
      off64_t remaining_bytes = (end - start + 1) - total_bytes_sent;
      buffer_size =
        remaining_bytes < (off64_t)sizeof(buffer) ? remaining_bytes : (off64_t)sizeof(buffer);
    }
  }

  fclose(file);
  return total_bytes_sent;
}

bool get_mime_type(const char* filename, size_t buffer_len, char mime_buffer[buffer_len]) {
  // Create a magic object
  magic_t magic_cookie = magic_open(MAGIC_MIME_TYPE);

  if (magic_cookie == NULL) {
    fprintf(stderr, "Unable to initialize libmagic\n");
    return false;
  }

  // Load the default database for libmagic
  if (magic_load(magic_cookie, NULL) != 0) {
    fprintf(stderr, "Cannot load magic database - %s\n", magic_error(magic_cookie));
    magic_close(magic_cookie);
    return false;
  }

  // Determine the MIME type. Possibly NULL
  const char* mime_type = magic_file(magic_cookie, filename);
  // Close the magic object

  size_t mimelen = strlen(mime_type);
  if (mimelen + 1 >= buffer_len) {
    magic_close(magic_cookie);
    fprintf(stderr, "Buffer length should be at least %zu bytes\n", mimelen);
    return false;
  }

  strncpy(mime_buffer, mime_type, buffer_len);
  mime_buffer[mimelen] = '\0';

  magic_close(magic_cookie);
  return true;
}
