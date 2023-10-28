#include "response.h"
#include <stdlib.h>
#include <sys/socket.h>
#include "magic.h"

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
    set_header(res, "Connection", "close");
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
    strcpy(res->statusText, StatusText(res->status));
  }

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
    char chunkSize[16];
    sprintf(chunkSize, "%zx\r\n", size);
    int sent = send(res->client_fd, chunkSize, strlen(chunkSize), 0);  // Send the chunk size
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
  *index = -1;

  if (!res)
    return NULL;

  for (int i = 0; i < res->header_count; i++) {
    if (strcasecmp(name, res->headers[i].name) == 0) {
      *index = i;
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

int send_response(Response* res, void* data, ssize_t content_length) {
  res->data            = data;
  res->content_length  = content_length;
  int total_bytes_sent = 0;

  char size_str[100];
  sprintf(size_str, "%ld", res->content_length);
  set_header(res, "Content-Length", size_str);
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

bool send_file(Response* res, const char* filename, ssize_t* total_bytes_sent) {
  char mime[96];
  if (get_mime_type(filename, sizeof(mime), mime)) {
    set_header(res, "Content-Type", mime);
    printf("Set mime type as: %s\n", mime);
  }

  *total_bytes_sent = 0;

  // Open the file with ftello64 for large file support
  FILE* file = fopen64(filename, "rb");
  if (file == NULL) {
    fprintf(stderr, "Unable to open the file\n");
    perror("fopen64");
    return false;
  }

  // determine file size.
  fseeko64(file, 0, SEEK_END);
  off64_t file_size = ftello64(file);
  fseeko64(file, 0, SEEK_SET);

  char size_str[100];
  sprintf(size_str, "%ld", file_size);

  set_header(res, "Content-Length", size_str);
  enable_chunked_transfer(res);

  write_headers(res);

  // Read and send the file in chunks
  char buffer[BUFSIZ];
  size_t chunk_size;

  while ((chunk_size = fread(buffer, 1, sizeof(buffer), file)) > 0) {
    // Send chunk size first.
    ssize_t sent_bytes;
    if ((sent_bytes = send_chunk_size(res, chunk_size)) == -1) {
      return false;
    }

    // send chunk.
    ssize_t body_bytes_sent = send(res->client_fd, buffer, chunk_size, 0);
    if (body_bytes_sent == -1) {
      perror("send");
      return false;
    } else {
      *total_bytes_sent += body_bytes_sent;

      if (!send_end_of_chunk(res)) {
        return false;
      }
    }
  }

  if (ferror(file)) {
    // Handle an error that occurred during file reading
    perror("fread");
    return false;
  }

  if (res->chunked) {
    return send_end_of_request(res);
  }

  return true;
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