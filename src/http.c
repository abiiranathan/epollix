#include "../include/http.h"
#include <ctype.h>
#include <solidc/file.h>
#include <solidc/filepath.h>
#include <stdio.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_PATTERN_LENGTH 256
#define MAX_HEADER_SIZE 4096

#ifndef DEFAULT_CONTENT_TYPE
#define DEFAULT_CONTENT_TYPE "text/html"
#endif

static Route routeTable[MAX_ROUTES] = {0};
static int numRoutes = 0;

// ======================== HTTP RESPONSE ================
typedef struct Response {
    bool chunked;           // Chunked transfer encoding
    bool stream_complete;   // Chunked transfer completed
    int client_fd;          // Client file descriptor.
    HttpStatus status;      // Status code
    void* data;             // Response data
    size_t content_length;  // Content-Length

    size_t header_count;               // Number of headers
    Header headers[MAX_RESP_HEADERS];  // Response headers
} Response;

// Helper function to register a new route
Route* registerRoute(HttpMethod method, const char* pattern, RouteHandler handler, RouteType type) {
    if (numRoutes >= MAX_ROUTES) {
        fprintf(stderr, "Number of routes %d exceeds MAX_ROUTES: %d\n", numRoutes, MAX_ROUTES);
        exit(EXIT_FAILURE);
    }

    Route* route = &routeTable[numRoutes];
    route->method = method;
    route->handler = handler;
    route->type = type;
    memset(route->dirname, 0, sizeof(route->dirname));
    route->pattern = strdup(pattern);
    if (route->pattern == NULL) {
        perror("registerRoute(): strdup(): memory allocation failed");
        return NULL;
    }

    route->params = malloc(sizeof(PathParams));
    if (route->params == NULL) {
        perror("registerRoute(): malloc(): memory allocation failed");
        return NULL;
    }

    route->params->match_count = 0;
    memset(route->params->params, 0, sizeof(route->params->params));

    numRoutes++;
    return route;
}

// url_query_param returns the value associated with a query parameter.
// Returns NULL if the parameter is not found.
const char* url_query_param(Context* ctx, const char* name) {
    URL* url = ctx->request->url;
    if (!url || !url->queryParams || !name)
        return NULL;
    return map_get(url->queryParams, (char*)name);
}

// url_path_param returns the value associated with a path parameter.
// Returns NULL if the parameter is not found.
const char* url_path_param(Context* ctx, const char* name) {
    if (!ctx || !ctx->route || !name) {
        return NULL;
    }
    return get_path_param(ctx->route->params, name);
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

Route* matchRoute(HttpMethod method, URL* url) {
    Route* bestMatch = NULL;
    bool matches = false;

    for (int i = 0; i < numRoutes; i++) {
        if (method != routeTable[i].method) {
            continue;
        }

        if (routeTable[i].type == StaticRoute) {
            // For static routes, we match only the prefix as an exact match.
            if (strncmp(routeTable[i].pattern, url->path, strlen(routeTable[i].pattern)) == 0) {
                bestMatch = &routeTable[i];
                break;
            }
        } else {
            matches = match_path_parameters(routeTable[i].pattern, url->path, routeTable[i].params);
            if (matches) {
                bestMatch = &routeTable[i];
                break;
            }
        }
    }
    return bestMatch;
}

void router_cleanup() {
    // Cleanup compiled patterns
    for (int i = 0; i < numRoutes; i++) {
        free(routeTable[i].pattern);
        free(routeTable[i].params);
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
cstr* url_encode(Arena* arena, const cstr* str) {
    // Since each character can be encoded as "%XX" (3 characters),
    // we multiply the length of the input string by 3 and add 1 for the null
    // terminator.
    cstr* encoded_str = cstr_new(arena, str->length * 3 + 1);
    if (encoded_str == NULL) {
        perror("url_encode(): cstr_new(): memory allocation failed");
        return NULL;
    }

    // Define a string of hexadecimal digits for percent-encoding
    const char* hex = "0123456789ABCDEF";

    // Initialize an index to keep track of the position in the encoded string
    size_t index = 0;

    // Iterate through each character in the input string
    for (size_t i = 0; i < str->length; i++) {
        unsigned char c = str->data[i];

        // Check if the character is safe and doesn't need encoding
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            encoded_str->data[index++] = c;
        } else {
            // If the character needs encoding, add '%' to the encoded string
            encoded_str->data[index++] = '%';

            // Convert the character to its hexadecimal
            encoded_str->data[index++] = hex[(c >> 4) & 0xF];  // High nibble
            encoded_str->data[index++] = hex[c & 0xF];         // Low nibble
        }
    }

    encoded_str->data[index] = '\0';
    return encoded_str;
}

// Define a handler function for serving static files
static void staticFileHandler(Context* ctx) {
    const char* dirname = ctx->route->dirname;

    // Trim the static pattern from the path
    const char* static_path = ctx->request->url->path + strlen(ctx->route->pattern);

    // Concatenate the dirname and the static path
    char fullpath[MAX_PATH_SIZE] = {0};

    int n = snprintf(fullpath, MAX_PATH_SIZE, "%s%s", dirname, static_path);
    if (n < 0 || n >= MAX_PATH_SIZE) {
        char errmsg[256];
        snprintf(errmsg, 256, "%s %d", "The path exceeds the maximum path size of", MAX_PATH_SIZE);
        set_header(ctx->response, "Content-Type", "text/html");
        set_status(ctx->response, StatusRequestURITooLong);
        send_response(ctx, errmsg, strlen(errmsg));
        return;
    }

    // Base64 decode the path such that it can be used to access the file system
    // decoding the path is necessary to handle special characters in the path
    // The buffer is large enough to hold the decoded path.
    char filepath[MAX_PATH_SIZE] = {0};
    urldecode(filepath, sizeof(filepath), fullpath);

    if (is_dir(filepath)) {
        size_t filepath_len = strlen(filepath);
        // remove the trailing slash
        if (filepath_len > 1 && filepath[filepath_len - 1] == '/') {
            filepath[filepath_len - 1] = '\0';
        }

        // Append /index.html to the path
        strncat(filepath, "/index.html", sizeof(filepath) - filepath_len - 1);
    }

    if (path_exists(filepath)) {
        char mime[1024];
        if (get_mime_type(filepath, sizeof(mime), mime)) {
            set_header(ctx->response, "Content-Type", mime);
        }
        send_file(ctx, filepath);
        return;
    }

    // Send a 404 response if the file is not found
    char* response = "File Not Found\n";
    set_header(ctx->response, "Content-Type", "text/html");
    set_status(ctx->response, StatusNotFound);
    send_response(ctx, response, strlen(response));
}

// Registers a static directory to serve files from at the specified pattern
void STATIC_DIR(const char* pattern, char* dir) {
    assert(MAX_DIRNAME > strlen(dir) + 1);

    char* dirname = strdup(dir);
    assert(dirname != NULL);

    if (strstr(dirname, "~")) {
        free(dirname);
        dirname = filepath_expanduser(dir);
        assert(dirname != NULL);
    }

    // Check that dirname exists
    if (access(dirname, F_OK) == -1) {
        perror("STATIC_DIR: Directory does not exist");
        free(dirname);
        return;
    }

    size_t dirlen = strlen(dirname);
    if (dirname[dirlen - 1] == '/') {
        dirname[dirlen - 1] = '\0';  // Remove trailing slash
    }

    Route* route = registerRoute(M_GET, pattern, staticFileHandler, StaticRoute);
    assert(route != NULL);

    route->type = StaticRoute;
    snprintf(route->dirname, MAX_DIRNAME, "%s", dirname);
    free(dirname);
}

Response* alloc_response(Arena* arena, int client_fd) {
    Response* res = arena_alloc(arena, sizeof(Response));
    if (!res) {
        return NULL;
    }

    res->status = 200;
    res->chunked = false;
    res->stream_complete = false;
    res->data = NULL;
    res->content_length = 0;
    res->client_fd = client_fd;

    // initialize the headers array
    res->header_count = 0;
    memset(res->headers, 0, sizeof(Header*) * MAX_RESP_HEADERS);

    // Set default headers
    set_header(res, "Content-Type", DEFAULT_CONTENT_TYPE);
    return res;
}

// Status codes and their corresponding text
// This is 4096 bytes in size
static const char* statusTextMap[] = {
    [StatusContinue] = "Continue",
    [StatusSwitchingProtocols] = "Switching Protocols",
    [StatusProcessing] = "Processing",
    [StatusEarlyHints] = "Early Hints",
    [StatusOK] = "OK",
    [StatusCreated] = "Created",
    [StatusAccepted] = "Accepted",
    [StatusNonAuthoritativeInfo] = "Non-Authoritative Information",
    [StatusNoContent] = "No Content",
    [StatusResetContent] = "Reset Content",
    [StatusPartialContent] = "Partial Content",
    [StatusMultiStatus] = "Multi-Status",
    [StatusAlreadyReported] = "Already Reported",
    [StatusIMUsed] = "IM Used",
    [StatusMultipleChoices] = "Multiple Choices",
    [StatusMovedPermanently] = "Moved Permanently",
    [StatusFound] = "Found",
    [StatusSeeOther] = "See Other",
    [StatusNotModified] = "Not Modified",
    [StatusUseProxy] = "Use Proxy",
    [StatusTemporaryRedirect] = "Temporary Redirect",
    [StatusPermanentRedirect] = "Permanent Redirect",
    [StatusBadRequest] = "Bad Request",
    [StatusUnauthorized] = "Unauthorized",
    [StatusPaymentRequired] = "Payment Required",
    [StatusForbidden] = "Forbidden",
    [StatusNotFound] = "Not Found",
    [StatusMethodNotAllowed] = "Method Not Allowed",
    [StatusNotAcceptable] = "Not Acceptable",
    [StatusProxyAuthRequired] = "Proxy Authentication Required",
    [StatusRequestTimeout] = "Request Timeout",
    [StatusConflict] = "Conflict",
    [StatusGone] = "Gone",
    [StatusLengthRequired] = "Length Required",
    [StatusPreconditionFailed] = "Precondition Failed",
    [StatusRequestEntityTooLarge] = "Request Entity Too Large",
    [StatusRequestURITooLong] = "Request URI Too Long",
    [StatusUnsupportedMediaType] = "Unsupported Media Type",
    [StatusRequestedRangeNotSatisfiable] = "Requested Range Not Satisfiable",
    [StatusExpectationFailed] = "Expectation Failed",
    [StatusTeapot] = "I'm a teapot",
    [StatusMisdirectedRequest] = "Misdirected Request",
    [StatusUnprocessableEntity] = "Unprocessable Entity",
    [StatusLocked] = "Locked",
    [StatusFailedDependency] = "Failed Dependency",
    [StatusTooEarly] = "Too Early",
    [StatusUpgradeRequired] = "Upgrade Required",
    [StatusPreconditionRequired] = "Precondition Required",
    [StatusTooManyRequests] = "Too Many Requests",
    [StatusRequestHeaderFieldsTooLarge] = "Request Header Fields Too Large",
    [StatusUnavailableForLegalReasons] = "Unavailable For Legal Reasons",
    [StatusInternalServerError] = "Internal Server Error",
    [StatusNotImplemented] = "Not Implemented",
    [StatusBadGateway] = "Bad Gateway",
    [StatusServiceUnavailable] = "Service Unavailable",
    [StatusGatewayTimeout] = "Gateway Timeout",
    [StatusHTTPVersionNotSupported] = "HTTP Version Not Supported",
    [StatusVariantAlsoNegotiates] = "Variant Also Negotiates",
    [StatusInsufficientStorage] = "Insufficient Storage",
    [StatusLoopDetected] = "Loop Detected",
    [StatusNotExtended] = "Not Extended",
    [StatusNetworkAuthenticationRequired] = "Network Authentication Required",

};

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
// https://go.dev/src/net/http/status.go
const char* StatusText(HttpStatus statusCode) {
    if (statusCode < StatusContinue || statusCode > StatusNetworkAuthenticationRequired) {
        return "";
    }

    const char* st = statusTextMap[statusCode];
    // if status code is not found, return an empty string
    if (st == NULL) {
        return "";
    }
    return st;
}

void set_status(Response* res, HttpStatus statusCode) {
    res->status = statusCode;
}

static void write_headers(Response* res) {
    // Set default status code
    if (res->status == 0) {
        res->status = StatusOK;
    }

    size_t written = 0;
    char status_line[128] = {0};
    char header_res[MAX_HEADER_SIZE] = {0};

    snprintf(status_line, sizeof(status_line), "HTTP/1.1 %u %s\r\n", res->status, StatusText(res->status));

    // Write the status line to the header
    snprintf(header_res, sizeof(header_res), "%s", status_line);
    written += strlen(status_line);

    // Add headers
    for (size_t i = 0; i < res->header_count; i++) {
        char header[MAX_HEADER_NAME + MAX_HEADER_VALUE + 4] = {0};
        header_tostring(&res->headers[i], header, sizeof(header));

        // append \r\n to the end of header
        strncat(header, "\r\n", sizeof(header) - strlen(header) - 1);

        size_t header_len = strlen(header);
        if (written + header_len >= MAX_HEADER_SIZE - 4) {  // 4 is for the \r\n\r\n
            fprintf(stderr, "Exceeded max header size: %d\n", MAX_HEADER_SIZE);
            return;
        }

        // Append the header to the response headers
        strncat(header_res, header, sizeof(header_res) - written);
        written += header_len;
    }

    // Append the end of the headers
    strncat(header_res, "\r\n", sizeof(header_res) - written);
    written += 2;
    header_res[written] = '\0';

    // Send the response headers
    // MSG_NOSIGNAL: Do not generate a SIGPIPE signal if the peer
    // on a stream-oriented socket has closed the connection.
    int nbytes_sent = send(res->client_fd, header_res, strlen(header_res), MSG_NOSIGNAL);
    if (nbytes_sent == -1) {
        perror("write_headers() failed");
    }
}

// Sends the chunk size in the format required by chunked transfer encoding
// Returns the number of bytes sent or -1 on error or if the response is not chunked
static ssize_t send_chunk_size(Response* res, ssize_t size) {
    if (res->chunked) {
        char chunkSize[128];
        sprintf(chunkSize, "%zx\r\n", size);
        int sent = send(res->client_fd, chunkSize, strlen(chunkSize), MSG_NOSIGNAL);
        if (sent == -1) {
            perror("send");
        }
        return sent;
    }
    return -1;
}

static bool send_end_of_chunk(Response* res) {
    if (!res->chunked)
        return true;  // nothing to do.

    // Send end of chunk: Send the chunk's CRLF (carriage return and line feed)
    if (send(res->client_fd, "\r\n", 2, MSG_NOSIGNAL) == -1) {
        perror("error send end of chunk sentinel");
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
    if (send(res->client_fd, "0\r\n\r\n", 5, MSG_NOSIGNAL) == -1) {
        perror("error send end of end of the response sentinel");
        return false;
    };

    res->stream_complete = true;
    return true;
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

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    if (name_len >= MAX_HEADER_NAME || value_len >= MAX_HEADER_VALUE) {
        fprintf(stderr, "Header name or value exceeds max length: (%d, %d)\n", MAX_HEADER_NAME, MAX_HEADER_VALUE);
        return;
    }

    // Check if this header already exists
    int index = find_header_index(res->headers, res->header_count, name);
    if (index == -1) {
        res->headers[res->header_count++] = new_header(name, value);
    } else {
        // Replace header value
        snprintf(res->headers[index].value, MAX_HEADER_VALUE, "%s", value);
    }
}

int send_response(Context* ctx, void* data, ssize_t content_length) {
    Response* res = ctx->response;

    res->data = data;
    res->content_length = content_length;
    int total_bytes_sent = 0;

    char content_len_str[20];
    if (snprintf(content_len_str, sizeof(content_len_str), "%ld", res->content_length) < 0) {
        perror("snprintf");
        return -1;
    }

    set_header(res, "Content-Length", content_len_str);
    write_headers(res);

    total_bytes_sent = send(res->client_fd, res->data, res->content_length, MSG_NOSIGNAL);
    if (total_bytes_sent == -1) {
        perror("send_response failed");
        return total_bytes_sent;
    }

    if (!send_end_of_request(res)) {
        perror("send_end_of_request failed\n");
        return -1;
    }
    return total_bytes_sent;
}

// chunk size is the size of the data to be sent
// format: chunk-size [ chunk-extension ] CRLF
bool send_chunk(Response* res, void* data, ssize_t chunk_size) {
    if (!res->chunked) {
        fprintf(stderr, "call to send_chunk before calling enable_chunked_transfer()");
        return false;
    }

    write_headers(res);

    // send chunk size
    ssize_t sent_bytes;
    if ((sent_bytes = send_chunk_size(res, chunk_size)) == -1) {
        return false;
    };

    // send chunk data
    ssize_t chunk_size_sent = send(res->client_fd, data, chunk_size, MSG_NOSIGNAL);
    if (chunk_size_sent == -1) {
        perror("send");
        return false;
    }
    // send end of chunk
    return send_end_of_chunk(res);
}

static void send_range_headers(Response* res, ssize_t start, ssize_t end, off64_t file_size) {
    char content_len[24];
    snprintf(content_len, sizeof(content_len), "%ld", end - start + 1);
    set_header(res, "Accept-Ranges", "bytes");
    set_header(res, "Content-Length", content_len);

    char content_range_str[128];
    snprintf(content_range_str, sizeof(content_range_str), "bytes %ld-%ld/%ld", start, end, file_size);
    set_header(res, "Content-Range", content_range_str);

    // Set the appropriate status code for partial content
    set_status(res, StatusPartialContent);
}

int send_file(Context* ctx, const char* filename) {
    Response* res = ctx->response;
    assert(res);

    // Guess content-type if not already set
    if (find_header(res->headers, res->header_count, "Content-Type") != NULL) {
        char mime[1024];
        if (get_mime_type(filename, sizeof(mime), mime)) {
            set_header(res, "Content-Type", mime);
        }
    }

    ssize_t start = 0, end = 0;
    const char* range_header = NULL;
    bool is_range_request = false;
    bool has_end_range = false;

    range_header = find_header(ctx->request->headers, ctx->request->header_length, "Range");
    if (range_header) {
        if (strstr(range_header, "bytes=") != NULL) {
            if (sscanf(range_header, "bytes=%ld-%ld", &start, &end) == 2) {
                is_range_request = true;
                has_end_range = true;
            } else if (sscanf(range_header, "bytes=%ld-", &start) == 1) {
                is_range_request = true;
                has_end_range = false;
            };
        }
    }

    // Open the file with fopen64 to support large files
    FILE* file = fopen64(filename, "rb");
    if (file == NULL) {
        perror("fopen64");
        set_status(res, StatusInternalServerError);
        write_headers(res);
        return -1;
    }

    // Get the file size
    fseeko64(file, 0, SEEK_END);
    off64_t file_size = ftello64(file);
    fseeko64(file, 0, SEEK_SET);

    // Set appropriate headers for partial content
    if (is_range_request) {
        if (start >= file_size) {
            set_status(res, StatusRequestedRangeNotSatisfiable);
            write_headers(res);
            fclose(file);
            return -1;
        }

        // Send the requested range in chunks of 4MB
        ssize_t byteRangeSize = (4 * 1024 * 1024) - 1;
        if (!has_end_range && start >= 0) {
            end = start + byteRangeSize;
        } else if (start < 0) {
            // Http range requests can be negative :) Wieird but true
            // I had to read the RFC to understand this, who would have thought?
            // https://datatracker.ietf.org/doc/html/rfc7233
            start = file_size + start;    // subtract from the file size
            end = start + byteRangeSize;  // send the next 4MB if not more than the file size
        } else if (end < 0) {
            // Even the end range can be negative. Deal with it!
            end = file_size + end;
        }

        // Ensure the end of the range doesn't exceed the file size
        if (end >= file_size) {
            end = file_size - 1;
        }

        // Ensure the start and end range are within the file size
        if (start < 0 || end < 0 || end >= file_size) {
            set_status(res, StatusRequestedRangeNotSatisfiable);
            write_headers(res);
            fclose(file);
            return -1;
        }

        send_range_headers(res, start, end, file_size);

        // Move file position to the start of the requested range
        if (fseeko64(file, start, SEEK_SET) != 0) {
            set_status(res, StatusRequestedRangeNotSatisfiable);
            perror("fseeko64");
            fclose(file);
            return -1;
        }
    } else {
        // Set the content length header for the non-range request
        char content_len_str[32];
        if (snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size) < 0) {
            perror("snprintf");
            fclose(file);
            return -1;
        }

        // Set the content length header if it's not a range request
        set_header(res, "Content-Length", content_len_str);
    }

    // Write the headers to the client
    write_headers(res);

    ssize_t total_bytes_sent = 0;           // Total bytes sent to the client
    off64_t buffer_size = 2 * 1024 * 1024;  // 2MB buffer size

    if (is_range_request) {
        // Ensure the buffer size doesn't exceed the remaining bytes in the requested range
        off64_t remaining_bytes = (end - start + 1);  // +1 to include the end byte

        //Adjust the buffer size to the remaining bytes if it's less than the buffer size
        buffer_size = remaining_bytes < buffer_size ? remaining_bytes : buffer_size;
    } else {
        // Set the buffer size to the file size if it's less than the buffer size
        buffer_size = file_size < buffer_size ? file_size : buffer_size;
    }

    // Offset to start reading the file from
    off_t offset = start;
    ssize_t sent_bytes = -1;
    int file_fd = fileno(file);
    int max_range = end - start + 1;

    // Send the file using sendfile to avoid copying data from the kernel to user space
    // This is more efficient than read/write
    // See man sendfile(2) for more information
    while (total_bytes_sent < file_size || (is_range_request && total_bytes_sent < max_range)) {
        sent_bytes = sendfile(res->client_fd, file_fd, &offset, buffer_size);
        if (sent_bytes > 0) {
            total_bytes_sent += sent_bytes;

            // If it's a range request, and we've sent the requested range, break out of
            // the loop
            if (is_range_request && total_bytes_sent >= max_range) {
                break;
            }

            // Update the remaining bytes based on the data sent to the client.
            if (is_range_request) {
                off64_t remaining_bytes = max_range - total_bytes_sent;

                // Adjust the buffer size to the remaining bytes if it's less than the buffer size
                buffer_size = remaining_bytes < buffer_size ? remaining_bytes : buffer_size;
            }
        } else if (sent_bytes == -1) {
            // Handle potential sendfile errors
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Retry sendfile after a short delay
                usleep(1000);  // 1ms delay

                // Continue the loop and retry sending the current buffer
                continue;
            } else {
                if (errno == EPIPE) {
                    // client disconnected. Nothing to report
                } else {
                    perror("sendfile");
                }
                fclose(file);
                return -1;
            }
        }
    }

    if (sent_bytes == -1) {
        if (errno == EPIPE) {
            // client disconnected. Nothing to report
        } else {
            perror("sendfile");
        }

        fclose(file);
        return -1;
    }

    fclose(file);
    return total_bytes_sent;
}

// Magic number for the libmagic cookie
static magic_t magic_cookie = NULL;

void initialize_libmagic(void) {
    static bool initialized = false;
    if (!initialized) {
        // Create a magic object
        magic_cookie = magic_open(MAGIC_MIME_TYPE);
        if (magic_cookie == NULL) {
            fprintf(stderr, "Unable to initialize libmagic\n");
            exit(EXIT_FAILURE);
        }

        // Load the default database for libmagic
        if (magic_load(magic_cookie, NULL) != 0) {
            fprintf(stderr, "Cannot load magic database - %s\n", magic_error(magic_cookie));
            magic_close(magic_cookie);
            exit(EXIT_FAILURE);
        }
        initialized = true;
    }
}

void cleanup_libmagic(void) {
    if (magic_cookie != NULL) {
        magic_close(magic_cookie);
    }
}

bool get_mime_type(const char* filename, size_t buffer_len, char mime_buffer[static buffer_len]) {
    if (magic_cookie == NULL) {
        fprintf(stderr, "libmagic not initialized\n");
        return false;
    }

    // Determine the MIME type.
    const char* mime_type = magic_file(magic_cookie, filename);
    if (mime_type == NULL) {
        fprintf(stderr, "Cannot determine MIME type - %s\n", magic_error(magic_cookie));
        return false;
    }

    // Close the magic object
    size_t mimelen = strlen(mime_type);
    if (mimelen + 1 >= buffer_len) {
        fprintf(stderr, "Buffer length should be at least %zu bytes\n", mimelen);
        return false;
    }

    snprintf(mime_buffer, buffer_len, "%s", mime_type);
    return true;
}

// Send string
int send_string(Context* ctx, const char* data) {
    return send_response(ctx, (void*)data, strlen(data));
}

int send_json(Context* ctx, const char* data) {
    set_header(ctx->response, "Content-Type", "application/json");
    return send_response(ctx, (void*)data, strlen(data));
}

// Send error
void send_error(Context* ctx, HttpStatus status) {
    if (status < StatusBadRequest || status > StatusNetworkAuthenticationRequired) {
        status = StatusInternalServerError;
    }

    Response* res = ctx->response;
    set_status(res, status);
    write_headers(res);
    send_string(ctx, StatusText(status));
}

void send_html_error(Context* ctx, HttpStatus status, const char* message) {
    if (status < StatusBadRequest || status > StatusNetworkAuthenticationRequired) {
        status = StatusInternalServerError;
    }

    Response* res = ctx->response;
    set_status(res, status);
    write_headers(res);
    send_string(ctx, message);
}

// redirect to the given url with a 302 status code
void redirect(Context* ctx, const char* url) {
    Response* res = ctx->response;
    set_status(res, StatusFound);
    set_header(res, "Location", url);
    write_headers(res);
}

// redirect to the given url with a custom status code
void redirect_with_status(Context* ctx, const char* url, HttpStatus status) {
    Response* res = ctx->response;
    set_status(res, status);
    set_header(res, "Location", url);
    write_headers(res);
}
