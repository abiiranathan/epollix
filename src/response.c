#define _GNU_SOURCE     1
#define _POSIX_C_SOURCE 200809L

#include "../include/response.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <solidc/filepath.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../include/request.h"

// Create a new response object.
bool response_init(Response* res, int client_fd) {
    res->client_fd        = client_fd;
    res->status           = StatusOK;
    res->data             = NULL;
    res->headers_sent     = false;
    res->chunked          = false;
    res->content_type_set = false;
    res->headers          = headers_new(16);
    return res->headers != NULL;
}

// Response headers are pre-allocated in the arena.
bool set_response_header(context_t* ctx, const char* name, const char* value) {
    char* header_name  = arena_alloc_string(ctx->arena, name);
    char* header_value = arena_alloc_string(ctx->arena, value);
    if (!header_name || !header_value) {
        LOG_ERROR("Failed to allocate memory for header");
        return false;
    }

    headers_append(ctx->response->headers, header_name, header_value);

    if (!ctx->response->content_type_set && (strcasecmp(name, CONTENT_TYPE_HEADER) == 0)) {
        ctx->response->content_type_set = true;
    }
    return true;
}

void process_response(context_t* ctx) {
    size_t global_count = get_global_middleware_count();
    Route* route        = ctx->request->route;

    // Directly execute the handler if no middleware
    if (route->middleware_count == 0 && global_count == 0) {
        route->handler(ctx);
        return;
    }

    // Define middleware context
    MiddlewareContext mw_ctx = {
        .handler = route->handler,
        .index   = 0,
        .count   = global_count + route->middleware_count,
    };

    // Combine global and route middleware
    Middleware* combined = arena_alloc(ctx->arena, sizeof(Middleware) * mw_ctx.count);
    if (!combined) {
        LOG_ERROR("Failed to allocate memory for combined middleware");
        http_error(ctx->response->client_fd, StatusInternalServerError, "Internal server error");
        return;
    }

    memcpy(combined, get_global_middleware(), global_count * sizeof(Middleware));
    memcpy(combined + global_count, route->middleware, route->middleware_count * sizeof(Middleware));

    mw_ctx.middleware = combined;

    // Store middleware context in request context.
    ctx->mw_ctx = &mw_ctx;

    // Execute middleware chain
    execute_middleware_chain(ctx, &mw_ctx);
}

static void write_headers(context_t* ctx) {
    if (ctx->response->headers_sent) return;

    // Set default status code if not set
    if (ctx->response->status == 0) ctx->response->status = StatusOK;

    char buffer[2048] = {0};
    size_t total_len  = 0;
    ssize_t nbytes_sent;

    // Write status line
    int len = snprintf(buffer, sizeof(buffer), "HTTP/1.1 %d %s\r\n", ctx->response->status,
                       http_status_text(ctx->response->status));
    if (len < 0) {
        LOG_ERROR("Failed to write status line");
        return;
    }
    total_len += len;
    buffer[total_len] = '\0';

    // Write headers
    char* ptr        = buffer + total_len;
    size_t remaining = sizeof(buffer) - total_len;
    if (!headers_tostring(ctx->response->headers, ptr, remaining)) {
        LOG_ERROR("Failed to convert headers to string");
        return;
    };

    // Send the headers to the client
    nbytes_sent = sendall(ctx->response->client_fd, buffer, strlen(buffer));
    if (nbytes_sent == -1) {
        perror("error sending headers");
        return;
    }
    ctx->response->headers_sent = true;
}

void send_status(context_t* ctx, http_status code) {
    ctx->response->status = code;
    write_headers(ctx);
}

// Send the response to the client.
// Returns the number of bytes sent or -1 on error.
ssize_t send_response(context_t* ctx, const char* data, size_t len) {
    char content_len[32];
    snprintf(content_len, sizeof(content_len), "%ld", len);
    set_response_header(ctx, "Content-Length", content_len);
    write_headers(ctx);
    return sendall(ctx->response->client_fd, data, len);
}

ssize_t send_json(context_t* ctx, const char* data, size_t len) {
    set_response_header(ctx, CONTENT_TYPE_HEADER, "application/json");
    return send_response(ctx, data, len);
}

// Send null-terminated JSON string.
ssize_t send_json_string(context_t* ctx, const char* data) {
    return send_json(ctx, data, strlen(data));
}

ssize_t send_string(context_t* ctx, const char* data) {
    return send_response(ctx, data, strlen(data));
}

__attribute__((format(printf, 2, 3))) ssize_t send_string_f(context_t* ctx, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char* buffer = nullptr;

    // Determine the required buffer size
    // See man vsnprintf for more information
    int len = vsnprintf(buffer, 0, fmt, args);
    va_end(args);

    if (len < 0) {
        // there was an error in formatting the string
        return -1;
    }

    // Allocate a buffer of the required size
    buffer = (char*)arena_alloc(ctx->arena, len + 1);  // +1 for the null terminator
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    // Format the string into the allocated buffer
    va_start(args, fmt);
    vsnprintf(buffer, len + 1, fmt, args);
    va_end(args);

    // Send the response
    ssize_t result = send_response(ctx, buffer, len);
    return result;
}

// Writes chunked data to the client.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
ssize_t response_send_chunk(context_t* ctx, const char* data, size_t len) {
    if (!ctx->response->headers_sent) {
        ctx->response->status = StatusOK;
        set_response_header(ctx, "Transfer-Encoding", "chunked");
        write_headers(ctx);
    }

    // Send the chunked header
    char chunked_header[32] = {0};
    int ret                 = snprintf(chunked_header, sizeof(chunked_header), "%zx\r\n", len);
    if (ret >= (int)sizeof(chunked_header)) {
        LOG_ERROR("chunked header truncated");
        // end the chunked response
        response_end(ctx);
        return -1;
    }

    ssize_t nbytes_sent = send(ctx->response->client_fd, chunked_header, strlen(chunked_header), MSG_NOSIGNAL);
    if (nbytes_sent == -1) {
        perror("error sending chunked header");
        response_end(ctx);
        return -1;
    }

    // Send the chunked data
    nbytes_sent = sendall(ctx->response->client_fd, data, len);
    if (nbytes_sent == -1) {
        perror("error sending chunked data");
        response_end(ctx);
        return -1;
    }

    // Send end of chunk: Send the chunk's CRLF (carriage return and line feed)
    if (send(ctx->response->client_fd, "\r\n", 2, MSG_NOSIGNAL) == -1) {
        perror("error send end of chunk sentinel");
        response_end(ctx);
        return false;
    };
    return nbytes_sent;
}

// End the chunked response. Must be called after all chunks have been sent.
ssize_t response_end(context_t* ctx) {
    ssize_t nbytes_sent = sendall(ctx->response->client_fd, "0\r\n\r\n", 5);
    if (nbytes_sent == -1) {
        perror("error sending end of chunked response");
        return -1;
    }
    return nbytes_sent;
}

// redirect to the given url status code set in response. If not set, 303 is used.
void response_redirect(context_t* ctx, const char* url) {
    if (ctx->response->status < StatusMovedPermanently || ctx->response->status > StatusPermanentRedirect) {
        ctx->response->status = StatusSeeOther;
    }

    set_response_header(ctx, "Location", url);
    write_headers(ctx);
}

// Write headers for the Content-Range and Accept-Ranges.
// Also sets the status code for partial content.
static void send_range_headers(context_t* ctx, ssize_t start, ssize_t end, off64_t file_size) {
    int ret;
    char content_len[24];
    ret = snprintf(content_len, sizeof(content_len), "%ld", end - start + 1);

    // This invariant must be respected.
    if (ret >= (int)sizeof(content_len)) {
        LOG_FATAL("send_range_headers(): truncation of content_len\n");
    }

    set_response_header(ctx, "Accept-Ranges", "bytes");
    set_response_header(ctx, "Content-Length", content_len);

    char content_range_str[128];
    ret = snprintf(content_range_str, sizeof(content_range_str), "bytes %ld-%ld/%ld", start, end, file_size);
    // This invariant must be respected.
    if (ret >= (int)sizeof(content_range_str)) {
        LOG_FATAL("send_range_headers(): truncation of content_range_str\n");
    }

    set_response_header(ctx, "Content-Range", content_range_str);
    ctx->response->status = StatusPartialContent;
}

// ==================== sendfile =============================
// Helper function prototypes
static inline bool parse_range(const char* range_header, ssize_t* start, ssize_t* end, bool* has_end_range);
static inline bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size);
static inline ssize_t send_file_content(int client_fd, FILE* file, ssize_t start, ssize_t end, bool is_range_request);
static inline void set_content_disposition(context_t* ctx, const char* filename);

// Main function to serve a file
ssize_t servefile(context_t* ctx, const char* filename) {
    Request* req = ctx->request;

    // Guess content-type if not already set
    if (!ctx->response->content_type_set) {
        set_response_header(ctx, CONTENT_TYPE_HEADER, get_mimetype((char*)filename));
    }

    // Open the file with fopen64 to support large files
    FILE* file = fopen64(filename, "rb");
    if (!file) {
        LOG_ERROR("Unable to open file: %s", filename);
        ctx->response->status = StatusInternalServerError;
        write_headers(ctx);
        return -1;
    }

    // Get the file size
    fseeko64(file, 0, SEEK_END);
    off64_t file_size = ftello64(file);
    if (file_size == -1) {
        perror("ftello64");
        LOG_ERROR("Unable to get file size: %s", filename);
        ctx->response->status = StatusInternalServerError;
        write_headers(ctx);
        return -1;
    }
    fseeko64(file, 0, SEEK_SET);

    // Handle range requests
    ssize_t start = 0, end = 0;
    bool has_end_range = false, range_valid = false;
    const char* range_header = headers_value(req->headers, "Range");

    if (range_header && parse_range(range_header, &start, &end, &has_end_range)) {
        range_valid = validate_range(has_end_range, &start, &end, file_size);
        if (!range_valid) {
            fclose(file);
            ctx->response->status = StatusRequestedRangeNotSatisfiable;
            write_headers(ctx);
            return -1;
        }
        send_range_headers(ctx, start, end, file_size);
    } else {
        // Set content length for non-range requests
        char content_len_str[32];
        snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size);
        set_response_header(ctx, "Content-Length", content_len_str);
        set_content_disposition(ctx, filename);
    }

    write_headers(ctx);
    ssize_t total_bytes_sent = send_file_content(ctx->response->client_fd, file, start, end, range_valid);

    fclose(file);
    return total_bytes_sent;
}

// Serve an already opened file.
// This is useful when the file is already opened by the caller and its not efficient to read
// the contents of the file again.
// The file is not closed by this function.
ssize_t serve_open_file(context_t* ctx, FILE* file, size_t file_size, const char* filename) {
    if (file == nullptr) {
        fprintf(stderr, "FILE*file is NULL\n");
        return -1;
    }

    if (file_size == 0) {
        fprintf(stderr, "file size must be greater than zero\n");
        return -1;
    }

    Request* req = ctx->request;

    // Guess content-type if not already set
    if (!ctx->response->content_type_set) {
        set_response_header(ctx, CONTENT_TYPE_HEADER, get_mimetype((char*)filename));
    }

    // Handle range requests
    ssize_t start = 0, end = 0;
    bool has_end_range = false, range_valid = false;
    const char* range_header = headers_value(req->headers, "Range");

    if (range_header && parse_range(range_header, &start, &end, &has_end_range)) {
        range_valid = validate_range(has_end_range, &start, &end, file_size);
        if (!range_valid) {
            fclose(file);
            ctx->response->status = StatusRequestedRangeNotSatisfiable;
            write_headers(ctx);
            return -1;
        }
        send_range_headers(ctx, start, end, file_size);
    } else {
        // Set content length for non-range requests
        char content_len_str[32];
        snprintf(content_len_str, sizeof(content_len_str), "%ld", file_size);
        set_response_header(ctx, "Content-Length", content_len_str);
        set_content_disposition(ctx, filename);
    }

    write_headers(ctx);
    ssize_t total_bytes_sent = send_file_content(ctx->response->client_fd, file, start, end, range_valid);
    return total_bytes_sent;
}

// Parses the Range header and extracts start and end values
bool parse_range(const char* range_header, ssize_t* start, ssize_t* end, bool* has_end_range) {
    if (strstr(range_header, "bytes=") != nullptr) {
        if (sscanf(range_header, "bytes=%ld-%ld", start, end) == 2) {
            *has_end_range = true;
            return true;
        } else if (sscanf(range_header, "bytes=%ld-", start) == 1) {
            *has_end_range = false;
            return true;
        }
    }
    return false;
}

// Validates the requested range against the file size
bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size) {
    ssize_t startByte = *start, endByte = *end;

    // Send the requested range in chunks of 4MB
    ssize_t byteRangeSize = (4 * 1024 * 1024) - 1;
    if (!has_end_range && startByte >= 0) {
        endByte = startByte + byteRangeSize;
    } else if (startByte < 0) {
        // Http range requests can be negative :) Wieird but true
        // I had to read the RFC to understand this, who would have thought?
        // https://datatracker.ietf.org/doc/html/rfc7233
        startByte = file_size + startByte;      // subtract from the file size
        endByte   = startByte + byteRangeSize;  // send the next 4MB if not more than the file size
    } else if (endByte < 0) {
        // Even the end range can be negative. Deal with it!
        endByte = file_size + endByte;
    }

    // Ensure the end of the range doesn't exceed the file size
    if (endByte >= file_size) {
        endByte = file_size - 1;
    }

    // Ensure the start and end range are within the file size
    if (startByte < 0 || endByte < 0 || endByte >= file_size) {
        return false;
    }

    *start = startByte;
    *end   = endByte;

    return true;
}

// Sends the file content, handling both full and partial responses
static inline ssize_t send_file_content(int client_fd, FILE* file, ssize_t start, ssize_t end, bool is_range_request) {
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size      = 4 << 20;  // 4MB buffer
    int file_fd              = fileno(file);
    off_t offset             = start;
    ssize_t max_range        = end - start + 1;

    if (is_range_request) {
        buffer_size = max_range < buffer_size ? max_range : buffer_size;
    } else {
        fseeko64(file, 0, SEEK_SET);
    }

    // Enable TCP_CORK to avoid small packets
    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));

    while (total_bytes_sent < max_range) {
        ssize_t sent_bytes = sendfile(client_fd, file_fd, &offset, buffer_size);
        if (sent_bytes > 0) {
            total_bytes_sent += sent_bytes;
            if (is_range_request && total_bytes_sent >= max_range) break;
            buffer_size = (max_range - total_bytes_sent) < buffer_size ? (max_range - total_bytes_sent) : buffer_size;
        } else if (sent_bytes == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(5000);  // 5ms delay
                continue;
            } else if (errno != EPIPE) {
                perror("sendfile");
            }
            break;
        }
    }

    // Disable TCP_CORK
    flag = 0;
    setsockopt(client_fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(int));

    return total_bytes_sent;
}

// Sets the Content-Disposition header for the response
void set_content_disposition(context_t* ctx, const char* filename) {
    char content_disposition[512];
    char base_name[256];
    filepath_basename(filename, base_name, sizeof(base_name));
    snprintf(content_disposition, sizeof(content_disposition), "inline; filename=\"%s\"", base_name);
    set_response_header(ctx, "Content-Disposition", content_disposition);
}

void set_content_type(context_t* ctx, const char* content_type) {
    set_response_header(ctx, CONTENT_TYPE_HEADER, content_type);
}
