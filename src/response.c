#define _GNU_SOURCE 1
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
#include "../include/fast_str.h"
#include "../include/request.h"

// Response headers are pre-allocated in the arena.
bool set_response_header(context_t* ctx, const char* name, const char* value) {
    if (ctx->response->header_count >= MAX_RES_HEADERS)
        return false;

    header_t* header = header_new(name, value, ctx->user_arena);
    if (!header) {
        return false;
    }
    ctx->response->headers[ctx->response->header_count++] = header;

    if (strcasecmp(name, CONTENT_TYPE_HEADER) == 0) {
        ctx->response->content_type_set = true;
    }
    return true;
}

void process_response(Request* req, Response* res, Arena* ctx_arena, Arena* user_arena) {
    res->client_fd = req->client_fd;
    res->content_type_set = false;
    res->status = StatusOK;

    context_t ctx = {
        .request = req,
        .locals = map_create(8, key_compare_char_ptr),
        .response = res,
        .user_arena = user_arena,
    };

    LOG_ASSERT(ctx.locals, "unable to allocate locals map");
    LOG_ASSERT(ctx.user_arena, "unable to allocate user arena");

    Route* route = req->route;

    // If no middleware is defined, execute the handler directly
    size_t globalCount = get_global_middleware_count();
    if (route->middleware_count == 0 && globalCount == 0) {
        route->handler(&ctx);
        free_context(&ctx);
        return;
    }

    // Define middleware context
    MiddlewareContext mw_ctx = {
        .count = 0,
        .index = 0,
        .handler = route->handler,
        .middleware = NULL,
    };

    ctx.mw_ctx = &mw_ctx;

    // if both global and route middleware are defined, combine them
    if (route->middleware_count > 0 && get_global_middleware_count() > 0) {
        // Allocate memory for the combined middleware
        mw_ctx.middleware = merge_middleware(route, &mw_ctx, ctx_arena);
        LOG_ASSERT(mw_ctx.middleware, "error allocating memory for combined middleware");

        // Execute middleware chain
        execute_middleware(&ctx, mw_ctx.middleware, mw_ctx.count, 0, route->handler);
        free_context(&ctx);
        return;
    } else if (route->middleware_count > 0) {
        mw_ctx.middleware = (Middleware*)route->middleware;
        mw_ctx.count = route->middleware_count;
    } else if (globalCount > 0) {
        mw_ctx.middleware = get_global_middleware();
        mw_ctx.count = globalCount;
    }

    // Execute middleware chain and handler
    execute_middleware(&ctx, mw_ctx.middleware, mw_ctx.count, 0, route->handler);

    // free the context
    free_context(&ctx);
}

// Optimized header writing function
static void write_headers(context_t* ctx) {
    if (ctx->response->headers_sent)
        return;

    // Set default status code
    if (ctx->response->status == 0) {
        ctx->response->status = StatusOK;
    }

    char header_res[MAX_RES_HEADER_SIZE];
    char* current = header_res;
    size_t remaining = sizeof(header_res);

    // Efficient status line writing
    const char* status_text = http_status_text(ctx->response->status);

    // Manually copy HTTP version
    memcpy(current, "HTTP/1.1 ", 9);
    current += 9;
    remaining -= 9;

    // Convert status code to string manually
    unsigned int status = ctx->response->status;
    char status_code[4];
    int status_len = 0;
    do {
        status_code[status_len++] = '0' + (status % 10);
        status /= 10;
    } while (status > 0);

    // Reverse the status code string
    for (int i = 0; i < status_len / 2; i++) {
        char temp = status_code[i];
        status_code[i] = status_code[status_len - 1 - i];
        status_code[status_len - 1 - i] = temp;
    }

    // Copy status code
    memcpy(current, status_code, status_len);
    current += status_len;
    remaining -= status_len;

    // Add space
    *current++ = ' ';
    remaining--;

    // Copy status text
    size_t status_text_len = strlen(status_text);
    memcpy(current, status_text, status_text_len);
    current += status_text_len;
    remaining -= status_text_len;

    // Add CRLF
    memcpy(current, "\r\n", 2);
    current += 2;
    remaining -= 2;

    // Add headers
    for (size_t i = 0; i < ctx->response->header_count; i++) {
        // Copy header name
        size_t name_len = strlen(ctx->response->headers[i]->name);
        memcpy(current, ctx->response->headers[i]->name, name_len);
        current += name_len;
        remaining -= name_len;

        // Add ": "
        memcpy(current, ": ", 2);
        current += 2;
        remaining -= 2;

        // Copy header value
        size_t value_len = strlen(ctx->response->headers[i]->value);
        memcpy(current, ctx->response->headers[i]->value, value_len);
        current += value_len;
        remaining -= value_len;

        // Add CRLF
        memcpy(current, "\r\n", 2);
        current += 2;
        remaining -= 2;
    }

    // Append the end of the headers
    if (remaining < 3) {
        LOG_ERROR("No space for final CRLF");
        return;
    }

    memcpy(current, "\r\n", 2);
    current += 2;
    *current = '\0';

    // Send the response headers
    int nbytes_sent = sendall(ctx->response->client_fd, header_res, strlen(header_res));
    if (nbytes_sent == -1) {
        if (errno == EBADF) {
            // Can happen if the client closes the connection before the response is sent.
            // We can safely ignore this error.
        } else {
            LOG_ERROR("%s, fd: %d", strerror(errno), ctx->response->client_fd);
        }
    }
    ctx->response->headers_sent = nbytes_sent != -1;
}

void send_status(context_t* ctx, http_status code) {
    ctx->response->status = code;
    write_headers(ctx);
}

// Send the response to the client.
// Returns the number of bytes sent or -1 on error.
int send_response(context_t* ctx, const char* data, size_t len) {
    char content_len[32];
    snprintf(content_len, sizeof(content_len), "%ld", len);
    set_response_header(ctx, "Content-Length", content_len);
    write_headers(ctx);
    return sendall(ctx->response->client_fd, data, len);
}

int send_json(context_t* ctx, const char* data, size_t len) {
    set_response_header(ctx, CONTENT_TYPE_HEADER, "application/json");
    return send_response(ctx, data, len);
}

// Send null-terminated JSON string.
int send_json_string(context_t* ctx, const char* data) {
    return send_json(ctx, data, strlen(data));
}

int send_string(context_t* ctx, const char* data) {
    return send_response(ctx, data, strlen(data));
}

__attribute__((format(printf, 2, 3))) int send_string_f(context_t* ctx, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char* buffer = NULL;

    // Determine the required buffer size
    // See man vsnprintf for more information
    int len = vsnprintf(buffer, 0, fmt, args);
    va_end(args);

    if (len < 0) {
        // there was an error in formatting the string
        return -1;
    }

    // Allocate a buffer of the required size
    buffer = (char*)malloc(len + 1);  // +1 for the null terminator
    if (!buffer) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    // Format the string into the allocated buffer
    va_start(args, fmt);
    vsnprintf(buffer, len + 1, fmt, args);
    va_end(args);

    // Send the response
    int result = send_response(ctx, buffer, len);

    // Free the allocated buffer
    free(buffer);
    return result;
}

// Writes chunked data to the client.
// Returns the number of bytes written.
// To end the chunked response, call response_end.
// The first-time call to this function will send the chunked header.
int response_send_chunk(context_t* ctx, const char* data, size_t len) {
    if (!ctx->response->headers_sent) {
        ctx->response->status = StatusOK;
        set_response_header(ctx, "Transfer-Encoding", "chunked");
        write_headers(ctx);
    }

    // Send the chunked header
    char chunked_header[32] = {0};
    int ret = snprintf(chunked_header, sizeof(chunked_header), "%zx\r\n", len);
    if (ret >= (int)sizeof(chunked_header)) {
        LOG_ERROR("chunked header truncated");
        // end the chunked response
        response_end(ctx);
        return -1;
    }

    int nbytes_sent = send(ctx->response->client_fd, chunked_header, strlen(chunked_header), MSG_NOSIGNAL);
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
int response_end(context_t* ctx) {
    int nbytes_sent = sendall(ctx->response->client_fd, "0\r\n\r\n", 5);
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
bool parse_range(const char* range_header, ssize_t* start, ssize_t* end, bool* has_end_range);
bool validate_range(bool has_end_range, ssize_t* start, ssize_t* end, off64_t file_size);
ssize_t send_file_content(int client_fd, FILE* file, ssize_t start, ssize_t end, bool is_range_request);
void set_content_disposition(context_t* ctx, const char* filename);

// Main function to serve a file
int servefile(context_t* ctx, const char* filename) {
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
    const char* range_header = find_header(req->headers, req->header_count, "Range");

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
int serve_open_file(context_t* ctx, FILE* file, size_t file_size, const char* filename) {
    Request* req = ctx->request;

    // Guess content-type if not already set
    if (!ctx->response->content_type_set) {
        set_response_header(ctx, CONTENT_TYPE_HEADER, get_mimetype((char*)filename));
    }

    // Handle range requests
    ssize_t start = 0, end = 0;
    bool has_end_range = false, range_valid = false;
    const char* range_header = find_header(req->headers, req->header_count, "Range");

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
    if (boyer_moore_strstr(range_header, "bytes=") != NULL) {
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
        startByte = file_size + startByte;    // subtract from the file size
        endByte = startByte + byteRangeSize;  // send the next 4MB if not more than the file size
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
    *end = endByte;

    return true;
}

// Sends the file content, handling both full and partial responses
ssize_t send_file_content(int client_fd, FILE* file, ssize_t start, ssize_t end, bool is_range_request) {
    ssize_t total_bytes_sent = 0;
    ssize_t buffer_size = 4 << 20;  // 2MB buffer
    int file_fd = fileno(file);
    off_t offset = start;
    ssize_t max_range = end - start + 1;

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
            if (is_range_request && total_bytes_sent >= max_range)
                break;
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
