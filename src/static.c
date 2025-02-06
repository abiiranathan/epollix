#define _GNU_SOURCE 1

#include "../include/request.h"
#include "../include/response.h"

#include <solidc/arena.h>
#include <solidc/cstr.h>
#include <solidc/filepath.h>

// Flag to enable or disable directory browsing.
static bool browse_enabled = false;

// Not found route is defined by the request.c file.
extern Route* notFoundRoute;

// Enable or disable directory browsing for the server.
// If the requested path is a directory, the server will list the files in the directory.
void enable_directory_browsing(bool enable) {
    browse_enabled = enable;
}

static void send_error_page(context_t* ctx, http_status status) {
    const char* status_str = http_status_text(status);
    char* error_page = nullptr;
    int ret = asprintf(&error_page, "<html><head><title>%d %s</title></head><body><h1>%d %s</h1></body></html>", status,
                       status_str, status, status_str);
    if (ret == -1) {
        LOG_ERROR("Failed to allocate memory for error page\n");
        return;
    }

    set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->response->status = status;
    send_string(ctx, error_page);
    free(error_page);
}

static inline void append_or_error(context_t* ctx, Arena* arena, cstr* response, const char* str) {
    if (!cstr_append(arena, response, str)) {
        LOG_ERROR("Failed to append to response\n");
        send_error_page(ctx, StatusInternalServerError);
        return;
    }
}

// Write human readable file size to buffer. A good buffer size is like >= 32.
static void format_file_size(off_t size, char* buf, size_t buffer_size) {
    char units[][3] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    int i = 0;
    double s = size;

    while (s >= 1024 && i < 8) {
        s /= 1024;
        i++;
    }

    if (i == 0) {
        snprintf(buf, buffer_size, "%ld %s", (long)size, units[i]);
    } else {
        snprintf(buf, buffer_size, "%.0f %s", s, units[i]);
    }
}

static void serve_directory_listing(context_t* ctx, const char* dirname, const char* base_prefix) {
    DIR* dir;
    struct dirent* ent;

    Arena* arena = arena_create(1 * 1024 * 1024);
    if (!arena) {
        LOG_ERROR("Failed to create arena\n");
        send_error_page(ctx, StatusInternalServerError);
        return;
    }

    cstr* html_response = cstr_from(arena,
                                    "<html>"
                                    "<head>"
                                    "<style>"
                                    "body { font-family: Arial, sans-serif; padding: 1rem; }"
                                    "h1 { color: #333; }"
                                    "table { width: 100%; border-collapse: collapse; }"
                                    "th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }"
                                    "th { background-color: #f2f2f2; }"
                                    "a { text-decoration: none; color: #0066cc; }"
                                    "a:hover { text-decoration: underline; }"
                                    ".breadcrumbs { margin-bottom: 20px; }"
                                    ".breadcrumbs a { color: #0066cc; text-decoration: none; }"
                                    ".breadcrumbs a:hover { text-decoration: underline; }"
                                    "</style>"
                                    "</head>"
                                    "<body>"
                                    "<h1>Directory Listing</h1>");

    if (!html_response) {
        LOG_ERROR("Failed to create cstr\n");
        send_error_page(ctx, StatusInternalServerError);
        arena_destroy(arena);
        return;
    }

    // Create breadcrumbs
    append_or_error(ctx, arena, html_response, "<div class=\"breadcrumbs\">");
    append_or_error(ctx, arena, html_response, "<a href=\"/\">Home</a>");

    char* path = strdup(base_prefix);
    if (!path) {
        LOG_ERROR("Failed to allocate memory for path\n");
        set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->response->status = StatusInternalServerError;
        send_string(ctx, "Failed to allocate memory for path");
        arena_destroy(arena);
        return;
    }

    char* token = strtok(path, "/");
    char breadcrumb_path[MAX_PATH_LEN] = {0};

    while (token) {
        strcat(breadcrumb_path, "/");
        strcat(breadcrumb_path, token);
        append_or_error(ctx, arena, html_response, " / <a href=\"");
        append_or_error(ctx, arena, html_response, breadcrumb_path);
        append_or_error(ctx, arena, html_response, "\">");
        append_or_error(ctx, arena, html_response, token);
        append_or_error(ctx, arena, html_response, "</a>");
        token = strtok(nullptr, "/");
    }
    free(path);

    append_or_error(ctx, arena, html_response, "</div>");
    append_or_error(ctx, arena, html_response,
                    "<table>"
                    "<tr><th>Name</th><th>Size</th></tr>");

    if ((dir = opendir(dirname)) != nullptr) {
        while ((ent = readdir(dir)) != nullptr) {
            if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) {
                append_or_error(ctx, arena, html_response, "<tr><td><a target=\"_blank\" rel=\"noreferer\" href=\"");
                // Add base prefix if we are not using / as static prefix.
                if (strcmp(base_prefix, "/") != 0) {
                    append_or_error(ctx, arena, html_response, base_prefix);
                }

                append_or_error(ctx, arena, html_response, "/");
                append_or_error(ctx, arena, html_response, ent->d_name);
                append_or_error(ctx, arena, html_response, "\">");
                append_or_error(ctx, arena, html_response, ent->d_name);
                append_or_error(ctx, arena, html_response, "</a></td>");

                char filepath[MAX_PATH_LEN] = {0};
                snprintf(filepath, MAX_PATH_LEN, "%s/%s", dirname, ent->d_name);

                struct stat st;
                if (stat(filepath, &st) == 0) {
                    if (S_ISDIR(st.st_mode)) {
                        append_or_error(ctx, arena, html_response, "<td>Directory</td>");
                    } else {
                        append_or_error(ctx, arena, html_response, "<td>");
                        char fs[32];
                        format_file_size(st.st_size, fs, sizeof(fs));
                        append_or_error(ctx, arena, html_response, fs);
                        append_or_error(ctx, arena, html_response, "</td>");
                    }
                } else {
                    append_or_error(ctx, arena, html_response, "<td>Unknown</td>");
                }
                append_or_error(ctx, arena, html_response, "</tr>");
            }
        }
        closedir(dir);
    } else {
        // Could not open directory
        set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->response->status = StatusInternalServerError;
        send_string(ctx, "Unable to open directory");
        arena_destroy(arena);
        return;
    }

    append_or_error(ctx, arena, html_response, "</table></body></html>");
    set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->response->status = StatusOK;
    send_string(ctx, html_response->data);
    arena_destroy(arena);
}

void staticFileHandler(context_t* ctx) {
    Request* req = ctx->request;
    Route* route = req->route;

    const char* dirname = route->dirname;

    // Replace . and .. with ./ and ../
    if (strcmp(dirname, ".") == 0) {
        dirname = "./";
    } else if (strcmp(dirname, "..") == 0) {
        dirname = "../";
    }

    // Trim the static pattern from the path
    const char* static_path = req->path + strlen(route->pattern);

    // Concatenate the dirname and the static path
    char fullpath[MAX_PATH_LEN] = {0};
    int n;
    if (dirname[strlen(dirname) - 1] == '/') {
        n = snprintf(fullpath, MAX_PATH_LEN, "%s%s", dirname, static_path);
    } else {
        n = snprintf(fullpath, MAX_PATH_LEN, "%s/%s", dirname, static_path);
    }

    if (n < 0 || n >= MAX_PATH_LEN) {
        char errmsg[256];
        snprintf(errmsg, 256, "%s %d", "The path exceeds the maximum path size of", MAX_PATH_LEN);
        set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->response->status = StatusRequestURITooLong;
        send_response(ctx, errmsg, strlen(errmsg));
        return;
    }

    // Base64 decode the path such that it can be used to access the file system
    // decoding the path is necessary to handle special characters in the path
    // The buffer is large enough to hold the decoded path.
    char filepath[MAX_PATH_LEN] = {0};
    decode_uri(fullpath, filepath, sizeof(filepath));

    // In: solidc/filepath.h
    if (is_dir(filepath)) {
        size_t filepath_len = strlen(filepath);
        // remove the trailing slash
        if (filepath_len > 1 && filepath[filepath_len - 1] == '/') {
            filepath[filepath_len - 1] = '\0';
        }

        char index_file[MAX_PATH_LEN + 16] = {0};
        snprintf(index_file, MAX_PATH_LEN + 16, "%s/index.html", filepath);

        if (!path_exists(index_file)) {
            if (browse_enabled) {
                char prefix[MAX_PATH_LEN] = {0};
                snprintf(prefix, MAX_PATH_LEN, "%s%s", route->pattern, static_path);
                serve_directory_listing(ctx, filepath, prefix);
            } else {
                set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
                ctx->response->status = StatusForbidden;
                send_string(ctx, "<h1>Directory listing is disabled</h1>");
            }
            return;
        } else {
            // Append /index.html to the path
            strncat(filepath, "/index.html", sizeof(filepath) - filepath_len - 1);
        }
    }

    if (path_exists(filepath)) {
        const char* web_ct = get_mimetype(filepath);
        set_response_header(ctx, CONTENT_TYPE_HEADER, web_ct);
        servefile(ctx, filepath);
        return;
    }

    if (notFoundRoute) {
        notFoundRoute->handler(ctx);
        return;
    }

    // Send a 404 response if the file is not found
    const char* response = "File Not Found\n";
    set_response_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->response->status = StatusNotFound;
    send_response(ctx, response, strlen(response));
}
