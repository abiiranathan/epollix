#define _GNU_SOURCE 1

#include "../include/request.h"
#include "../include/response.h"
#include <solidc/cstr.h>
#include <solidc/filepath.h>
#include <solidc/defer.h>

// Flag to enable or disable directory browsing.
static bool browse_enabled = false;

// Not found route is defined by the request.c file.
extern Route* notFoundRoute;

static bool append_breadcrumbs(context_t* ctx, cstr* html, const char* base_prefix);
static bool list_directory_contents(context_t* ctx, cstr* html, const char* dirname, const char* base_prefix);

// Enable or disable directory browsing for the server.
// If the requested path is a directory, the server will list the files in the directory.
void enable_directory_browsing(bool enable) {
    browse_enabled = enable;
}

// Write human readable file size to buffer. A good buffer size is like >= 32.
static void format_file_size(off_t size, char* buf, size_t buffer_size) {
    char units[][3] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    int i    = 0;
    double s = (double)size;

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

static void send_error_page(context_t* ctx, http_status status) {
    const char* status_str = http_status_text(status);
    char* error_page       = NULL;
    int ret = asprintf(&error_page, "<html><head><title>%d %s</title></head><body><h1>%d %s</h1></body></html>", status,
                       status_str, status, status_str);
    if (ret == -1) {
        LOG_ERROR("Failed to allocate memory for error page\n");
        return;
    }

    write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->response->status = status;
    send_string(ctx, error_page);
    free(error_page);
}

static inline bool append_or_error(context_t* ctx, cstr* response, const char* str) {
    bool ok;
    if (!(ok = cstr_append(response, str))) {
        send_error_page(ctx, StatusInternalServerError);
    }
    return ok;
}

/**
 * Generates and serves an HTML directory listing page
 * 
 * @param ctx The HTTP context
 * @param dirname The directory path to list
 * @param base_prefix The base URL prefix for links
 */
static void serve_directory_listing(context_t* ctx, const char* dirname, const char* base_prefix) {
    // Initialize HTML response with header and styles
    cstr* html = cstr_new(
        "<!DOCTYPE html>"
        "<html>"
        "<head>"
        "<meta charset=\"UTF-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">"
        "<title>Directory Listing</title>"
        "<style>"
        "body { font-family: Arial, sans-serif; padding: 1rem; max-width: 1200px; margin: 0 auto; }"
        "h1 { color: #333; margin-bottom: 1rem; }"
        "table { width: 100%; border-collapse: collapse; }"
        "th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }"
        "th { background-color: #f2f2f2; position: sticky; top: 0; }"
        "a { text-decoration: none; color: #0066cc; }"
        "a:hover { text-decoration: underline; }"
        ".breadcrumbs { margin-bottom: 20px; padding: 10px; background-color: #f8f8f8; border-radius: 4px; }"
        ".breadcrumbs a { color: #0066cc; margin: 0 5px; }"
        "</style>"
        "</head>"
        "<body>"
        "<h1>Directory Listing</h1>");

    if (!html) {
        send_error_page(ctx, StatusInternalServerError);
        return;
    }

    // Reserve enough capacity(0.5 MB)
    if (!cstr_resize(html, ((1 << 20) / 2))) {
        send_error_page(ctx, StatusInternalServerError);
        return;
    };

    // defer freeing the string
    defer({ cstr_free(html); });

    // Add breadcrumb navigation
    if (!append_breadcrumbs(ctx, html, base_prefix)) {
        return;
    }

    // Start the table
    if (!append_or_error(ctx, html, "<table><tr><th>Name</th><th>Size</th></tr>")) {
        return;
    }

    // List directory contents
    if (!list_directory_contents(ctx, html, dirname, base_prefix)) {
        return;
    }

    // Close the HTML
    if (!append_or_error(ctx, html, "</table></body></html>")) {
        return;
    }

    // Send the response
    write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->response->status = StatusOK;
    send_string(ctx, cstr_data_const(html));
}

/**
 * Appends breadcrumb navigation to the HTML string
 * 
 * @param ctx The HTTP context
 * @param html The HTML string to append to
 * @param base_prefix The base URL prefix
 * @param arena Memory arena for allocations
 * @return true on success, false on failure
 */
static bool append_breadcrumbs(context_t* ctx, cstr* html, const char* base_prefix) {
    if (!append_or_error(ctx, html, "<div class=\"breadcrumbs\">")) {
        return false;
    }

    if (!append_or_error(ctx, html, "<a href=\"/\">Home</a>")) {
        return false;
    }

    // Skip processing if we're at the root
    if (base_prefix == NULL || base_prefix[0] == '\0' || (base_prefix[0] == '/' && base_prefix[1] == '\0')) {
        if (!append_or_error(ctx, html, "</div>")) {
            return false;
        }
        return true;
    }

    // Allocate and copy the path for tokenization
    char* path = strdup(base_prefix);
    if (!path) {
        write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->response->status = StatusInternalServerError;
        send_string(ctx, "Failed to allocate memory for path");
        return false;
    }
    defer({ free(path); });

    // Build breadcrumb path pieces
    char breadcrumb_path[MAX_PATH_LEN] = {0};
    char* token                        = strtok(path, "/");

    while (token) {
        strcat(breadcrumb_path, "/");
        strcat(breadcrumb_path, token);

        if (!append_or_error(ctx, html, " / <a href=\"") || !append_or_error(ctx, html, breadcrumb_path) ||
            !append_or_error(ctx, html, "\">") || !append_or_error(ctx, html, token) ||
            !append_or_error(ctx, html, "</a>")) {
            return false;
        }

        token = strtok(NULL, "/");
    }

    if (!append_or_error(ctx, html, "</div>")) {
        return false;
    }

    return true;
}

/**
 * Lists directory contents and appends them to the HTML string
 * 
 * @param ctx The HTTP context
 * @param html The HTML string to append to
 * @param dirname The directory to list
 * @param base_prefix The base URL prefix for links
 * @return true on success, false on failure
 */
static bool list_directory_contents(context_t* ctx, cstr* html, const char* dirname, const char* base_prefix) {
    DIR* dir = opendir(dirname);
    if (!dir) {
        write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->response->status = StatusInternalServerError;
        send_string(ctx, "Unable to open directory");
        return false;
    }

    struct dirent* ent;
    while ((ent = readdir(dir)) != NULL) {
        // Skip . and .. entries
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
            continue;
        }

        // Build the file path
        char filepath[MAX_PATH_LEN] = {0};
        snprintf(filepath, MAX_PATH_LEN, "%s/%s", dirname, ent->d_name);

        // Get file information
        struct stat st;
        const char* size_str = "Unknown";
        char size_buf[32]    = {0};

        if (stat(filepath, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                size_str = "Directory";
            } else {
                format_file_size(st.st_size, size_buf, sizeof(size_buf));
                size_str = size_buf;
            }
        }

        // Create the table row
        if (!append_or_error(ctx, html, "<tr><td><a target=\"_blank\" rel=\"noreferer\" href=\"")) {
            closedir(dir);
            return false;
        }

        // Add base prefix if not root
        if (strcmp(base_prefix, "/") != 0) {
            if (!append_or_error(ctx, html, base_prefix)) {
                closedir(dir);
                return false;
            }
        }

        // Add the filename and size
        if (!append_or_error(ctx, html, "/") || !append_or_error(ctx, html, ent->d_name) ||
            !append_or_error(ctx, html, "\">") || !append_or_error(ctx, html, ent->d_name) ||
            !append_or_error(ctx, html, "</a></td><td>") || !append_or_error(ctx, html, size_str) ||
            !append_or_error(ctx, html, "</td></tr>")) {
            closedir(dir);
            return false;
        }
    }

    closedir(dir);
    return true;
}

void staticFileHandler(context_t* ctx) {
    Request* req = ctx->request;
    Route* route = req->route;

    const char* dirname = route->dirname.data;

    // Replace . and .. with ./ and ../
    if (strcmp(dirname, ".") == 0) {
        dirname = "./";
    } else if (strcmp(dirname, "..") == 0) {
        dirname = "../";
    }

    // Trim the static pattern from the path
    const char* static_path = cstr_data(ctx->request->path) + route->pattern.length;

    // Concatenate the dirname and the static path
    char fullpath[MAX_PATH_LEN] = {0};
    int n;
    if (dirname[route->dirname.length - 1] == '/') {
        n = snprintf(fullpath, MAX_PATH_LEN, "%s%s", dirname, static_path);
    } else {
        n = snprintf(fullpath, MAX_PATH_LEN, "%s/%s", dirname, static_path);
    }

    if (n < 0 || n >= MAX_PATH_LEN) {
        char errmsg[256];
        snprintf(errmsg, 256, "%s %d", "The path exceeds the maximum path size of", MAX_PATH_LEN);
        write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
        ctx->response->status = StatusRequestURITooLong;
        send_response(ctx, errmsg, strlen(errmsg));
        return;
    }

    // Base64 decode the path such that it can be used to access the file system
    // decoding the path is necessary to handle special characters in the path
    // The buffer is large enough to hold the decoded path.
    char filepath[MAX_PATH_LEN] = {0};
    url_percent_decode(fullpath, filepath, sizeof(filepath));

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
                snprintf(prefix, MAX_PATH_LEN, "%s%s", route->pattern.data, static_path);
                serve_directory_listing(ctx, filepath, prefix);
            } else {
                write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
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
        write_header(ctx, CONTENT_TYPE_HEADER, web_ct);
        servefile(ctx, filepath);
        return;
    }

    if (notFoundRoute) {
        notFoundRoute->handler(ctx);
        return;
    }

    // Send a 404 response if the file is not found
    const char* response = "File Not Found\n";
    write_header(ctx, CONTENT_TYPE_HEADER, "text/html");
    ctx->response->status = StatusNotFound;
    send_response(ctx, response, strlen(response));
}
