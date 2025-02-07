#define _GNU_SOURCE 1

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../include/middleware.h"
#include "../include/middleware/logger.h"
#include "../include/net.h"
#include "../include/response.h"

#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_WHITE "\x1b[37m]"

// File where the logs will be written
FILE* log_file = nullptr;

// Default global log flags
LogFlag log_flags = LOG_DEFAULT;

// Thread-local buffer for each thread
#define LOG_BUFFER_SIZE 4096
__thread char log_buffer[LOG_BUFFER_SIZE] = {0};  // thread-local storage for logging

pthread_mutex_t file_write_mutex = PTHREAD_MUTEX_INITIALIZER;

// Function to check if running in a terminal
static inline int running_in_terminal() {
    return isatty(fileno(log_file));
}

// Optimized logging function
void epollix_logger(context_t* ctx, Handler next) {
    if (log_flags == LOG_NONE) {
        next(ctx);
        return;
    }

    if (log_file == nullptr) {
        log_file = stdout;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    next(ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);

    size_t buffer_offset = 0;
    memset(log_buffer, 0, sizeof(log_buffer));

    // Date and time
    if (log_flags & (LOG_DATE | LOG_TIME)) {
        time_t raw_time = time(nullptr);
        struct tm* tm_info = localtime(&raw_time);
        if (log_flags & LOG_DATE) {
            buffer_offset +=
                strftime(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%Y-%m-%d ", tm_info);
        }
        if (log_flags & LOG_TIME) {
            buffer_offset +=
                strftime(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%H:%M:%S ", tm_info);
        }
    }

    // Method
    if (log_flags & LOG_METHOD) {
        const char* method_str = method_tostring(ctx->request->method);
        if (method_str) {
            if (running_in_terminal()) {
                buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset,
                                          COLOR_CYAN "%s" COLOR_RESET " ", method_str);
            } else {
                buffer_offset +=
                    snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%s ", method_str);
            }
        }
    }

    // Path
    if (log_flags & LOG_PATH) {
        const char* path = ctx->request->path;
        if (path) {
            buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%s ", path);
        }
    }

    // Status Code
    if (log_flags & LOG_STATUS) {
        int status = ctx->response->status;
        if (running_in_terminal()) {
            switch (status / 100) {
                case 2:
                    buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset,
                                              COLOR_GREEN "%d" COLOR_RESET " ", status);
                    break;
                case 4:
                    buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset,
                                              COLOR_YELLOW "%d" COLOR_RESET " ", status);
                    break;
                case 5:
                    buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset,
                                              COLOR_RED "%d" COLOR_RESET " ", status);
                    break;
                default:
                    buffer_offset +=
                        snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%d ", status);
            }
        } else {
            buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%d ", status);
        }
    }

    // Latency
    if (log_flags & LOG_LATENCY) {
        long seconds = end.tv_sec - start.tv_sec;
        long nanoseconds = end.tv_nsec - start.tv_nsec;

        // Adjust nanoseconds if negative (borrow from seconds)
        if (nanoseconds < 0) {
            seconds--;
            nanoseconds += 1000000000L;
        }

        long microseconds = nanoseconds / 1000;
        long milliseconds = microseconds / 1000;

        if (seconds > 0) {
            buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%lds ", seconds);
        } else if (milliseconds > 0) {
            buffer_offset +=
                snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%ldms ", milliseconds);
        } else if (microseconds > 0) {
            buffer_offset +=
                snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%ldµs ", microseconds);
        } else {
            buffer_offset +=
                snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%ldns ", nanoseconds);
        }
    }

    // IP Address
    if (log_flags & LOG_IP) {
        char* ip = get_ip_address(ctx);
        if (ip) {
            buffer_offset += snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%s ", ip);
            free(ip);
        }
    }

    // User Agent
    if (log_flags & LOG_USER_AGENT) {
        const char* user_agent = find_header(ctx->request->headers, ctx->request->header_count, "User-Agent");
        if (user_agent) {
            buffer_offset +=
                snprintf(log_buffer + buffer_offset, sizeof(log_buffer) - buffer_offset, "%s ", user_agent);
        }
    }

    // Add newline
    if (buffer_offset < sizeof(log_buffer) - 1) {
        log_buffer[buffer_offset++] = '\n';
        log_buffer[buffer_offset] = '\0';
    }

    // Write the accumulated log to the file safely
    pthread_mutex_lock(&file_write_mutex);
    fwrite(log_buffer, 1, buffer_offset, log_file);
    fflush(log_file);
    pthread_mutex_unlock(&file_write_mutex);
}

// Get the log flags
LogFlag get_log_flags(void) {
    return log_flags;
}

// Remove the log flags
void remove_log_flags(LogFlag flags) {
    log_flags &= ~flags;
}

// Append the log flags
void append_log_flags(LogFlag flags) {
    log_flags |= flags;
}

// Set the file where the logs will be written
// Default is stdout
void set_log_file(FILE* file) {
    log_file = file;
}
