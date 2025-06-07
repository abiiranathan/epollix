#define _GNU_SOURCE 1

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../include/middleware/logger.h"
#include "../include/response.h"

#define LOG_BATCH_SIZE 100
#define COLOR_RESET    "\x1b[0m"
#define COLOR_RED      "\x1b[31m"
#define COLOR_GREEN    "\x1b[32m"
#define COLOR_YELLOW   "\x1b[33m"
#define COLOR_BLUE     "\x1b[34m"
#define COLOR_MAGENTA  "\x1b[35m"
#define COLOR_CYAN     "\x1b[36m"
#define COLOR_WHITE    "\x1b[37m]"

// Thread-local buffer for each thread
#define LOG_BUFFER_SIZE 4096

// thread-local storage for logging
__thread char log_buffer[LOG_BUFFER_SIZE] = {0};

typedef struct {
    char buffer[LOG_BUFFER_SIZE];
    size_t offset;
} ThreadLocalBuffer;

// Thread-local buffer for logging
__thread ThreadLocalBuffer thread_buffer = {0};

typedef struct {
    char logs[LOG_BATCH_SIZE][LOG_BUFFER_SIZE];
    size_t count;
    pthread_mutex_t mutex;
} LogBatch;

// Global varibles
LogFlag log_flags         = LOG_DEFAULT;
static LogBatch log_batch = {0};
static FILE* log_file     = NULL;
static pthread_t logger_thread;
static volatile int logger_running = 1;

// Function to check if running in a terminal
static inline int running_in_terminal() {
    return isatty(fileno(log_file));
}

// Dedicated logger thread
void* logger_thread_func(void* arg) {
    (void)(arg);

    while (logger_running) {
        pthread_mutex_lock(&log_batch.mutex);
        if (log_batch.count > 0) {
            for (size_t i = 0; i < log_batch.count; i++) {
                fwrite(log_batch.logs[i], 1, strlen(log_batch.logs[i]), log_file);
            }
            fflush(log_file);
            log_batch.count = 0;
        }
        pthread_mutex_unlock(&log_batch.mutex);
        usleep(1000);  // Sleep for 1ms to avoid busy-waiting
    }
    return NULL;
}

// Initialize the logger
__attribute__((constructor())) void logger_init(void) {
    log_file = stdout;

    pthread_mutex_init(&log_batch.mutex, NULL);
    pthread_create(&logger_thread, NULL, logger_thread_func, NULL);
}

// Shutdown the logger
__attribute__((destructor())) void logger_shutdown(void) {
    logger_running = 0;
    pthread_join(logger_thread, NULL);
    pthread_mutex_destroy(&log_batch.mutex);

    // Close the log file
    if (log_file && log_file != stdout && log_file != stderr && log_file != stdin) {
        fclose(log_file);
    }
}

void epollix_logger(context_t* ctx, Handler next) {
    if (log_flags == LOG_NONE) {
        next(ctx);
        return;
    }

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    next(ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Use thread-local buffer to avoid contention
    ThreadLocalBuffer* buffer = &thread_buffer;
    buffer->offset            = 0;

    // Date and time
    if (log_flags & (LOG_DATE | LOG_TIME)) {
        time_t raw_time    = time(NULL);
        struct tm* tm_info = localtime(&raw_time);
        if (log_flags & LOG_DATE) {
            buffer->offset +=
                strftime(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%Y-%m-%d ", tm_info);
        }
        if (log_flags & LOG_TIME) {
            buffer->offset +=
                strftime(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%H:%M:%S ", tm_info);
        }
    }

    // Method
    if (log_flags & LOG_METHOD) {
        const char* method_str = method_tostring(ctx->request->method);
        if (method_str) {
            if (running_in_terminal()) {
                buffer->offset += snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset,
                                           COLOR_CYAN "%s" COLOR_RESET " ", method_str);
            } else {
                buffer->offset +=
                    snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%s ", method_str);
            }
        }
    }

    // Path
    if (log_flags & LOG_PATH) {
        const char* path = cstr_data_const(ctx->request->path);
        if (path) {
            buffer->offset += snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%s ", path);
        }
    }

    // Status Code
    if (log_flags & LOG_STATUS) {
        int status = ctx->response->status;

        if (running_in_terminal()) {
            switch (status / 100) {
                case 2:
                    buffer->offset += snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset,
                                               COLOR_GREEN "%d" COLOR_RESET " ", status);
                    break;
                case 4:
                    buffer->offset += snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset,
                                               COLOR_YELLOW "%d" COLOR_RESET " ", status);
                    break;
                case 5:
                    buffer->offset += snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset,
                                               COLOR_RED "%d" COLOR_RESET " ", status);
                    break;
                default:
                    buffer->offset +=
                        snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%d ", status);
            }
        } else {
            buffer->offset +=
                snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%d ", status);
        }
    }

    // Latency
    if (log_flags & LOG_LATENCY) {
        long seconds     = end.tv_sec - start.tv_sec;
        long nanoseconds = end.tv_nsec - start.tv_nsec;

        // Adjust nanoseconds if negative (borrow from seconds)
        if (nanoseconds < 0) {
            seconds--;
            nanoseconds += 1000000000L;
        }

        long microseconds = nanoseconds / 1000;
        long milliseconds = microseconds / 1000;

        if (seconds > 0) {
            buffer->offset +=
                snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%lds ", seconds);
        } else if (milliseconds > 0) {
            buffer->offset +=
                snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%ldms ", milliseconds);
        } else if (microseconds > 0) {
            buffer->offset +=
                snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%ldµs ", microseconds);
        } else {
            buffer->offset +=
                snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%ldns ", nanoseconds);
        }
    }

    // IP Address
    if (log_flags & LOG_IP) {
        char* ip = get_ip_address(ctx);
        if (ip) {
            buffer->offset += snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%s ", ip);
            free(ip);
        }
    }

    // User Agent
    if (log_flags & LOG_USER_AGENT) {
        const char* user_agent = headers_value(ctx->request->headers, "User-Agent");
        if (user_agent) {
            buffer->offset +=
                snprintf(buffer->buffer + buffer->offset, LOG_BUFFER_SIZE - buffer->offset, "%s ", user_agent);
        }
    }

    // Add newline
    if (buffer->offset < LOG_BUFFER_SIZE - 1) {
        buffer->buffer[buffer->offset++] = '\n';
        buffer->buffer[buffer->offset]   = '\0';
    }

    // Add to batch
    pthread_mutex_lock(&log_batch.mutex);
    if (log_batch.count < LOG_BATCH_SIZE) {
        // Ensure we never overflow, with explicit truncation
        size_t copy_len = strnlen(buffer->buffer, LOG_BUFFER_SIZE - 1);
        memcpy(log_batch.logs[log_batch.count], buffer->buffer, copy_len);
        log_batch.logs[log_batch.count][copy_len] = '\0';
        log_batch.count++;
    }
    pthread_mutex_unlock(&log_batch.mutex);
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

void set_log_file(FILE* file) {
    if (file) {
        log_file = file;
    }
}
