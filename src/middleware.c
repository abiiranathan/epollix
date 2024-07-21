#include "../include/middleware.h"
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define COLOR_RESET "\x1b[0m"
#define COLOR_RED "\x1b[31m"
#define COLOR_GREEN "\x1b[32m"
#define COLOR_YELLOW "\x1b[33m"
#define COLOR_BLUE "\x1b[34m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_CYAN "\x1b[36m"
#define COLOR_WHITE "\x1b[37m"

// File where the logs will be written
FILE* log_file = NULL;

// Default global log flags
LogFlag log_flags = LOG_DEFAULT;

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

static int running_in_terminal() {
    return isatty(fileno(log_file));
}

// Function to print method with color
static void print_colored_method(const char* method) {
    // Ignore colors if using a file
    if (!running_in_terminal()) {
        fprintf(log_file, "%s ", method);
        return;
    }

    fprintf(log_file, COLOR_CYAN "%s" COLOR_RESET " ", method);
}

// Function to print status code with color
static void print_colored_status(int status) {
    // Ignore colors if using a file
    if (!running_in_terminal()) {
        fprintf(log_file, "%d ", status);
        return;
    }

    if (status >= 200 && status < 300) {
        fprintf(log_file, COLOR_GREEN "%d" COLOR_RESET " ", status);
    } else if (status >= 400 && status < 500) {
        fprintf(log_file, COLOR_YELLOW "%d" COLOR_RESET " ", status);
    } else if (status >= 500) {
        fprintf(log_file, COLOR_RED "%d" COLOR_RESET " ", status);
    } else {
        fprintf(log_file, "%d ", status);  // Default color
    }
}

void epollix_logger(context_t* ctx, Handler next) {
    if (log_flags == LOG_NONE) {
        next(ctx);
        return;
    }

    if (log_file == NULL) {
        log_file = stdout;
    }

    // Get the current time before executing the next handler
    time_t raw_time = time(NULL);
    struct tm* tm_info = localtime(&raw_time);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    next(ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);

    // Lock the mutex for thread-safe printf
    flockfile(log_file);

    if (log_flags & LOG_DATE) {
        fprintf(log_file, "%d-%02d-%02d ", tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
    }

    if (log_flags & LOG_TIME) {
        fprintf(log_file, "%02d:%02d:%02d ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    }

    if (log_flags & LOG_METHOD) {
        print_colored_method(get_method_str(ctx));
    }

    if (log_flags & LOG_PATH) {
        fprintf(log_file, "%s ", get_path(ctx));
    }

    if (log_flags & LOG_STATUS) {
        print_colored_status(get_status(ctx));
    }

    if (log_flags & LOG_LATENCY) {
        // Calculate the elapsed time in microseconds
        long seconds = end.tv_sec - start.tv_sec;
        long nanoseconds = end.tv_nsec - start.tv_nsec;
        long microseconds = seconds * 1000000 + nanoseconds / 1000;
        long milliseconds = microseconds / 1000;

        // Print time in microseconds if less than 1 second, otherwise in milliseconds
        if (seconds == 0 && milliseconds == 0) {
            fprintf(log_file, "%ldµs ", microseconds);
        } else if (seconds >= 1) {
            fprintf(log_file, "%lds ", seconds);
        } else {
            fprintf(log_file, "%ldms ", milliseconds);
        }
    }

    if (log_flags & LOG_IP) {
        char* ip = get_ip_address(ctx);
        if (ip) {
            fprintf(log_file, "%s ", ip);
            free(ip);
        }
    }

    if (log_flags & LOG_USER_AGENT) {
        const char* user_agent = get_header(ctx, "User-Agent");
        if (user_agent) {
            fprintf(log_file, " %s", user_agent);
        }
    }

    fprintf(log_file, "\n");
    fflush(log_file);
    funlockfile(log_file);
}
