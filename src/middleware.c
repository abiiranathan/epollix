#include "../include/middleware.h"
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

// Default global log flags
LogFlag log_flags = LOG_DEFAULT;

// Get the log flags
LogFlag get_log_flags() {
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

// Function to print method with color
static void print_colored_method(const char* method) {
    printf(COLOR_CYAN "%s" COLOR_RESET " ", method);
}

// Function to print status code with color
static void print_colored_status(int status) {
    if (status >= 200 && status < 300) {
        printf(COLOR_GREEN "%d" COLOR_RESET " ", status);
    } else if (status >= 400 && status < 500) {
        printf(COLOR_YELLOW "%d" COLOR_RESET " ", status);
    } else if (status >= 500) {
        printf(COLOR_RED "%d" COLOR_RESET " ", status);
    } else {
        printf("%d ", status);  // Default color
    }
}

void epollix_logger(context_t* ctx, Handler next) {
    if (log_flags == LOG_NONE) {
        next(ctx);
        return;
    }

    // Get the current time before executing the next handler
    time_t raw_time = time(NULL);
    struct tm* tm_info = localtime(&raw_time);

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    next(ctx);

    clock_gettime(CLOCK_MONOTONIC, &end);

    if (log_flags & LOG_DATE) {
        printf("%d-%02d-%02d ", tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
    }

    if (log_flags & LOG_TIME) {
        printf("%02d:%02d:%02d ", tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec);
    }

    if (log_flags & LOG_METHOD) {
        print_colored_method(get_method_str(ctx));
    }

    if (log_flags & LOG_PATH) {
        printf("%s ", get_path(ctx));
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
            printf("%ldµs ", microseconds);
        } else if (seconds >= 1) {
            printf("%lds ", seconds);
        } else {
            printf("%ldms ", milliseconds);
        }
    }

    if (log_flags & LOG_IP) {
        char* ip = get_ip_address(ctx);
        if (ip) {
            printf("%s ", ip);
            free(ip);
        }
    }

    if (log_flags & LOG_USER_AGENT) {
        const char* user_agent = get_header(ctx, "User-Agent");
        if (user_agent) {
            printf(" %s ", user_agent);
        }
    }

    printf("\n");
}
