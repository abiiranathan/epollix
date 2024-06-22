#ifndef A308B9B1_4C38_4C7E_888F_0EFEA346C0CF
#define A308B9B1_4C38_4C7E_888F_0EFEA346C0CF

#include <stdio.h>

// Define a detailed logging macro that logs line number, function name and file name.
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR]: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) fprintf(stdout, "[INFO]: %s:%d:%s(): " fmt, __FILE__, __LINE__, __func__, ##__VA_ARGS__)

// Log fatal errors and exit the program.
#define LOG_FATAL(fmt, ...)                                                                                            \
    do {                                                                                                               \
        LOG_ERROR(fmt, ##__VA_ARGS__);                                                                                 \
        exit(EXIT_FAILURE);                                                                                            \
    } while (0)

#endif /* A308B9B1_4C38_4C7E_888F_0EFEA346C0CF */
