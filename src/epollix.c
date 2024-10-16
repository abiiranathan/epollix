#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>  // TCP_NODELAY, TCP_CORK
#include <stdarg.h>
#include <unistd.h>

#include "../include/net.h"
#include "response.h"

int set_nonblocking(int sock) {
    int flags, s;

    flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1) {
        perror("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    s = fcntl(sock, F_SETFL, flags);
    if (s == -1) {
        perror("fcntl");
        return -1;
    }

    return 0;
}

// Free epollix context resources.
void free_context(context_t* ctx) {
    if (!ctx) {
        return;
    }

    free_reponse(ctx->response);
    request_destroy(ctx->request);
    if (ctx->locals) {
        map_destroy(ctx->locals, true);
        ctx->locals = NULL;
    }
}

// Add a value to the context. This is useful for sharing data between middleware.
void set_context_value(context_t* ctx, const char* key, void* value) {
    char* k = strdup(key);
    if (!k) {
        LOG_ERROR("unable to allocate memory for key: %s", key);
        return;
    }
    map_set(ctx->locals, k, value);
}

// Get a value from the context. Returns NULL if the key does not exist.
void* get_context_value(context_t* ctx, const char* key) {
    return map_get(ctx->locals, (char*)key);
}

// format_file_size returns a human-readable string representation of the file size.
// The function returns a pointer to a static buffer that is overwritten on each call.
// This means that it is not thread-safe.
const char* format_file_size(off_t size) {
    static char buf[32];
    char units[][3] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};

    int i = 0;
    double s = size;

    while (s >= 1024 && i < 8) {
        s /= 1024;
        i++;
    }

    if (i == 0) {
        snprintf(buf, sizeof(buf), "%ld %s", (long)size, units[i]);
    } else {
        snprintf(buf, sizeof(buf), "%.0f %s", s, units[i]);
    }
    return buf;
}

void enable_keepalive(int sockfd) {
    int keepalive = 1;  // Enable keepalive
    int keepidle = 60;  // 60 seconds before sending keepalive probes
    int keepintvl = 5;  // 5 seconds interval between keepalive probes
    int keepcnt = 3;    // 3 keepalive probes before closing the connection

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {
        LOG_FATAL("setsockopt(): new_tcpserver failed\n");
    }
}

char* get_ip_address(context_t* ctx) {
    // try the forwarded header
    const char* ip_addr = find_header(ctx->request->headers, ctx->request->header_count, "X-Forwarded-For");
    if (!ip_addr) {
        // try the real ip address
        ip_addr = find_header(ctx->request->headers, ctx->request->header_count, "X-Real-IP");
    }

    if (!ip_addr) {
        // use peer address
        struct sockaddr_storage addr;
        socklen_t len = sizeof(addr);
        getpeername(ctx->request->client_fd, (struct sockaddr*)&addr, &len);

        char ipstr[INET6_ADDRSTRLEN];
        if (addr.ss_family == AF_INET) {
            struct sockaddr_in* s = (struct sockaddr_in*)&addr;
            inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
        } else {  // AF_INET6
            struct sockaddr_in6* s = (struct sockaddr_in6*)&addr;
            inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
        }

        return strdup(ipstr);
    }
    return strdup(ip_addr);
}
