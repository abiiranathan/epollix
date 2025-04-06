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

// Add a value to the context. This is useful for sharing data between middleware.
void set_context_value(context_t* ctx, const char* key, void* value) {
    if (ctx->locals_count >= MAX_CONTEXT_LOCALS) {
        LOG_ERROR("context value limit reached");
        return;
    }

    ctx->locals[ctx->locals_count].key   = strdup(key);
    ctx->locals[ctx->locals_count].value = value;
    ctx->locals_count++;
}

void free_locals(context_t* ctx) {
    for (size_t i = 0; i < ctx->locals_count; ++i) {
        free(ctx->locals[i].key);
        free(ctx->locals[i].value);
    }
}

// Get a value from the context. Returns nullptr if the key does not exist.
void* get_context_value(context_t* ctx, const char* key) {
    for (size_t i = 0; i < ctx->locals_count; ++i) {
        if (strcmp(ctx->locals[i].key, key) == 0) {
            return ctx->locals[i].value;
        }
    }
    return nullptr;
}

void enable_keepalive(int sockfd) {
    int keepalive = 1;   // Enable keepalive
    int keepidle  = 60;  // 60 seconds before sending keepalive probes
    int keepintvl = 5;   // 5 seconds interval between keepalive probes
    int keepcnt   = 3;   // 3 keepalive probes before closing the connection

    if (setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(int)) < 0) {
        perror("setsockopt");
        LOG_FATAL("setsockopt(): new_tcpserver failed: sockfd=%d\n", sockfd);
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(int)) < 0) {
        perror("setsockopt");
        LOG_FATAL("setsockopt(): new_tcpserver failed: sockfd=%d\n", sockfd);
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(int)) < 0) {
        perror("setsockopt");
        LOG_FATAL("setsockopt(): new_tcpserver failed: sockfd=%d\n", sockfd);
    }

    if (setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(int)) < 0) {
        perror("setsockopt");
        LOG_FATAL("setsockopt(): new_tcpserver failed: sockfd=%d\n", sockfd);
    }
}

char* get_ip_address(context_t* ctx) {
    // try the forwarded header
    const char* ip_addr = headers_value(ctx->request->headers, "X-Forwarded-For");
    if (!ip_addr) {
        // try the real ip address
        ip_addr = headers_value(ctx->request->headers, "X-Real-IP");
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
