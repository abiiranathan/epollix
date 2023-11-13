#ifndef SERVER_H
#define SERVER_H

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../http/str.h"

typedef unsigned int uint;

#define MAX_REQUEST_HEADERS  50
#define MAX_RESPONSE_HEADERS 50
#define MAX_BODY_SIZE        (1 << 24)  // 16 MB
#define MAX_METHOD_SIZE      16
#define MAX_PATH_LENGTH      256
#define HEADER_KEY_LENGTH    256
#define HEADER_VALUE_LENGTH  1024
#define BACKLOG              100

typedef enum Method {
  METHOD_OPTIONS = 1,
  METHOD_HEAD,
  METHOD_GET,
  METHOD_POST,
  METHOD_PUT,
  METHOD_PATCH,
  METHOD_DELETE
} Method;

typedef struct Header {
  char name[HEADER_KEY_LENGTH];
  char value[HEADER_VALUE_LENGTH];
} Header;

typedef struct Server Server;
typedef struct Request Request;
typedef struct Response Response;

typedef struct Context {
  Request* req;   // Pointer to request
  Response* res;  // Pointer to response

  int headers_sent;  // flag to keep track of whether headers where already sent
  int chunked;       // chunked Transfer encoding.
} Context;

Server* NewTCPServer(unsigned int port);
void InstallHandler(Server* server, void (*handler)(Context* ctx));
void RunForever(Server* server);

const char* get_status_text(unsigned int statusCode);
int is_safe_method(const char* method);

// More public APIs to access request and response
extern ssize_t server_send(Context* ctx);

// Request methods
Method getMethod(Context* ctx);
const char* getMethodAsString(Context* ctx);

const char* getHeader(Context* ctx, char* key);
const Header* getHeaders(Context* ctx);
ssize_t getNumHeaders(Context* ctx);
const char* getBody(Context* ctx);
const char* getPathName(Context* ctx);

// Response methods
void Status(Context* ctx, uint status);
Header createHeader(const char* key, const char* value);
void setHeader(Context* ctx, const char* key, const char* value);
void setHeaderArray(Context* ctx, Header* headers, uint num_headers);
void Send(Context* ctx, void* data, ssize_t contentLength);

// general purpose methods
const char* findResponseHeader(Context* ctx, char* key);

// Allow 'chunked' transfer encoding.
void EnableStreaming(Context* ctx);
void toLower(char* str);

#endif /* SERVER_H */
