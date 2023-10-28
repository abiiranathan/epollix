#ifndef CONTEXT_H
#define CONTEXT_H
#include "request.h"
#include "response.h"

typedef struct {
  Request* request;
  Response* response;
} Context;

#endif /* CONTEXT_H */
