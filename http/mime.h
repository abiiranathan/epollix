#ifndef MIME_H
#define MIME_H

typedef struct {
  const char* extension;
  const char* contentType;
} ContentTypeMapping;

const char* getWebContentType(char* filename);

#endif /* MIME_H */
