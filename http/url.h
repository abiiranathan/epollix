#ifndef URL_H
#define URL_H

#include <curl/curl.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct URL {
  char* scheme;
  char* host;
  char* path;
  char* query;
  char* fragment;
  char* port;
} URL;

// Parse a url using libcurl.
bool url_parse(const char* url, URL* parsedUrl);

// Free pointers to URL parts.
void url_free(URL* url);

#endif /* URL_H */
