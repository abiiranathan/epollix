#ifndef URL_H
#define URL_H

#include <curl/curl.h>
#include <solidc/cstr.h>
#include <stdbool.h>
#include <stdio.h>

// Represent a URL object.
typedef struct URL {
  const char* original_url;  // Original URL from client.
  char* scheme;              // Protocol
  char* host;                // Host
  char* path;                // PathName for url.
  char* query;               // Query string if present or NULL.
  char* fragment;            // Fragment is not forwarded by http clients and browsers.
  char* port;                // port.
} URL;

// Parse a url into it's components.
// uses libcurl's curl_url_set API. The URL * and its components are allocated
// on the heap. call url_free to free this memory.
URL* url_parse(Arena* arena, const char* url);

// Free URL* and it's components.
void url_free(URL* url);

// Return allocated string representation for URL.
cstr* url_tostring(Arena* arena, const URL* url);

#endif /* URL_H */
