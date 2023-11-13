#include "url.h"
#include <stdlib.h>
#include <string.h>

URL* url_parse(const char* url) {
  URL* parsedUrl = malloc(sizeof(URL));
  if (!parsedUrl) {
    return NULL;
  }
  parsedUrl->original_url = strdup(url);

  CURLU* urlhandle = curl_url();
  CURLUcode ucode;

  // Parse the URL
  ucode = curl_url_set(urlhandle, CURLUPART_URL, url, 0);
  if (ucode != CURLUE_OK) {
    fprintf(stderr, "URL parsing failed: %s\n", curl_url_strerror(ucode));
    curl_url_cleanup(urlhandle);
    return NULL;
  }

  curl_url_get(urlhandle, CURLUPART_SCHEME, &parsedUrl->scheme, 0);
  curl_url_get(urlhandle, CURLUPART_HOST, &parsedUrl->host, 0);
  curl_url_get(urlhandle, CURLUPART_PATH, &parsedUrl->path, 0);
  curl_url_get(urlhandle, CURLUPART_QUERY, &parsedUrl->query, 0);
  curl_url_get(urlhandle, CURLUPART_FRAGMENT, &parsedUrl->fragment, 0);
  curl_url_get(urlhandle, CURLUPART_PORT, &parsedUrl->port, 0);

  curl_url_cleanup(urlhandle);

  if (parsedUrl->port == NULL) {
    if (strcmp(parsedUrl->scheme, "https") == 0) {
      parsedUrl->port = strdup("443");
    } else if (strcmp(parsedUrl->scheme, "http") == 0) {
      parsedUrl->port = strdup("80");
    }
  }
  return parsedUrl;
}

void url_free(URL* url) {
  if (!url) {
    return;
  }

  free((void*)url->original_url);
  curl_free(url->scheme);
  curl_free(url->host);
  curl_free(url->path);

  if (url->query) {
    curl_free(url->query);
  }

  if (url->fragment) {
    curl_free(url->fragment);
  }

  if (url->port) {
    curl_free(url->port);
  }

  free(url);
  url = NULL;
}

char* url_tostring(const URL* url) {
  // total buffer size incl. separators & null-terminators
  size_t buffer_size = strlen(url->scheme) + strlen(url->host) + strlen(url->path) +
                       (url->query ? strlen(url->query) : 0) +
                       (url->fragment ? strlen(url->fragment) : 0) +
                       (url->port ? strlen(url->port) : 0) + 8;

  // Allocate memory for the buffer
  char* result = malloc(buffer_size);
  if (!result) {
    fprintf(stderr, "Memory allocation error in url_tostring\n");
    return NULL;
  }


  // Create the string representation
  snprintf(result, buffer_size, "%s://%s:%s%s%s%s%s%s", url->scheme, url->host,
           url->port ? url->port : "", url->path, url->query ? "?" : "",
           url->query ? url->query : "", url->fragment ? "#" : "",
           url->fragment ? url->fragment : "");

  return result;
}
