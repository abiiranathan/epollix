#include "url.h"
#include <string.h>

bool url_parse(const char* url, URL* parsedUrl) {
  CURLU* urlhandle = curl_url();
  CURLUcode ucode;

  // Parse the URL
  ucode = curl_url_set(urlhandle, CURLUPART_URL, url, 0);
  if (ucode != CURLUE_OK) {
    fprintf(stderr, "URL parsing failed: %s\n", curl_url_strerror(ucode));
    curl_url_cleanup(urlhandle);
    return false;
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
      parsedUrl->port = "443";
    } else if (strcmp(parsedUrl->scheme, "http") == 0) {
      parsedUrl->port = "80";
    }
  }
  return true;
}

void url_free(URL* url) {
  if (!url)
    return;

  if (url->scheme) {
    curl_free(url->scheme);
  }
  if (url->host) {
    curl_free(url->host);
  }
  if (url->path) {
    curl_free(url->path);
  }
  if (url->query) {
    curl_free(url->query);
  }
  if (url->fragment) {
    curl_free(url->fragment);
  }
}
