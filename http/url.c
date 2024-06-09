#include "url.h"
#include <stdlib.h>
#include <string.h>

URL* url_parse(Arena* arena, const char* url) {
  if (!url) {
    return NULL;
  }

  cstr* urlstr = cstr_from(arena, url);
  if (!urlstr) {
    fprintf(stderr, "cstr_from(): Memory allocation error in url_parse\n");
    return NULL;
  }

  URL* parsedUrl = arena_alloc(arena, sizeof(URL));
  if (!parsedUrl) {
    return NULL;
  }
  parsedUrl->original_url = urlstr->data;

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

  url = NULL;  // allocated in the arena.
}

cstr* url_tostring(Arena* arena, const URL* url) {
  // limit url to 1024 bytes
  cstr* result = cstr_new(arena, 1024);
  if (!result) {
    fprintf(stderr, "cstr_new(): Memory allocation error in url_tostring\n");
    return NULL;
  }

  cstr_append_fmt(arena, result, "%s://%s:%s%s%s%s%s%s", url->scheme, url->host,
                  url->port ? url->port : "", url->path, url->query ? "?" : "",
                  url->query ? url->query : "", url->fragment ? "#" : "",
                  url->fragment ? url->fragment : "");

  return result;
}
