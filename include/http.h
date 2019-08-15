
#ifndef TSAUTH_HTTP_H
#define TSAUTH_HTTP_H

#define MAX_BUFFER_SIZE (65536)

#include <curl/curl.h>

extern CURL *curl;

int http_init(long timeout, int use_https);
char *http_get(const char *url);
void http_cleanup();

#endif
