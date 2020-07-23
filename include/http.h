
#ifndef TSAUTH_HTTP_H
#define TSAUTH_HTTP_H

#define MAX_BUFFER_SIZE (65536)

#include <curl/curl.h>

extern CURL *curl;

int http_init(long timeout);
char *http_get(const char *url);
char *http_postform(const char *url, const char *form);
void http_cleanup();

#endif
