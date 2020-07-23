
#ifndef TSAUTH_HTTP_H
#define TSAUTH_HTTP_H

#include <curl/curl.h>

extern CURL *curl;

int http_init(long timeout);
char *http_get(const char *url);
char *http_post(const char *url, const char *form);
void http_cleanup();

#endif
