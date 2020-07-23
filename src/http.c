
#include "http.h"
#include "utils.h"

#include <curl/curl.h>

#include <errno.h>
#include <string.h>

#define MAX_BUFFER_SIZE (65536)

struct mem_chunk
{
    char *ptr;
    size_t len;
};

CURL *curl = NULL;
long _timeout = 1;

// Callback for receiving HTTP respose
static size_t write_data(char *ptr, size_t size, size_t nmemb, void *data)
{
    size_t len, new_len;
    struct mem_chunk *mem = (struct mem_chunk *)data;
    if ((nmemb >= MAX_BUFFER_SIZE || size >= MAX_BUFFER_SIZE) && nmemb > 0 && MAX_BUFFER_SIZE / nmemb < size)
    {
        errno = ENOMEM;
        return 0;
    }
    len = size * nmemb;
    new_len = len + mem->len + 1;
    if (new_len <= mem->len || new_len <= len || new_len < 1)
    {
        errno = ENOMEM;
        return 0;
    }

    mem->ptr = (char *)xrealloc(mem->ptr, new_len);
    memcpy(mem->ptr + mem->len, ptr, len);
    mem->len += len;
    mem->ptr[mem->len] = '\0';

    return len;
}

static inline void http_reset()
{
    curl_easy_reset(curl);
    // set callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    // set use http(s)
    if (flags & TSAUTH_FLAG_HTTP)
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "http");
    else
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
    // set resolve ipv4
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, _timeout);
}

int http_init(long timeout)
{
    // init curl
    curl = curl_easy_init();
    if (!curl)
        die("http_init: could not init cURL library");

    _timeout = timeout;
    http_reset();
}

char *http_get(const char *url)
{
    if (!url)
        return NULL;

    struct mem_chunk res;
    CURLcode ret;
    char *result = NULL;

    memset(&res, 0, sizeof(res));
    http_reset();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    verbose("[HTTP] GET %s", url);

    ret = curl_easy_perform(curl);
    if (CURLE_OK == ret)
    {
        result = res.ptr;
        verbose("[HTTP] Res %s", result);
    }
    else
    {
        res.len = 0;
        free(res.ptr);
        res.ptr = NULL;
        warn("http_get: perform request failed: %s", curl_easy_strerror(ret));
    }

    return result;
}

char *http_post(const char *url, const char *form)
{
    if (!url)
        return NULL;

    struct mem_chunk res;
    CURLcode ret;
    char *result = NULL;

    memset(&res, 0, sizeof(res));
    http_reset();
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, form);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    verbose("[HTTP] POST %s", url);
    verbose("[HTTP] FORM %s", form);

    ret = curl_easy_perform(curl);
    if (CURLE_OK == ret)
    {
        result = res.ptr;
        verbose("[HTTP] Res %s", result);
    }
    else
    {
        res.len = 0;
        free(res.ptr);
        res.ptr = NULL;
        warn("http_post: perform request failed: %s", curl_easy_strerror(ret));
    }

    return result;
}

void http_cleanup()
{
    if (curl)
        curl_easy_cleanup(curl);
    curl = NULL;
}
