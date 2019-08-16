
#include "http.h"
#include "utils.h"

#include <curl/curl.h>

#include <errno.h>
#include <string.h>

struct mem_chunk
{
    char *ptr;
    size_t len;
};

CURL *curl = NULL;

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

int http_init(long timeout)
{
    // init curl
    curl = curl_easy_init();
    if (!curl)
        die("Could not init cURL library");
    // set callbacks
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    // set use http(s)
    if (flags & TSAUTH_FLAG_HTTP)
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "http");
    else
        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
}

char *http_get(const char *url)
{
    if (!url)
        return NULL;

    struct mem_chunk res;
    CURLcode ret;
    char *result = NULL;

    memset(&res, 0, sizeof(res));
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &res);
    verbose("[HTTP] GET %s", url);

    ret = curl_easy_perform(curl);
    if (CURLE_OK == ret)
        result = res.ptr;
    else
    {
        res.len = 0;
        free(res.ptr);
        res.ptr = NULL;
        warn("Perform request failed: %s", curl_easy_strerror(ret));
    }

    verbose("[HTTP] Res %s", result);
    return result;
}

void http_cleanup()
{
    if (curl)
        curl_easy_cleanup(curl);
    curl = NULL;
}
