#ifndef TSAUTH_UTILS_H
#define TSAUTH_UTILS_H

#include <curl/curl.h>

#include <stddef.h>
#include <stdlib.h>

#define TSAUTH_FLAG_IPV4        (1 << 0)
#define TSAUTH_FLAG_IPV6        (1 << 1)
#define TSAUTH_FLAG_INSIDE      (1 << 2)
#define TSAUTH_FLAG_LOGOUT      (1 << 3)
#define TSAUTH_FLAG_LOGIN       (1 << 4)
#define TSAUTH_FLAG_STATUS      (1 << 5)
#define TSAUTH_FLAG_HTTP        (1 << 6)
#define TSAUTH_FLAG_VERBOSE     (1 << 7)

extern unsigned char flags;

#define _noreturn_ __attribute__((noreturn))
#define _printf_(x, y) __attribute__((format(printf, x, y)))
#define _cleanup_(x) __attribute__((cleanup(x)))

static inline void freep(void *p)
{
    if (p)
        free(*(void **)p);
}
static inline void curl_freep(void *p)
{
    if (p)
        curl_free(*(void **)p);
}
#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_curl_free_ _cleanup_(curl_freep)

void message(const char *format, ...) _printf_(1, 2);
void warn(const char *format, ...) _printf_(1, 2);
void verbose(const char *format, ...) _printf_(1, 2);
_noreturn_ void die(const char *err, ...) _printf_(1, 2);
_noreturn_ void die_errno(const char *err, ...) _printf_(1, 2);
_noreturn_ void die_usage();
_noreturn_ void die_version();

void *xmalloc(size_t size);
void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);

#endif
