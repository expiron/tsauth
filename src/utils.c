
#include "utils.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_BUF_LEN (1024)

void message(const char *format, ...)
{
    char msg[MAX_BUF_LEN];
    va_list params;

    va_start(params, format);
    vsnprintf(msg, sizeof(msg), format, params);
    va_end(params);

    fprintf(stderr, "[INFO] %s\n", msg);
}

void warn(const char *format, ...)
{
    char msg[MAX_BUF_LEN];
    va_list params;

    va_start(params, format);
    vsnprintf(msg, sizeof(msg), format, params);
    va_end(params);

    fprintf(stderr, "[WARN] %s\n", msg);
}

void verbose(const char *format, ...)
{
    if (!(flags & TSAUTH_FLAG_VERBOSE))
        return;
    char msg[MAX_BUF_LEN];
    va_list params;

    va_start(params, format);
    vsnprintf(msg, sizeof(msg), format, params);
    va_end(params);

    fprintf(stderr, "[INFO] %s\n", msg);
}

_noreturn_ void die(const char *err, ...)
{
    char message[MAX_BUF_LEN];
    va_list params;

    va_start(params, err);
    vsnprintf(message, sizeof(message), err, params);
    va_end(params);

    fprintf(stderr, "[ERR ] %s\n", message);
    exit(EXIT_FAILURE);
}

_noreturn_ void die_errno(const char *err, ...)
{
    char message[MAX_BUF_LEN], *error_message;
    va_list params;

    error_message = strerror(errno);

    va_start(params, err);
    vsnprintf(message, sizeof(message), err, params);
    va_end(params);

    fprintf(stderr, "[ERR ] %s: %s\n", error_message, message);
    exit(EXIT_FAILURE);
}

_noreturn_ void die_usage()
{
    fprintf(
        stderr,
        "TsinghuaAuth v" TSAUTH_VERSION /* "-" TSAUTH_GIT_COMMIT_ID */ "\n\n"
        "    A tiny client for Tsinghua network AAA system\n\n"
        "Usage:\n"
        "    tsauth [OPTIONS] [--login] [-d <IP>] -u <username> -p <password>\n"
        "    tsauth [OPTIONS] --logout [-d <IP>] -u <username>\n\n"
        "Options:\n"
        "    -d, --addr <IP address>        Specify the IP address to authorize\n"
        "        --http                     Use HTTP for requests instead of HTTPS\n"
        "        --inside                   Authorize campus internal network only\n"
        "    -i, --login                    Perform login operation (default)\n"
        "    -o, --logout                   Perform logout operation\n"
        "    -u, --username <username>      Tsinghua username or ID number\n"
        "    -p, --password <plaintext>     Password in plaintext\n"
        "    -t, --timeout <seconds>        Timeout of each request (default: 1)\n"
        "    -v, --verbose                  Show detailed information\n"
        "    -h, -?, --help                 Show usage and quit\n"
        "        --version                  Show version string and quit\n");

    exit(EXIT_FAILURE);
}

_noreturn_ void die_version()
{
    fprintf(stderr, TSAUTH_VERSION /* "-" TSAUTH_GIT_COMMIT_ID */ "\n");
    exit(EXIT_SUCCESS);
}

void *xmalloc(size_t size)
{
    void *ret = malloc(size);
    if (ret)
        return ret;
    die_errno("malloc(%zu)", size);
}
void *xcalloc(size_t nmemb, size_t size)
{
    void *ret = calloc(nmemb, size);
    if (ret)
        return ret;
    die_errno("calloc(%zu, %zu)", nmemb, size);
}
void *xrealloc(void *ptr, size_t size)
{
    void *ret = realloc(ptr, size);
    if (ret)
        return ret;
    die_errno("realloc(%p, %zu)", ptr, size);
}
