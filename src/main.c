/*      _____         _           _    _
 *     |_   _|___    / \   _   _ | |_ | |__
 *       | | / __|  / _ \ | | | || __|| '_ \
 *       | | \__ \ / ___ \| |_| || |_ | | | |
 *       |_| |___//_/   \_\\__,_| \__||_| |_|
 */

#include "endpoint.h"
#include "http.h"
#include "utils.h"

#include <curl/curl.h>

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

static const char *opts = "d:u:p:t:46iosvh?";

static const struct option long_opts[] = {{"addr", required_argument, NULL, 'd'},
                                          {"http", no_argument, NULL, 0},
                                          {"inside", no_argument, NULL, 0},
                                          {"ipv4", no_argument, NULL, '4'},
                                          {"ipv6", no_argument, NULL, '6'},
                                          {"login", no_argument, NULL, 'i'},
                                          {"logout", no_argument, NULL, 'o'},
                                          {"password", required_argument, NULL, 'p'},
                                          {"username", required_argument, NULL, 'u'},
                                          {"status", no_argument, NULL, 's'},
                                          {"timeout", required_argument, NULL, 't'},
                                          {"verbose", no_argument, NULL, 'v'},
                                          {"help", no_argument, NULL, 'h'},
                                          {"version", no_argument, NULL, 0},
                                          {NULL, no_argument, NULL, 0}};

unsigned char flags = 0;

int main(int argc, char *argv[])
{
    int opt;
    int long_index;
    tsauth_info *info = NULL;

    char *ip = NULL;
    char *username = NULL;
    char *password = NULL;
    int timeout = 1;

    if (1 == argc)
        die_usage();

    while ((opt = getopt_long(argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch (opt)
        {
        case '4':
            flags |= TSAUTH_FLAG_IPV4;
            break;
        case '6':
            flags |= TSAUTH_FLAG_IPV6;
            break;
        case 'i':
            flags |= TSAUTH_FLAG_LOGIN;
            break;
        case 'o':
            flags |= TSAUTH_FLAG_LOGOUT;
            break;
        case 's':
            flags |= TSAUTH_FLAG_STATUS;
            break;
        case 'v':
            flags |= TSAUTH_FLAG_VERBOSE;
            break;
        case 'h':
        case '?':
            die_usage();
            break;
        case 'd':
            ip = optarg;
            break;
        case 'u':
            username = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 't':
            if (atoi(optarg) >= 0)
                timeout = atoi(optarg);
            else
                die("Invalid timeout parameter");
            break;
        case 0:
            if (strcmp("http", long_opts[long_index].name) == 0)
                flags |= TSAUTH_FLAG_HTTP;
            if (strcmp("inside", long_opts[long_index].name) == 0)
                flags |= TSAUTH_FLAG_INSIDE;
            if (strcmp("version", long_opts[long_index].name) == 0)
                die_version();
            break;
        default:
            break;
        }
    }

    int result = 0;

    if ((TSAUTH_FLAG_LOGIN | TSAUTH_FLAG_LOGOUT) == (flags & (TSAUTH_FLAG_LOGIN | TSAUTH_FLAG_LOGOUT)))
        die("confused option: --login, --logout");

    http_init(timeout);

    if (flags & TSAUTH_FLAG_STATUS)
        tsauth_status();
    else
    {
        // set resolve ipv4(6)
        if (TSAUTH_FLAG_IPV4 == (flags & (TSAUTH_FLAG_IPV4 | TSAUTH_FLAG_IPV6)))
            curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        if (TSAUTH_FLAG_IPV6 == (flags & (TSAUTH_FLAG_IPV4 | TSAUTH_FLAG_IPV6)))
            curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V6);

        info = tsauth_init(username, password, ip, flags & TSAUTH_FLAG_INSIDE);
        info->double_stack = !((flags ^ (flags >> 1)) & TSAUTH_FLAG_IPV4);

        if (info->ip)
            message("IP: %s", info->ip);

        if (flags & TSAUTH_FLAG_LOGOUT)
            result = tsauth_logout(info);
        else
            result = tsauth_login(info);
        if (TSAUTH_OK != result)
            warn("%s", tsauth_strcode(result));
        tsauth_cleanup(info);
    }

    http_cleanup();

    return EXIT_SUCCESS;
}
