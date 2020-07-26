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

static const char *opts = "d:u:p:t:ionsvh?";

static const struct option long_opts[] = {{"addr", required_argument, NULL, 'd'},
                                          {"http", no_argument, NULL, 0},
                                          {"inside", no_argument, NULL, 0},
                                          {"login", no_argument, NULL, 'i'},
                                          {"logout", no_argument, NULL, 'o'},
                                          {"net", no_argument, NULL, 'n'},
                                          {"status", no_argument, NULL, 's'},
                                          {"password", required_argument, NULL, 'p'},
                                          {"username", required_argument, NULL, 'u'},
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
        case 'i':
            flags |= TSAUTH_FLAG_LOGIN;
            break;
        case 'o':
            flags |= TSAUTH_FLAG_LOGOUT;
            break;
        case 'n':
            flags |= TSAUTH_FLAG_NET;
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
                die("invalid timeout parameter");
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

    tsauth_info *info = tsauth_init(username, password, ip, flags & TSAUTH_FLAG_INSIDE);
    info->double_stack = 1;

    if (flags & TSAUTH_FLAG_STATUS)
        return tsauth_status(info);

    if (info->ip)
        message("IP: %s", info->ip);

    if (flags & TSAUTH_FLAG_LOGOUT)
        result = (flags & TSAUTH_FLAG_NET) ? tsauth_netout(info) : tsauth_logout(info);
    else
        result = (flags & TSAUTH_FLAG_NET) ? tsauth_netin(info) : tsauth_login(info);

    tsauth_cleanup(info);
    http_cleanup();

    if (TSAUTH_OK != result)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}
