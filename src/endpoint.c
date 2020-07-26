
#include "endpoint.h"
#include "encoding.h"
#include "http.h"
#include "utils.h"

#include <curl/curl.h>
#include <json-c/json.h>
#include <mbedtls/md.h>

#include <errno.h>
#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_BUF_LEN (1024)

tsauth_info *tsauth_init(char *userid, char *passwd, char *ip, int login_inside)
{
    tsauth_info *info = xcalloc(1, sizeof(tsauth_info));

    if (userid)
    {
        info->userid = xmalloc(strlen(userid) + login_inside ? 9 : 0 + 1);
        strcpy(info->userid, userid);
        if (login_inside)
            strcat(info->userid, "@tsinghua");
    }
    if (passwd)
    {
        info->passwd = xmalloc(strlen(passwd) + 1);
        strcpy(info->passwd, passwd);
    }
    if (ip)
    {
        info->ip = xmalloc(strlen(ip) + 1);
        strcpy(info->ip, ip);
    }

    return info;
}

void tsauth_cleanup(tsauth_info *info)
{
    if (!info)
        return;

    tsauth_info_cleanup(info->userid);
    tsauth_info_cleanup(info->passwd);
    tsauth_info_cleanup(info->ip);
    tsauth_info_cleanup(info->acid);
    tsauth_info_cleanup(info->token);
    tsauth_info_cleanup(info->hmd5);
    tsauth_info_cleanup(info->password);
    tsauth_info_cleanup(info->info);
    tsauth_info_cleanup(info->chksum);
    tsauth_info_cleanup(info->ipv4);
    tsauth_info_cleanup(info->ipv6);
}

static inline void check_auth(tsauth_info *info)
{
    info->authed = 0;
    _cleanup_free_ char *body = http_get("http://" ENDPOINT_NET_BASE);
    if (body && 0 == strcmp(body, "ok"))
        info->authed = 1;
}

static inline void check_net(tsauth_info *info)
{
    info->neted = 0;
    check_auth(info);
    if (!info->authed)
        return;

    _cleanup_free_ char *body = http_get(ENDPOINT_NET_LOGIN "?action=check_online");
    if (body && 0 == strcmp(body, "online"))
        info->neted = 1;
}

static inline json_object *extract_jsonp_response(char *src)
{
    char *p = strrchr(src, ')');
    char *q = strchr(src, '(');
    if (!p || !q)
        warn("extract_jsonp_response: JSON data is broken");
    else
        *p = '\0';
    return json_tokener_parse(q + 1);
}

static inline void update_info_from_json(char **dst, const char *key, json_object_iter *iter)
{
    if (0 == strcmp(iter->key, key))
    {
        *dst = (char *)xrealloc(*dst, json_object_get_string_len(iter->val) + 1);
        strcpy(*dst, json_object_get_string(iter->val));
    }
}

int get_acid(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    if (!info->ip)
    {
        _cleanup_free_ char *html = http_get("http://" ENDPOINT_NET_BASE);
        if (!html)
            return TSAUTH_ERROR_NO_RESPONSE;

        regex_t reg;
        regmatch_t pmatch[3];
        regcomp(&reg, "href=\"http://auth4.tsinghua.edu.cn/index_([0-9]+).html\"", REG_EXTENDED);
        if (0 == regexec(&reg, html, 3, pmatch, 0))
        {
            info->acid = xmalloc(pmatch[1].rm_eo - pmatch[1].rm_so + 1);
            *(html + pmatch[1].rm_eo) = 0;
            strcpy(info->acid, html + pmatch[1].rm_so);
        }
        else
            return TSAUTH_ERROR_NO_MATCHES;
    }
    else
    {
        _cleanup_free_ char *form = xmalloc(MAX_BUF_LEN);
        snprintf(form, MAX_BUF_LEN, "actionType=searchNasId&ip=%s", info->ip);
        _cleanup_free_ char *acid = http_post(ENDPOINT_USEREG "/ip_login_import.php", form);
        if (acid && 0 != strcmp(acid, "fail"))
        {
            info->acid = xmalloc(strlen(acid) + 1);
            strcpy(info->acid, acid);
        }
        else
            return TSAUTH_ERROR_RES_FAIL;
    }
    return TSAUTH_OK;
}

int get_challenge(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;
    if (!(info->userid))
        return TSAUTH_ERROR_NULL_USERID;

    _cleanup_free_ char *url = xmalloc(MAX_BUF_LEN);
    int result = TSAUTH_OK;

    snprintf(url, MAX_BUF_LEN,
             ENDPOINT_AUTH_BASE "/get_challenge?callback=tsauth"
                                "&username=%s"
                                "&ip=%s"
                                "&double_stack=%d",
             info->userid,
             (info->ip ? info->ip : ""),
             info->double_stack);

    _cleanup_free_ char *res = http_get(url);

    if (res)
    {
        json_object *data = extract_jsonp_response(res);
        json_object_iter iter;
        json_object_object_foreachC(data, iter)
        {
            update_info_from_json(&info->token, "challenge", &iter);
            update_info_from_json(&info->ip, "online_ip", &iter);
            if (0 == strcmp(iter.key, "ecode") && 0 != json_object_get_int(iter.val))
                result = json_object_get_int(iter.val);
            if (0 == strcmp(iter.key, "error") && 0 != strcmp("ok", json_object_get_string(iter.val)))
                result = TSAUTH_ERROR_CHALLENGE_FAILED;
        }
        json_object_put(data);
    }
    else
        result = TSAUTH_ERROR_NO_RESPONSE;

    return result;
}

static inline void generate_info(tsauth_info *info, int login)
{
    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "username", json_object_new_string(info->userid));
    if (login)
        json_object_object_add(obj, "password", json_object_new_string(info->passwd));
    json_object_object_add(obj, "ip", json_object_new_string(info->ip));
    json_object_object_add(obj, "acid", json_object_new_int(atoi(info->acid)));
    json_object_object_add(obj, "enc_ver", json_object_new_string("srun_bx1"));
    const char *json = json_object_to_json_string(obj);
    verbose("generate_info: JSON string: %s", json);
    size_t len = strlen(json);
    unsigned char buf1[MAX_BUF_LEN], buf2[MAX_BUF_LEN];
    size_t dlen = 0;

    if (xencode(buf1, MAX_BUF_LEN, &dlen, json, len, info->token, strlen(info->token)))
        warn("generate_info: xencode failed");
    if (base64_encode(buf2, MAX_BUF_LEN, &dlen, buf1, dlen))
        warn("generate_info: base64_encode failed");

    info->info = (char *)xrealloc(info->info, dlen + 8);
    strcpy(info->info, "{SRBX1}");
    strcat(info->info, buf2);

    verbose("generate_info: generated info: %s", info->info);
    json_object_put(obj);
}

static inline void generate_hmd5(tsauth_info *info)
{
    unsigned char digest[16];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_MD5),
                    (const unsigned char *)info->token,
                    strlen(info->token),
                    (unsigned char *)info->passwd,
                    strlen(info->passwd),
                    digest);

    bytes_to_hex(&info->hmd5, digest, 16);
    info->password = xrealloc(info->password, 5 + 32 + 1);
    strcpy(info->password, "{MD5}");
    strcat(info->password, info->hmd5);

    verbose("generate_hmd5: hmd5: %s", info->hmd5);
    verbose("generate_hmd5: password: %s", info->password);
}

static inline void generate_chksum(tsauth_info *info, int login)
{
    unsigned char digest[20];
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 0);
    mbedtls_md_starts(&ctx);

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, info->userid, strlen(info->userid));

    if (login)
    {
        mbedtls_md_update(&ctx, info->token, strlen(info->token));
        mbedtls_md_update(&ctx, info->hmd5, strlen(info->hmd5));
    }

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, info->acid, strlen(info->acid));

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, info->ip, strlen(info->ip));

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, "200", 3); // n = 200

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, "1", 1); // type = 1

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, info->info, strlen(info->info));

    mbedtls_md_finish(&ctx, digest);
    bytes_to_hex(&info->chksum, digest, 20);

    mbedtls_md_free(&ctx);

    verbose("generate_chksum: chksum: %s", info->chksum);
}

#define escape(x) curl_easy_escape(curl, x, strlen(x))

int tsauth_login(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    check_auth(info);
    if (!info->ip && info->authed)
        return TSAUTH_OK;

    if (!info->userid)
        return TSAUTH_ERROR_NULL_USERID;
    if (!info->passwd)
        return TSAUTH_ERROR_NULL_PASSWD;

    int result = get_acid(info);
    if (TSAUTH_OK != result)
    {
        warn("get_acid: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    result = get_challenge(info);
    if (TSAUTH_OK != result)
    {
        warn("get_challenge: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    generate_info(info, 1);
    generate_hmd5(info);
    generate_chksum(info, 1);

    _cleanup_free_ char *url = xmalloc(MAX_BUF_LEN);

    _cleanup_curl_free_ char *userid = escape(info->userid);
    _cleanup_curl_free_ char *password = escape(info->password);
    _cleanup_curl_free_ char *pinfo = escape(info->info);
    _cleanup_curl_free_ char *chksum = escape(info->chksum);

    snprintf(url, MAX_BUF_LEN,
             ENDPOINT_AUTH_BASE "/srun_portal?callback=tsauth&action=login"
                                "&username=%s"
                                "&password=%s"
                                "&ac_id=%s"
                                "&ip=%s"
                                "&double_stack=%d"
                                "&info=%s"
                                "&chksum=%s"
                                "&n=200"
                                "&type=1",
             userid, password,
             info->acid,
             (info->ip ? info->ip : ""),
             info->double_stack,
             pinfo, chksum);

    _cleanup_free_ char *res = http_get(url);
    _cleanup_free_ char *success_msg = NULL;
    _cleanup_free_ char *error = NULL;
    _cleanup_free_ char *error_msg = NULL;

    if (res)
    {
        json_object *data = extract_jsonp_response(res);
        json_object_iter iter;
        json_object_object_foreachC(data, iter)
        {
            update_info_from_json(&success_msg, "suc_msg", &iter);
            update_info_from_json(&error, "error", &iter);
            update_info_from_json(&error_msg, "error_msg", &iter);
            if (0 == strcmp(iter.key, "ecode") && 0 != json_object_get_int(iter.val))
                result = json_object_get_int(iter.val);
        }
        if (TSAUTH_OK == result && success_msg)
            message("auth: Login successfully: %s", success_msg);
        else
            warn("auth: Login failed: %s", error_msg);
        json_object_put(data);
    }
    else
        result = TSAUTH_ERROR_NO_RESPONSE;

    return result;
}

int tsauth_netin(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    check_net(info);
    if (!info->authed)
        return TSAUTH_ERROR_NOT_AUTH;

    if (!info->neted)
    {
        if (!info->userid)
            return TSAUTH_ERROR_NULL_USERID;
        if (!info->passwd)
            return TSAUTH_ERROR_NULL_PASSWD;

        unsigned char digest[16];
        _cleanup_free_ char *md5hex = xmalloc(32 + 1);
        _cleanup_free_ char *form = xmalloc(MAX_BUF_LEN);

        mbedtls_md_context_t ctx;
        mbedtls_md_init(&ctx);

        mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_MD5), 0);
        mbedtls_md_starts(&ctx);
        mbedtls_md_update(&ctx, info->passwd, strlen(info->passwd));
        mbedtls_md_finish(&ctx, digest);
        mbedtls_md_free(&ctx);

        bytes_to_hex(&md5hex, digest, 16);
        verbose("tsauth_netin: password: {MD5_HEX}%s", md5hex);

        snprintf(form, MAX_BUF_LEN, "action=login&username=%s&password={MD5_HEX}%s&ac_id=1", info->userid, md5hex); // ac_id = 1
        _cleanup_free_ char *text = http_post(ENDPOINT_NET_LOGIN, form);
        message("net: %s", text);
        if (text && 0 == strcmp(text, "Login is successful."))
            return TSAUTH_OK;
        else
            return TSAUTH_ERROR_NETIN_FAILED;
    }
    return TSAUTH_OK;
}

int tsauth_logout(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    check_auth(info);
    if (!info->ip && !info->authed)
        return TSAUTH_OK;

    if (!info->userid)
        return TSAUTH_ERROR_NULL_USERID;

    // set ac_id = 1
    if (info->acid)
        tsauth_info_cleanup(info->acid);
    info->acid = xmalloc(2);
    strcpy(info->acid, "1");

    int result = get_challenge(info);
    if (TSAUTH_OK != result)
    {
        warn("get_challenge: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    generate_info(info, 0);
    generate_chksum(info, 0);

    _cleanup_free_ char *url = xmalloc(MAX_BUF_LEN);

    _cleanup_curl_free_ char *userid = escape(info->userid);
    _cleanup_curl_free_ char *pinfo = escape(info->info);
    _cleanup_curl_free_ char *chksum = escape(info->chksum);

    snprintf(url, MAX_BUF_LEN,
             ENDPOINT_AUTH_BASE "/srun_portal?callback=tsauth&action=logout"
                                "&username=%s"
                                "&ac_id=%s"
                                "&ip=%s"
                                "&double_stack=%d"
                                "&info=%s"
                                "&chksum=%s"
                                "&n=200"
                                "&type=1",
             userid,
             info->acid,
             (info->ip ? info->ip : ""),
             info->double_stack,
             pinfo, chksum);

    _cleanup_free_ char *res = http_get(url);

    _cleanup_free_ char *success_msg = NULL;
    _cleanup_free_ char *error = NULL;
    _cleanup_free_ char *error_msg = NULL;

    if (res)
    {
        json_object *data = extract_jsonp_response(res);
        json_object_iter iter;

        json_object_object_foreachC(data, iter)
        {
            update_info_from_json(&success_msg, "res", &iter);
            update_info_from_json(&error, "error", &iter);
            update_info_from_json(&error_msg, "error_msg", &iter);
            if (0 == strcmp(iter.key, "ecode") && 0 != json_object_get_int(iter.val))
                result = json_object_get_int(iter.val);
        }
        if (error && 0 != strcmp("ok", error))
            result = TSAUTH_ERROR_LOGOUT_FAILED;

        if (TSAUTH_OK == result)
            message("auth: Logout successfully: %s", success_msg);
        else
            warn("auth: Logout failed: %s", error_msg);

        json_object_put(data);
    }
    else
        result = TSAUTH_ERROR_NO_RESPONSE;

    return result;
}

int tsauth_netout(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    check_net(info);
    if (!info->authed)
        return TSAUTH_ERROR_NOT_AUTH;

    if (info->neted)
    {
        _cleanup_free_ char *text = http_post(ENDPOINT_NET_LOGIN, "action=logout");
        message("net: %s", text);
        if (text && 0 == strcmp(text, "Logout is successful."))
            return TSAUTH_OK;
        else
            return TSAUTH_ERROR_NETOUT_FAILED;
    }
    return TSAUTH_OK;
}

#define convert_readable_byte(x)     \
    (x > 1e9 ? x / 1e9f : x / 1e6f), \
        (x > 1e9 ? "GB" : "MB")
#define convert_readable_duration(x)                                                     \
    (x > 86400 ? x / 86400.f : (x > 3600 ? x / 3600.f : (x > 60 ? x / 60.f : x * 1.f))), \
        (x > 86400 ? "days" : (x > 3600 ? "hours" : (x > 60 ? "mins" : "seconds")))

int tsauth_status(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    check_net(info);
    if (info->authed)
    {
        info->ipv4 = http_get(ENDPOINT_GET_IPV4);
        message("IPv4: %s", info->ipv4);
        info->ipv6 = http_get(ENDPOINT_GET_IPV6);
        message("IPv6: %s", info->ipv6);
    }
    else
        message("Not Authenticated!");
    if (info->neted)
    {
        _cleanup_free_ char *data = http_get(ENDPOINT_USER_INFO);

        char *s[20] = {NULL};
        char *p = s[0] = data;
        int i = 0;
        while (*(++p))
            if (*p == ',')
            {
                *p = 0;
                s[++i] = p + 1;
            }

        if (s[1])
            sscanf(s[1], "%ld", &info->start);
        if (s[6])
            sscanf(s[6], "%ld", &info->used_bytes);
        if (s[7])
            sscanf(s[7], "%ld", &info->used_time);
        if (s[11])
            sscanf(s[11], "%f", &info->quota);

        struct tm *t = localtime(&info->start);
        char timebuf[32] = {0};
        strftime(timebuf, 32, "%Y-%m-%d %H:%M:%S", t);
        message("Login time: %s", timebuf);
        message("Used: %.4f %s", convert_readable_byte(info->used_bytes));
        message("IPv4 used time: %lds (%f %s)", info->used_time, convert_readable_duration(info->used_time));
        message("Quota: %.2f", info->quota);
    }
    else
        message("net not login");
}

static char error_string[32] = {0};

const char *tsauth_strcode(int code)
{
    switch (code)
    {
    case TSAUTH_ERROR_NULL_INFO:
        return "tsauth_info NULL ptr";
        break;
    case TSAUTH_ERROR_NULL_USERID:
        return "username missed";
        break;
    case TSAUTH_ERROR_NULL_PASSWD:
        return "password missed";
        break;
    case TSAUTH_ERROR_CHALLENGE_FAILED:
        return "get_challenge failed";
        break;
    case TSAUTH_ERROR_NO_RESPONSE:
        return "server no response or timeout";
        break;
    case TSAUTH_ERROR_LOGOUT_FAILED:
        return "logout failed";
        break;
    case TSAUTH_ERROR_NO_MATCHES:
        return "response has no matches";
        break;
    case TSAUTH_ERROR_RES_FAIL:
        return "response fail";
        break;
    case TSAUTH_ERROR_NOT_AUTH:
        return "not authenticated";
        break;
    case TSAUTH_ERROR_NETIN_FAILED:
        return "net login failed";
        break;
    case TSAUTH_ERROR_NETOUT_FAILED:
        return "net logout failed";
        break;

    default:
        snprintf(error_string, 32, "unknown code - %d", code);
        return error_string;
    }
    return "";
}
