
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

#define MAX_URL_LEN (1024)
#define MAX_BUF_LEN (512)

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
    // clean up curl
    http_cleanup();

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
}

static inline json_object *extract_jsonp_response(char *src)
{
    char *p = strrchr(src, ')');
    char *q = strchr(src, '(');
    if (!p || !q)
        warn("JSON data is broken");
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
        regex_t reg;
        regmatch_t pmatch[3];
        _cleanup_free_ char *html = http_get("http://" NET_BASE_URL);
        regcomp(&reg, "href=\"http://auth4.tsinghua.edu.cn/index_([0-9]+).html\"", REG_EXTENDED);
        if (REG_NOERROR == regexec(&reg, html, 3, pmatch, 0))
        {
            info->acid = xmalloc(pmatch[1].rm_eo - pmatch[1].rm_so + 1);
            *(html + pmatch[1].rm_eo) = 0;
            strcpy(info->acid, html + pmatch[1].rm_so);
        }
        else
        {
            warn("[ACID] regex failed!");
            return TSAUTH_ERROR_REGEX_FAILED;
        }
    }
    else
    {
        _cleanup_free_ char *form = xmalloc(MAX_BUFFER_SIZE);
        snprintf(form, MAX_BUFFER_SIZE, "actionType=searchNasId&ip=%s", info->ip);
        char *acid = http_postform(USEREG_BASE_URL "/ip_login_import.php", form);
        if (0 != strcmp(acid, "fail"))
        {
            info->acid = xmalloc(strlen(acid) + 1);
            strcpy(info->acid, acid);
        }
        else
        {
            warn("[ACID] get failed!");
            return TSAUTH_ERROR_REGEX_FAILED;
        }
    }
    return TSAUTH_OK;
}

int get_challenge(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;
    if (!(info->userid))
        return TSAUTH_ERROR_NULL_USERID;

    _cleanup_free_ char *url = xmalloc(MAX_URL_LEN);
    int result = TSAUTH_OK;

    snprintf(url, MAX_URL_LEN,
             AUTH_BASE_ENDPOINT "/get_challenge?callback=tsauth"
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
    verbose("JSON String: %s", json);
    size_t len = strlen(json);
    unsigned char buf1[MAX_BUF_LEN], buf2[MAX_BUF_LEN];
    size_t dlen = 0;

    if (xencode(buf1, MAX_BUF_LEN, &dlen, json, len, info->token, strlen(info->token)))
        warn("call xencode failed");
    if (base64_encode(buf2, MAX_BUF_LEN, &dlen, buf1, dlen))
        warn("call base64_encode failed");

    info->info = (char *)xrealloc(info->info, dlen + 8);
    strcpy(info->info, "{SRBX1}");
    strcat(info->info, buf2);

    verbose("Generated info: %s", info->info);
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

    if (bytes_to_hex(&info->hmd5, digest, 16))
        warn("call bytes_to_hex failed");
    info->password = xrealloc(info->password, 5 + 32 + 1);
    strcpy(info->password, "{MD5}");
    strcat(info->password, info->hmd5);

    verbose("Calculated hmd5: %s", info->hmd5);
    verbose("Calculated password: %s", info->password);
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
    mbedtls_md_update(&ctx, "200", 3);

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, "1", 1);

    mbedtls_md_update(&ctx, info->token, strlen(info->token));
    mbedtls_md_update(&ctx, info->info, strlen(info->info));

    mbedtls_md_finish(&ctx, digest);
    if (bytes_to_hex(&info->chksum, digest, 20))
        warn("call bytes_to_hex failed");

    mbedtls_md_free(&ctx);

    verbose("Calculated chksum: %s", info->chksum);
}

#define escape(x) curl_easy_escape(curl, x, strlen(x))

int tsauth_login(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    if (!info->userid)
        return TSAUTH_ERROR_NULL_USERID;
    if (!info->passwd)
        return TSAUTH_ERROR_NULL_PASSWD;

    int result = get_acid(info);
    if (TSAUTH_OK != result)
    {
        warn("get_acid failed: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    result = get_challenge(info);
    if (TSAUTH_OK != result)
    {
        warn("get_challenge failed: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    generate_info(info, 1);
    generate_hmd5(info);
    generate_chksum(info, 1);

    _cleanup_free_ char *url = xmalloc(MAX_URL_LEN);

    _cleanup_curl_free_ char *userid = escape(info->userid);
    _cleanup_curl_free_ char *password = escape(info->password);
    _cleanup_curl_free_ char *pinfo = escape(info->info);
    _cleanup_curl_free_ char *chksum = escape(info->chksum);

    snprintf(url, MAX_URL_LEN,
             AUTH_BASE_ENDPOINT "/srun_portal?callback=tsauth&action=login"
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

    if (res)
    {
        json_object *data = extract_jsonp_response(res);
        json_object_iter iter;
        json_object_object_foreachC(data, iter)
        {
            update_info_from_json(&success_msg, "suc_msg", &iter);
            update_info_from_json(&error, "error", &iter);
            if (0 == strcmp(iter.key, "ecode") && 0 != json_object_get_int(iter.val))
                result = json_object_get_int(iter.val);
        }
        if (TSAUTH_OK == result && success_msg)
            message("Login successfully: %s", success_msg);
        else
            warn("Login failed: %s", error);
        json_object_put(data);
    }
    else
        result = TSAUTH_ERROR_NO_RESPONSE;

    return result;
}

int tsauth_logout(tsauth_info *info)
{
    if (!info)
        return TSAUTH_ERROR_NULL_INFO;

    if (!info->userid)
        return TSAUTH_ERROR_NULL_USERID;

    int result = get_acid(info);
    if (TSAUTH_OK != result)
    {
        warn("get_acid failed: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    result = get_challenge(info);
    if (TSAUTH_OK != result)
    {
        warn("get_challenge failed: %s", tsauth_strcode(result));
        return TSAUTH_ERROR_CHALLENGE_FAILED;
    }
    generate_info(info, 0);
    generate_chksum(info, 0);

    _cleanup_free_ char *url = xmalloc(MAX_URL_LEN);

    _cleanup_curl_free_ char *userid = escape(info->userid);
    _cleanup_curl_free_ char *pinfo = escape(info->info);
    _cleanup_curl_free_ char *chksum = escape(info->chksum);

    snprintf(url, MAX_URL_LEN,
             AUTH_BASE_ENDPOINT "/srun_portal?callback=tsauth&action=logout"
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

    if (res)
    {
        json_object *data = extract_jsonp_response(res);
        json_object_iter iter;

        json_object_object_foreachC(data, iter)
        {
            update_info_from_json(&success_msg, "suc_msg", &iter);
            update_info_from_json(&error, "error", &iter);
            if (0 == strcmp(iter.key, "ecode") && 0 != json_object_get_int(iter.val))
                result = json_object_get_int(iter.val);
        }
        if (error && 0 != strcmp("ok", error))
            result = TSAUTH_ERROR_LOGOUT_FAILED;

        if (TSAUTH_OK == result)
            message("Logout successfully: %s", success_msg);
        else
            warn("Logout failed: %s", error);

        json_object_put(data);
    }
    else
        result = TSAUTH_ERROR_NO_RESPONSE;

    return result;
}

int tsauth_status()
{
    _cleanup_free_ char *ipv4 = get_ipv4();
    _cleanup_free_ char *ipv6 = get_ipv6();
    message("IPv4: %s, IPv6: %s", ipv4, ipv6);
    _cleanup_free_ char *ruinfo = get_rad_user_info();
    message("Rad_User_Info: %s", ruinfo);
    return TSAUTH_OK;
}

static char error_string[32] = {0};

const char *tsauth_strcode(int code)
{
    switch (code)
    {
    case TSAUTH_ERROR_NULL_INFO:
        return "Auth info NULL ptr";
        break;
    case TSAUTH_ERROR_NULL_USERID:
        return "Username missed";
        break;
    case TSAUTH_ERROR_NULL_PASSWD:
        return "Password missed";
        break;
    case TSAUTH_ERROR_CHALLENGE_FAILED:
        return "Get challenge failed";
        break;
    case TSAUTH_ERROR_NO_RESPONSE:
        return "Server no response or timeout";
        break;
    case TSAUTH_ERROR_LOGOUT_FAILED:
        return "Logout failed";
        break;
    case TSAUTH_ERROR_REGEX_FAILED:
        return "ACID failed";
        break;

    default:
        snprintf(error_string, 32, "Unknown code - %d", code);
        return error_string;
    }
    return "";
}
