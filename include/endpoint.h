
#ifndef TSAUTH_ENDPOINT_H
#define TSAUTH_ENDPOINT_H

#include <time.h>

#define ENDPOINT_AUTH_BASE  "auth.tsinghua.edu.cn/cgi-bin"
#define ENDPOINT_NET_BASE   "net.tsinghua.edu.cn"
#define ENDPOINT_NET_LOGIN  "net.tsinghua.edu.cn/do_login.php"
#define ENDPOINT_USEREG     "usereg.tsinghua.edu.cn"
#define ENDPOINT_USER_INFO  "auth4.tsinghua.edu.cn/rad_user_info.php"
#define ENDPOINT_GET_IPV4   "http://118.229.2.198/getip.php"
#define ENDPOINT_GET_IPV6   "http://[2402:f000:0:2c4::198]/getip.php"

#define TSAUTH_OK                       (0)
#define TSAUTH_ERROR_NULL_INFO          (-1)
#define TSAUTH_ERROR_NULL_USERID        (-2)
#define TSAUTH_ERROR_NULL_PASSWD        (-3)
#define TSAUTH_ERROR_CHALLENGE_FAILED   (-4)
#define TSAUTH_ERROR_NO_RESPONSE        (-5)
#define TSAUTH_ERROR_LOGOUT_FAILED      (-6)
#define TSAUTH_ERROR_NO_MATCHES         (-7)
#define TSAUTH_ERROR_RES_FAIL           (-8)
#define TSAUTH_ERROR_NOT_AUTH           (-9)
#define TSAUTH_ERROR_NETIN_FAILED       (-10)
#define TSAUTH_ERROR_NETOUT_FAILED      (-11)

typedef struct tsauth_info_t
{
    char *userid;
    char *passwd;
    char *ip;
    int double_stack;
    char *acid;
    char *token;
    char *hmd5;
    char *password;
    char *info;
    char *chksum;
    int authed;
    int neted;
    char *ipv4;
    char *ipv6;
    time_t start;
    size_t used_bytes;
    size_t used_time;
    float quota;
} tsauth_info;

#define tsauth_info_cleanup(x) \
    if (x)                     \
    free(x)

tsauth_info *tsauth_init(char *userid, char *passwd, char *ip, int login_inside);
int tsauth_login(tsauth_info *info);
int tsauth_netin(tsauth_info *info);
int tsauth_logout(tsauth_info *info);
int tsauth_netout(tsauth_info *info);
int tsauth_status(tsauth_info *info);
void tsauth_cleanup(tsauth_info *info);
const char *tsauth_strcode(int code);

#endif
