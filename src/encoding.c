
#include "encoding.h"
#include "utils.h"

#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE64_SIZE_T_MAX ((size_t)-1) /* SIZE_T_MAX is not standard */

static const unsigned char base64_encode_map[] =
    "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA";

int base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                  const unsigned char *src, size_t slen)
{
    size_t i, n;
    int C1, C2, C3;
    unsigned char *p;

    if (slen == 0)
    {
        *olen = 0;
        return (0);
    }

    n = slen / 3 + (slen % 3 != 0);
    if (n > (BASE64_SIZE_T_MAX - 1) / 4)
    {
        *olen = BASE64_SIZE_T_MAX;
        return (-1);
    }

    n *= 4;

    if ((dlen < n + 1) || (NULL == dst))
    {
        *olen = n + 1;
        return (-1);
    }

    n = (slen / 3) * 3;

    for (i = 0, p = dst; i < n; i += 3)
    {
        C1 = *src++;
        C2 = *src++;
        C3 = *src++;

        *p++ = base64_encode_map[(C1 >> 2) & 0x3F];
        *p++ = base64_encode_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];
        *p++ = base64_encode_map[(((C2 & 15) << 2) + (C3 >> 6)) & 0x3F];
        *p++ = base64_encode_map[C3 & 0x3F];
    }

    if (i < slen)
    {
        C1 = *src++;
        C2 = ((i + 1) < slen) ? *src++ : 0;

        *p++ = base64_encode_map[(C1 >> 2) & 0x3F];
        *p++ = base64_encode_map[(((C1 & 3) << 4) + (C2 >> 4)) & 0x3F];

        if ((i + 1) < slen)
            *p++ = base64_encode_map[((C2 & 15) << 2) & 0x3F];
        else
            *p++ = '=';

        *p++ = '=';
    }

    *olen = p - dst;
    *p = 0;

    return (0);
}

int xencode(unsigned char *dst, size_t dlen, size_t *olen,
            const unsigned char *str, size_t slen, const unsigned char *key, size_t klen)
{
    uint32_t n = ceil(slen / 4.0); // n = v.length - 1
    if (slen == 0)
    {
        *olen = 0;
        return (0);
    }
    if (dlen < (n + 1) * 4 || (NULL == dst))
    {
        // too small
        *olen = (n + 1) * 4;
        return (-1);
    }

    _cleanup_free_ uint32_t *v = (uint32_t *)xmalloc((n + 1) * sizeof(uint32_t));
    _cleanup_free_ uint32_t *k = (uint32_t *)xmalloc(4 * sizeof(uint32_t));

    uint32_t *p;
    unsigned char *q;

    // v = s(str, true)
    p = v, q = (unsigned char *)str;
    for (q; q < str + slen; q += 4)
        *p++ = *q | *(q + 1) << 8 | *(q + 2) << 16 | *(q + 3) << 24;
    *p = slen;

    // k = s(str, false)
    memset(k, 0, 4 * sizeof(uint32_t));
    p = k, q = (unsigned char *)key;
    for (q; q < key + klen && p < k + 4; q += 4)
        *p++ = *q | *(q + 1) << 8 | *(q + 2) << 16 | *(q + 3) << 24;

    uint32_t z = v[n], y = v[0];
    uint32_t c = 0x9E3779B9; // c = 0x86014019 | 0x183639A0
    uint32_t d = 0, e = 0, m = 0;
    uint32_t i = 0, j = floor(6.0 + 52.0 / (n + 1)); // p = 0, q = Math.floor(6 + 52 / (n + 1))
    while (j-- > 0)
    {
        d += c;                  // d = d + c & (0x8CE0D9BF | 0x731F2640)
        e = d >> 2 & 3;          // e = d >>> 2 & 3
        for (i = 0; i <= n; i++) // for (p = 0; p < n; p++)
        {
            y = v[(i + 1) % (n + 1)];         // y = v[p + 1]
            m = z >> 5 ^ y << 2;              // m = z >>> 5 ^ y << 2
            m += (y >> 3 ^ z << 4) ^ (d ^ y); // m += (y >>> 3 ^ z << 4) ^ (d ^ y)
            m += k[(i & 3) ^ e] ^ z;          // m += k[(p & 3) ^ e] ^ z
            z = v[i] = v[i] + m;              // z = v[p] = v[p] + m & (0xEFB8D130 | 0x10472ECF)
        }
    }

    // return l(v, false)
    p = v, q = dst;
    for (p; p < v + n + 1; p++)
    {
        *(q++) = *p & 0xff;
        *(q++) = *p >> 8 & 0xff;
        *(q++) = *p >> 16 & 0xff;
        *(q++) = *p >> 24 & 0xff;
    }
    *olen = q - dst;

    p = 0, q = 0;
    return (0);
}

static char hex_digits[] = "0123456789abcdef";

void bytes_to_hex(char **dst, const unsigned char *bytes, size_t len)
{
    if (!*dst)
        *dst = (char *)xmalloc(len * 2 + 1);
    for (size_t i = 0; i < len; ++i)
    {
        (*dst)[i * 2] = hex_digits[(bytes[i] >> 4) & 0xF];
        (*dst)[i * 2 + 1] = hex_digits[bytes[i] & 0xF];
    }
    (*dst)[len * 2] = '\0';
}
