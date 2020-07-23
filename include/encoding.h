
#ifndef TSAUTH_ENCODING_H
#define TSAUTH_ENCODING_H

#include <stddef.h>

int base64_encode(unsigned char *dst, size_t dlen, size_t *olen,
                  const unsigned char *src, size_t slen);
int xencode(unsigned char *dst, size_t dlen, size_t *olen,
            const unsigned char *str, size_t slen, const unsigned char *key, size_t klen);
void bytes_to_hex(char **dst, const unsigned char *bytes, size_t len);

#endif
