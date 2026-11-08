/*
 * url_encode.c
 *
 * Implementation of the conservative URL encoder.
 */

#include "url_encode.h"

int url_encode(char *dst, size_t dst_size, const char *src)
{
    static const char hex[] = "0123456789ABCDEF";
    if (dst == NULL || src == NULL || dst_size == 0) {
        return -1;
    }

    size_t o = 0;
    for (const unsigned char *p = (const unsigned char *)src; *p != '\0'; p++) {
        unsigned char c = *p;
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9')) {
            if (o + 1 >= dst_size) {
                return -1;
            }
            dst[o++] = (char)c;
        } else {
            /* Percent-encode everything else as %XX. */
            if (o + 3 >= dst_size) {
                return -1;
            }
            dst[o++] = '%';
            dst[o++] = hex[c >> 4];
            dst[o++] = hex[c & 0x0F];
        }
    }

    if (o >= dst_size) {
        return -1;
    }
    dst[o] = '\0';
    return 0;
}
