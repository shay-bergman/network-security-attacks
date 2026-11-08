/*
 * percent_encode.c
 *
 * Implementation of the RFC 3986 percent-encoder.
 */

#include "percent_encode.h"

#include <ctype.h>

/* RFC 3986 unreserved set: ALPHA / DIGIT / "-" / "." / "_" / "~". */
static int is_unreserved(unsigned char c)
{
    return isalnum((int)c) != 0 || c == '-' || c == '.' || c == '_' || c == '~';
}

int percent_encode(const unsigned char *in, size_t in_len, char *out, size_t out_sz)
{
    static const char hex[] = "0123456789ABCDEF";
    if (in == NULL || out == NULL || out_sz == 0) {
        return -1;
    }

    size_t o = 0;
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = in[i];
        if (is_unreserved(c)) {
            if (o + 1 >= out_sz) {
                return -1;
            }
            out[o++] = (char)c;
        } else {
            if (o + 3 >= out_sz) {
                return -1;
            }
            out[o++] = '%';
            out[o++] = hex[(c >> 4) & 0x0F];
            out[o++] = hex[c & 0x0F];
        }
    }

    if (o >= out_sz) {
        return -1;
    }
    out[o] = '\0';
    return 0;
}
