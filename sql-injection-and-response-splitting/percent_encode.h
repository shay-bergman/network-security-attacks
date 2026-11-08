/*
 * percent_encode.h
 *
 * RFC 3986 percent-encoder used by the response-splitting tool to carry an
 * arbitrary byte payload (including CR/LF) inside a URL query parameter.
 */

#ifndef PERCENT_ENCODE_H
#define PERCENT_ENCODE_H

#include <stddef.h>

/*
 * Percent-encode in_len bytes of 'in' into 'out'. Unreserved characters
 * (ALPHA / DIGIT / "-" / "." / "_" / "~") pass through; everything else is
 * encoded as %XX. Returns 0 on success, -1 if 'out' is too small.
 */
int percent_encode(const unsigned char *in, size_t in_len, char *out, size_t out_sz);

#endif /* PERCENT_ENCODE_H */
