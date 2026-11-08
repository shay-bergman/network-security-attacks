/*
 * url_encode.h
 *
 * Conservative URL encoder used by the SQL-injection tool: everything that is
 * not an ASCII letter or digit is percent-encoded, so SQL conditions survive
 * transport in an HTTP query string.
 */

#ifndef URL_ENCODE_H
#define URL_ENCODE_H

#include <stddef.h>

/*
 * Percent-encode src into dst. dst must hold up to 3*strlen(src)+1 bytes.
 * Returns 0 on success, -1 if dst is too small.
 */
int url_encode(char *dst, size_t dst_size, const char *src);

#endif /* URL_ENCODE_H */
