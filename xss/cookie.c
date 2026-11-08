/*
 * cookie.c
 *
 * Implementation of the cookie extraction routine.
 */

#include "cookie.h"
#include "config.h"

#include <string.h>

#define COOKIE_NEEDLE COOKIE_PARAM "="

void extract_cookie(const char *request, char *dest, size_t max_len)
{
    if (dest == NULL || max_len == 0U) {
        return;
    }
    dest[0] = '\0';
    if (request == NULL) {
        return;
    }

    /* Locate the COOKIE_PARAM query parameter. */
    const char *start = strstr(request, COOKIE_NEEDLE);
    if (start == NULL) {
        return;
    }
    start += strlen(COOKIE_NEEDLE);

    /* The browser's document.cookie may itself contain "cookieId1234=...";
     * if so, start from that inner occurrence so the real value is captured
     * regardless of cookie ordering. */
    const char *inner = strstr(start, COOKIE_NEEDLE);
    if (inner != NULL) {
        start = inner;
    }

    /* Copy until a delimiter: space, CR, LF, ';', '&', or NUL. */
    size_t i = 0;
    while (i < max_len - 1 &&
           start[i] != ' ' && start[i] != '\r' && start[i] != '\n' &&
           start[i] != ';' && start[i] != '&' && start[i] != '\0') {
        dest[i] = start[i];
        i++;
    }
    dest[i] = '\0';
}
