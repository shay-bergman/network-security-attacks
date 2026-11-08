/*
 * exfil.h
 *
 * Replay of a stolen cookie against the target web application to retrieve a
 * protected resource and save it to disk.
 */

#ifndef EXFIL_H
#define EXFIL_H

/*
 * Connect to the target web application, request target_page while presenting
 * the stolen cookie in the Cookie header, and write the full HTTP response to
 * out_file. Errors are handled silently.
 */
void fetch_with_cookie(const char *stolen_cookie,
                       const char *target_page, const char *out_file);

#endif /* EXFIL_H */
