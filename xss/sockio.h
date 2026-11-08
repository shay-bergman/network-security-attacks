/*
 * sockio.h
 *
 * Low-level socket I/O helpers shared by the XSS tools.
 */

#ifndef SOCKIO_H
#define SOCKIO_H

#include <stddef.h>

/* Apply a send/receive timeout (in seconds) to a socket. */
void set_socket_timeouts(int fd, int seconds);

/* Send the entire buffer, retrying on partial writes.
 * Returns 0 on success, -1 on error. */
int send_all(int fd, const char *buf, size_t len);

#endif /* SOCKIO_H */
