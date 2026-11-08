/*
 * net_io.h
 *
 * TCP connection and full-write helpers shared by both tools.
 */

#ifndef NET_IO_H
#define NET_IO_H

#include <stddef.h>
#include <stdint.h>

/* Open a blocking IPv4 TCP connection to ip:port. Returns the fd, or -1. */
int connect_tcp(const char *ip, uint16_t port);

/* Send the whole buffer, retrying on partial writes. Returns 0 / -1. */
int send_all(int fd, const char *buf, size_t len);

#endif /* NET_IO_H */
