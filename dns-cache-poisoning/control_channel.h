/*
 * control_channel.h
 *
 * Minimal TCP control channel used to pass the resolver's learned UDP source
 * port from the authoritative server to the attacker client. Both ends live
 * here: the client fetches, the server listens and sends.
 */

#ifndef CONTROL_CHANNEL_H
#define CONTROL_CHANNEL_H

#include <stdint.h>

/* Client side: connect to server_ip:tcp_port and read the resolver's UDP
 * source port (host byte order). Returns 0 on failure. */
uint16_t control_fetch_port(const char *server_ip, uint16_t tcp_port);

/* Server side: create a listening TCP socket on tcp_port. Returns -1 on error. */
int control_listen(uint16_t tcp_port);

/* Server side: accept one connection on listen_fd and send host_port (as a
 * 16-bit value in network byte order), then close that connection. */
void control_send_port_once(int listen_fd, uint16_t host_port);

#endif /* CONTROL_CHANNEL_H */
