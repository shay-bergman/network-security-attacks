/*
 * dns_responder.h
 *
 * Authoritative-server DNS handling: socket setup, response construction, and
 * the query-serving loop for the attacker-controlled name server.
 */

#ifndef DNS_RESPONDER_H
#define DNS_RESPONDER_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

/* Create and bind a UDP socket for DNS on port 53. Returns -1 on error. */
int create_dns_udp_socket(void);

/*
 * Handle one received DNS query:
 *   - Record the resolver's UDP source port into *resolver_port_out.
 *   - Answer the victim host with a poisoned A record; answer everything else
 *     with an empty authoritative NOERROR response.
 */
void handle_dns_query(int dns_fd, const uint8_t *data, size_t len,
                      const struct sockaddr_in *client, socklen_t client_len,
                      uint16_t *resolver_port_out);

/* Receive and handle DNS queries forever, updating *resolver_port_out. */
void dns_serve_forever(int dns_fd, uint16_t *resolver_port_out);

#endif /* DNS_RESPONDER_H */
