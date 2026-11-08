/*
 * net_util.h
 *
 * Small socket helpers shared by the attacker client and authoritative server.
 */

#ifndef NET_UTIL_H
#define NET_UTIL_H

#include <stdbool.h>
#include <netinet/in.h>

/* Parse a dotted IPv4 string into out_addr. Returns false on error. */
bool ipv4_from_string(const char *ip_str, struct in_addr *out_addr);

/* Enable SO_REUSEADDR and SO_REUSEPORT on sockfd. Returns false on error. */
bool set_reuse_addr_port(int sockfd);

#endif /* NET_UTIL_H */
