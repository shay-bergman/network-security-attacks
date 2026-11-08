/*
 * lab_config.h
 *
 * Shared configuration for the DNS cache-poisoning tools: the sandbox lab
 * host addresses, the attacker/victim zone names, and the well-known ports.
 * All values describe a private, controlled lab network.
 */

#ifndef LAB_CONFIG_H
#define LAB_CONFIG_H

/* Lab host addresses (private RFC 1918 range). */
#define RESOLVER_IP_STRING        "192.168.1.203"
#define ROOT_NS_IP_STRING         "192.168.1.204"
#define ATTACKER_AUTH_IP_STRING   "192.168.1.201"
#define ATTACKER_CLIENT_IP_STRING "192.168.1.202"

/* Zone names. Stored without a trailing dot; callers add one where the wire
 * or presentation format requires a fully qualified name. */
#define ATTACKER_NS_FQDN   "ns.attacker.lab.example"
#define ATTACKER_WWW_NAME  "www.attacker.lab.example"
#define TARGET_BASE_DOMAIN "victim.lab.example"
#define VICTIM_HOST        "www.victim.lab.example"

/* IP injected into the cache for the victim host once poisoning succeeds. */
#define VICTIM_POISON_IP   "6.6.6.6"

/* Ports. */
#define DNS_PORT         53U
#define CONTROL_TCP_PORT 12345U

/* Kaminsky attack parameters. */
#define MAX_ATTACK_ROUNDS 20U
#define MAX_TXID_SPACE    65536U

#endif /* LAB_CONFIG_H */
