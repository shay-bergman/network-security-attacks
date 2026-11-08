/*
 * raw_packet.h
 *
 * Raw IPv4/UDP packet building and Internet checksums, used to inject spoofed
 * DNS responses with a forged source address via an IP_HDRINCL raw socket.
 */

#ifndef RAW_PACKET_H
#define RAW_PACKET_H

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

struct IPv4Header {
    uint8_t  version_ihl;     /* 4 bits version, 4 bits IHL       */
    uint8_t  dscp_ecn;
    uint16_t total_length;    /* IP header + UDP header + payload */
    uint16_t identification;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;        /* 17 = UDP                         */
    uint16_t checksum;        /* IP header checksum               */
    uint32_t src_ip;
    uint32_t dst_ip;
} __attribute__((packed));

struct UdpHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;          /* UDP header + payload             */
    uint16_t checksum;
} __attribute__((packed));

/* IPv4 header checksum. */
uint16_t ip_checksum(const struct IPv4Header *ip);

/*
 * Serialize one IP+UDP frame (no Ethernet header) into 'frame'. The UDP
 * checksum (over the pseudo-header, UDP header and payload) is computed.
 * Returns the frame length on success, 0 on error.
 */
size_t build_udp_ip_frame(uint8_t *frame, size_t frame_size,
                          const struct IPv4Header *ip_template,
                          uint16_t src_port, uint16_t dst_port,
                          const uint8_t *udp_payload, size_t udp_payload_len);

/*
 * Open a raw IPv4/UDP socket with IP_HDRINCL and fill dst_addr with the
 * destination (family + port + dst_ip). Returns the socket fd, or -1 on error.
 */
int open_raw_udp_socket(struct sockaddr_in *dst_addr,
                        const char *dst_ip, uint16_t dst_port);

#endif /* RAW_PACKET_H */
