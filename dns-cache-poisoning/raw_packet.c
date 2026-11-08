/*
 * raw_packet.c
 *
 * Implementation of the raw IPv4/UDP framing and checksum routines.
 */

#include "raw_packet.h"
#include "net_util.h"

#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Fold a 32-bit accumulator into a 16-bit one's-complement checksum. */
static uint16_t fold_checksum(uint32_t sum)
{
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)(~sum);
}

/* Partial (unfolded) 16-bit ones'-complement sum over a byte buffer. */
static uint32_t partial_sum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0U;
    size_t i = 0U;
    while (i + 1U < len) {
        sum += ((uint16_t)data[i] << 8) | (uint16_t)data[i + 1U];
        i += 2U;
    }
    if (i < len) {
        sum += (uint16_t)((uint16_t)data[i] << 8);
    }
    return sum;
}

uint16_t ip_checksum(const struct IPv4Header *ip)
{
    return fold_checksum(partial_sum((const uint8_t *)ip, sizeof(*ip)));
}

/* UDP checksum over the IPv4 pseudo-header, UDP header, and payload. */
static uint16_t udp_checksum(const struct IPv4Header *ip,
                             const struct UdpHeader *udp,
                             const uint8_t *payload, size_t payload_len)
{
    uint8_t pseudo[12];
    memcpy(&pseudo[0], &ip->src_ip, 4);
    memcpy(&pseudo[4], &ip->dst_ip, 4);
    pseudo[8] = 0U;
    pseudo[9] = ip->protocol;
    memcpy(&pseudo[10], &udp->length, 2);

    uint32_t sum = 0U;
    sum += partial_sum(pseudo, sizeof(pseudo));
    sum += partial_sum((const uint8_t *)udp, sizeof(*udp));
    sum += partial_sum(payload, payload_len);
    return fold_checksum(sum);
}

size_t build_udp_ip_frame(uint8_t *frame, size_t frame_size,
                          const struct IPv4Header *ip_template,
                          uint16_t src_port, uint16_t dst_port,
                          const uint8_t *udp_payload, size_t udp_payload_len)
{
    if (frame == NULL || ip_template == NULL || udp_payload == NULL) {
        return 0U;
    }

    const size_t ip_len = sizeof(struct IPv4Header);
    const size_t udp_len = sizeof(struct UdpHeader);
    const size_t total_len = ip_len + udp_len + udp_payload_len;
    if (total_len > frame_size) {
        return 0U;
    }

    struct IPv4Header ip = *ip_template;

    struct UdpHeader udp;
    memset(&udp, 0, sizeof(udp));
    udp.src_port = htons(src_port);
    udp.dst_port = htons(dst_port);
    udp.length   = htons((uint16_t)(udp_len + udp_payload_len));
    udp.checksum = 0U;
    udp.checksum = htons(udp_checksum(&ip, &udp, udp_payload, udp_payload_len));

    size_t offset = 0U;
    memcpy(frame + offset, &ip, ip_len);                   offset += ip_len;
    memcpy(frame + offset, &udp, udp_len);                 offset += udp_len;
    memcpy(frame + offset, udp_payload, udp_payload_len);  offset += udp_payload_len;
    return offset;
}

int open_raw_udp_socket(struct sockaddr_in *dst_addr,
                        const char *dst_ip, uint16_t dst_port)
{
    if (dst_addr == NULL || dst_ip == NULL) {
        return -1;
    }

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sockfd < 0) {
        return -1;
    }

    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, (socklen_t)sizeof(one)) < 0) {
        (void)close(sockfd);
        return -1;
    }

    memset(dst_addr, 0, sizeof(*dst_addr));
    dst_addr->sin_family = AF_INET;
    dst_addr->sin_port = htons(dst_port);
    if (!ipv4_from_string(dst_ip, &dst_addr->sin_addr)) {
        (void)close(sockfd);
        return -1;
    }
    return sockfd;
}
