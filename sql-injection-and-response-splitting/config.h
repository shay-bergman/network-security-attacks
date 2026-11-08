/*
 * config.h
 *
 * Shared lab configuration for the blind SQL injection and HTTP response
 * splitting tools. All addresses refer to sandbox lab hosts.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* Proof-of-exploitation marker. The original lab used a unique identifier so a
 * run could be attributed; it has no functional role and is a placeholder. */
#define PROOF_MARKER "0000000"

/* --- Blind SQL injection target --- */
#define SQLI_TARGET_IP   "192.168.1.202"
#define SQLI_TARGET_PORT 80U
/* An order id known to produce the positive ("order has been sent") message,
 * used to keep the base query valid while an AND condition is appended. */
#define GOOD_ORDER_ID    "2"

/* --- HTTP response splitting target --- */
#define PROXY_IP          "192.168.1.202"
#define PROXY_PORT        8080U
/* The cache key includes Host + URL in this lab. */
#define PROXY_HOST_HEADER "192.168.1.202:8080"
/* Page whose cache entry is poisoned. */
#define TARGET_PATH       "/promo.html"
/* Endpoint that reflects a parameter into a response header (the split point). */
#define VULN_PATH         "/cgi-bin/product_lookup"
#define VULN_PARAM_NAME   "product_id"

#endif /* CONFIG_H */
