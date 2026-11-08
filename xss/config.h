/*
 * config.h
 *
 * Shared lab configuration for the XSS cookie-exfiltration tools: the target
 * web application, the attacker's collection endpoint, and the query-parameter
 * name that injected payloads use to carry the stolen cookie.
 */

#ifndef CONFIG_H
#define CONFIG_H

/* Vulnerable target web application (sandbox lab host). */
#define TARGET_WEB_IP   "192.168.1.203"
#define TARGET_WEB_PORT 80

/* Attacker collection server (where injected payloads send the cookie). */
#define ATTACKER_IP     "192.168.1.201"
#define ATTACKER_PORT   5555

/* Query-parameter name used by the injected JavaScript to carry the cookie. */
#define COOKIE_PARAM    "cookieId1234"

/* Socket read/write timeout, in seconds, to avoid hangs. */
#define SOCKET_TIMEOUT_SECONDS 5

#endif /* CONFIG_H */
