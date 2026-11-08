/*
 * control_channel.c
 *
 * Implementation of both ends of the TCP control channel.
 */

#include "control_channel.h"
#include "net_util.h"

#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

uint16_t control_fetch_port(const char *server_ip, uint16_t tcp_port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return 0U;
    }

    if (!set_reuse_addr_port(sockfd)) {
        (void)close(sockfd);
        return 0U;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(tcp_port);

    if (!ipv4_from_string(server_ip, &server_addr.sin_addr) ||
        connect(sockfd, (const struct sockaddr *)&server_addr,
                (socklen_t)sizeof(server_addr)) < 0) {
        (void)close(sockfd);
        return 0U;
    }

    uint16_t port_net = 0U;
    ssize_t bytes_read = read(sockfd, &port_net, sizeof(port_net));
    (void)close(sockfd);

    if (bytes_read != (ssize_t)sizeof(port_net)) {
        return 0U;
    }
    return (uint16_t)ntohs(port_net);
}

int control_listen(uint16_t tcp_port)
{
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    if (!set_reuse_addr_port(sockfd)) {
        (void)close(sockfd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(tcp_port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sockfd, (const struct sockaddr *)&addr, (socklen_t)sizeof(addr)) < 0 ||
        listen(sockfd, 1) < 0) {
        (void)close(sockfd);
        return -1;
    }
    return sockfd;
}

void control_send_port_once(int listen_fd, uint16_t host_port)
{
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t client_len = (socklen_t)sizeof(client_addr);

    int connfd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (connfd < 0) {
        return;
    }

    uint16_t port_net = htons(host_port);
    (void)write(connfd, &port_net, sizeof(port_net));
    (void)close(connfd);
}
