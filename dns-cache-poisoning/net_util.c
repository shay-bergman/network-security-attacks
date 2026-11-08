/*
 * net_util.c
 *
 * Implementation of the shared socket helpers.
 */

#include "net_util.h"

#include <arpa/inet.h>
#include <sys/socket.h>

bool ipv4_from_string(const char *ip_str, struct in_addr *out_addr)
{
    if (ip_str == NULL || out_addr == NULL) {
        return false;
    }
    return inet_pton(AF_INET, ip_str, out_addr) == 1;
}

bool set_reuse_addr_port(int sockfd)
{
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, (socklen_t)sizeof(opt)) < 0) {
        return false;
    }
    opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, (socklen_t)sizeof(opt)) < 0) {
        return false;
    }
    return true;
}
