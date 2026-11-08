CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
LDLIBS   = -lldns

CLIENT        = poison_client
SERVER        = auth_server

COMMON_OBJS   = net_util.o control_channel.o
CLIENT_OBJS   = poison_client.o spoof_dns.o raw_packet.o $(COMMON_OBJS)
SERVER_OBJS   = auth_server.o dns_responder.o $(COMMON_OBJS)

.PHONY: all clean

all: $(CLIENT) $(SERVER)

$(CLIENT): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(CLIENT) $(SERVER) *.o
