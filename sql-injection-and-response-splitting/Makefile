CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

SQLI       = blind_sqli
SPLIT      = response_splitting

SQLI_OBJS  = blind_sqli.o http_oracle.o url_encode.o net_io.o
SPLIT_OBJS = response_splitting.o percent_encode.o net_io.o

.PHONY: all clean

all: $(SQLI) $(SPLIT)

$(SQLI): $(SQLI_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(SPLIT): $(SPLIT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(SQLI) $(SPLIT) *.o
