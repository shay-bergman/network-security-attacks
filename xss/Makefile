CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

LOGGER      = cookie_logger
INJECTOR    = inject_stored

LOGGER_OBJS = cookie_logger.o cookie.o exfil.o sockio.o
INJECT_OBJS = inject_stored.o sockio.o

.PHONY: all clean

all: $(LOGGER) $(INJECTOR)

$(LOGGER): $(LOGGER_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(INJECTOR): $(INJECT_OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(LOGGER) $(INJECTOR) *.o
