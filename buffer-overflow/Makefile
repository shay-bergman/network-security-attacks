CC      ?= gcc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11
TARGET   = overflow_exploit
OBJS     = overflow_exploit.o payload.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) *.o
