CC=gcc
CFLAGS=-Wall
LIBS=-levent

all:udp_proxy tcp_proxy

%: %.c
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o udp_proxy tcp_proxy
