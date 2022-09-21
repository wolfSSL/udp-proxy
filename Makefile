CC=gcc
CFLAGS=-Wall
LIBS=-levent

all:udp_proxy tcp_proxy

udp_proxy:udp_proxy.o
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LIBS)

tcp_proxy:tcp_proxy.o
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o udp_proxy tcp_proxy
