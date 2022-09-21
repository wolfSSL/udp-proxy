CC=gcc
WOLF_INSTALL_DIR=/usr/local
CFLAGS=-I$(WOLF_INSTALL_DIR)/include -Wall
LIBS=-L$(WOLF_INSTALL_DIR)/lib -levent

all:udp_proxy tcp_proxy

udp_proxy:udp_proxy.o
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LIBS)

tcp_proxy:tcp_proxy.o
	$(CC) -o $@ $^ $(CFLAGS) $(CPPFLAGS) $(LIBS)

.PHONY: clean all

clean:
	rm -f *.o udp_proxy tcp_proxy
