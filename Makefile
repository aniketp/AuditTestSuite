CC=gcc

all: clean
	$(CC) -o tcp_socket network.c
	$(CC) -o udp_server udp_server.c
	$(CC) -o udp_client udp_client.c

.PHONY: clean

clean:
	rm -f tcp_socket tcp_socket.core udp_server udp_client