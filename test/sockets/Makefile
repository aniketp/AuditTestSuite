CC=gcc

all: clean
	$(CC) -o tcp_socket tcp_socket.c
	$(CC) -o udp_server udp_server.c
	$(CC) -o udp_client udp_client.c

.PHONY: clean

run:
	./run_tests

clean:
	rm -f tcp_socket tcp_socket.core udp_server udp_client
