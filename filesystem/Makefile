CC=gcc

all: clean
	$(CC) -o readlink readlink.c
	$(CC) -o open open.c

.PHONY: clean

run:
	./run_tests

clean:
	rm -f readlink open
