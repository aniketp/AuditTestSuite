CC=gcc

all: clean
	$(CC) -o readlink readlink.c
	$(CC) -o symlink symlink.c
	$(CC) -o mkdir mkdir.c
	$(CC) -o mknod mknod.c
	$(CC) -o mkfifo mkfifo.c
	$(CC) -o link link.c
	$(CC) -o open open.c

.PHONY: clean

run:
	./run_tests

clean:
	rm -f readlink open symlink mkdir mknod \
		mkfifo link
