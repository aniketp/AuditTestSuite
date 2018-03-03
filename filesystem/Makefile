CC=gcc

all: clean
	$(CC) -o readlink readlink.c
	$(CC) -o symlink open.c
	$(CC) -o mkdir open.c
	$(CC) -o mknod open.c
	$(CC) -o mkfifo open.c
	$(CC) -o link open.c
	$(CC) -o open open.c

.PHONY: clean

run:
	./run_tests

clean:
	rm -f readlink open symlink mkdir mknod \
		mkfifo link
