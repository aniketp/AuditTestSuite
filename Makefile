CC=gcc

all: clean
	$(CC) -o network network.c

.PHONY: clean

clean:
	rm -f network network.core 
