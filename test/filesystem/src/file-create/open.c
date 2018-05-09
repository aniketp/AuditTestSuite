#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/syscall.h>

void main(){
	char *file = "templog";
	char *err = "temp/error";

	/* Success Condition: open(2): read, creat */
	if (syscall(SYS_open, file, O_RDONLY | O_CREAT) == -1){
		perror("open: read, creat");
		exit(-1);
	}

	/* Failure Condition: open(2): read, creat */
	syscall(SYS_open, err, O_RDONLY | O_CREAT);
	unlink(file);


	/* Success Condition: open(2): read, creat, trunc */
	if (syscall(SYS_open, file, O_RDONLY | O_CREAT | O_TRUNC) == -1){
		perror("open: read, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): read, creat, trunc */
	syscall(SYS_open, err, O_RDONLY | O_CREAT | O_TRUNC);
	unlink(file);


	/* Success Condition: open(2): write, creat */
	if (syscall(SYS_open, file, O_WRONLY | O_CREAT) == -1){
		perror("open: write, creat");
		exit(-1);
	}

	/* Failure Condition: open(2): write, creat */
	syscall(SYS_open, err, O_WRONLY | O_CREAT);
	unlink(file);


	/* Success Condition: open(2): write, creat, trunc */
	if (syscall(SYS_open, file, O_WRONLY | O_CREAT | O_TRUNC) == -1){
		perror("open: write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): write, creat, trunc */
	syscall(SYS_open, err, O_WRONLY | O_CREAT | O_TRUNC);
	unlink(file);


	/* Success Condition: open(2): read, write, creat */
	if (syscall(SYS_open, file, O_RDWR | O_CREAT) == -1){
		perror("open: read, write, creat");
		exit(-1);
	}

	/* Failure Condition: open(2): read, write, creat */
	syscall(SYS_open, err, O_RDWR | O_CREAT);
	unlink(file);


	/* Success Condition: open(2): read, write, creat, trunc */
	if (syscall(SYS_open, file, O_RDWR | O_CREAT | O_TRUNC) == -1){
		perror("open: read, write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): read, write, creat, trunc */
	syscall(SYS_open, err, O_RDWR | O_CREAT | O_TRUNC);
	unlink(file);


	/* OPENAT Test-Cases */

	/* Success Condition: openat(2): read, creat */
	if (openat(AT_FDCWD, file, O_RDONLY | O_CREAT) == -1){
		perror("openat: read, creat");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, creat */
	openat(AT_FDCWD, err, O_RDONLY | O_CREAT);
	unlink(file);


	/* Success Condition: openat(2): read, creat, trunc */
	if (openat(AT_FDCWD, file, O_RDONLY | O_CREAT | O_TRUNC) == -1){
		perror("openat: read, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, creat, trunc */
	openat(AT_FDCWD, err, O_RDONLY | O_CREAT | O_TRUNC);
	unlink(file);


	/* Success Condition: openat(2): write, creat */
	if (openat(AT_FDCWD, file, O_WRONLY | O_CREAT) == -1){
		perror("openat: write, creat");
		exit(-1);
	}

	/* Failure Condition: openat(2): write, creat */
	openat(AT_FDCWD, err, O_WRONLY | O_CREAT);
	unlink(file);


	/* Success Condition: openat(2): write, creat, trunc */
	if (openat(AT_FDCWD, file, O_WRONLY | O_CREAT | O_TRUNC) == -1){
		perror("openat: write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): write, creat, trunc */
	openat(AT_FDCWD, err, O_WRONLY | O_CREAT | O_TRUNC);
	unlink(file);


	/* Success Condition: openat(2): read, write, creat */
	if (openat(AT_FDCWD, file, O_RDWR | O_CREAT) == -1){
		perror("openat: read, write, creat");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, write, creat */
	openat(AT_FDCWD, err, O_RDWR | O_CREAT);
	unlink(file);


	/* Success Condition: openat(2): read, write, creat, trunc */
	if (openat(AT_FDCWD, file, O_RDWR | O_CREAT | O_TRUNC) == -1){
		perror("openat: read, write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, write, creat, trunc */
	openat(AT_FDCWD, err, O_RDWR | O_CREAT | O_TRUNC);
	unlink(file);

}
