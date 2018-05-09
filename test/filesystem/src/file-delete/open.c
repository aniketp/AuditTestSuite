#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/syscall.h>

void main(){
	char *file = "fileexists";
	char *err = "dirdoesnotexist/filedoesnotexist";

	/* Success Condition: open(2): read, trunc */
	if (syscall(SYS_open, file, O_RDONLY | O_TRUNC) == -1){
		perror("open: read, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): read, trunc */
	syscall(SYS_open, err, O_RDONLY | O_TRUNC);
	unlink(file);


	/* Success Condition: open(2): read, creat, trunc */
	if (syscall(SYS_open, file, O_RDONLY | O_CREAT | O_TRUNC) == -1){
		perror("open: read, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): read, creat, trunc */
	syscall(SYS_open, err, O_RDONLY | O_CREAT | O_TRUNC);


	/* Success Condition: open(2): write, trunc */
	if (syscall(SYS_open, file, O_WRONLY | O_TRUNC) == -1){
		perror("open: write, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): write, trunc */
	syscall(SYS_open, err, O_WRONLY | O_TRUNC);
	unlink(file);


	/* Success Condition: open(2): write, creat, trunc */
	if (syscall(SYS_open, file, O_WRONLY | O_CREAT | O_TRUNC) == -1){
		perror("open: write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): write, creat, trunc */
	syscall(SYS_open, err, O_WRONLY | O_CREAT | O_TRUNC);


	/* Success Condition: open(2): read, write, trunc */
	if (syscall(SYS_open, file, O_RDWR | O_TRUNC) == -1){
		perror("open: read, write, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): read, write, trunc */
	syscall(SYS_open, err, O_RDWR | O_TRUNC);
	unlink(file);


	/* Success Condition: open(2): read, write, creat, trunc */
	if (syscall(SYS_open, file, O_RDWR | O_CREAT | O_TRUNC) == -1){
		perror("open: read, write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: open(2): read, write, creat, trunc */
	syscall(SYS_open, err, O_RDWR | O_CREAT | O_TRUNC);


	/* OPENAT Test-Cases */

	/* Success Condition: openat(2): read, trunc */
	if (openat(AT_FDCWD, file, O_RDONLY | O_TRUNC) == -1){
		perror("openat: read, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, trunc */
	openat(AT_FDCWD, err, O_RDONLY | O_TRUNC);
	unlink(file);


	/* Success Condition: openat(2): read, creat, trunc */
	if (openat(AT_FDCWD, file, O_RDONLY | O_CREAT | O_TRUNC) == -1){
		perror("openat: read, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, creat, trunc */
	openat(AT_FDCWD, err, O_RDONLY | O_CREAT | O_TRUNC);


	/* Success Condition: openat(2): write, trunc */
	if (openat(AT_FDCWD, file, O_WRONLY | O_TRUNC) == -1){
		perror("openat: write, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): write, trunc */
	openat(AT_FDCWD, err, O_WRONLY | O_TRUNC);
	unlink(file);


	/* Success Condition: openat(2): write, creat, trunc */
	if (openat(AT_FDCWD, file, O_WRONLY | O_CREAT | O_TRUNC) == -1){
		perror("openat: write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): write, creat, trunc */
	openat(AT_FDCWD, err, O_WRONLY | O_CREAT | O_TRUNC);


	/* Success Condition: openat(2): read, write, trunc */
	if (openat(AT_FDCWD, file, O_RDWR | O_TRUNC) == -1){
		perror("openat: read, write, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, write, trunc */
	openat(AT_FDCWD, err, O_RDWR | O_TRUNC);
	unlink(file);


	/* Success Condition: openat(2): read, write, creat, trunc */
	if (openat(AT_FDCWD, file, O_RDWR | O_CREAT | O_TRUNC) == -1){
		perror("openat: read, write, creat, trunc");
		exit(-1);
	}

	/* Failure Condition: openat(2): read, write, creat, trunc */
	openat(AT_FDCWD, err, O_RDWR | O_CREAT | O_TRUNC);

}
