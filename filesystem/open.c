#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/syscall.h>

#define BUFFLEN 1024
#define ERROR (-1)

void main(){
    long int filedesc1, filedesc2;
    char *sym = "/tmp/templog";
    char *err = "/tmp/ERROR";

    /* Success Condition: open(2) */
    if ((filedesc1 = syscall(SYS_open, sym, O_RDWR)) == ERROR){
        perror("open");
        exit(ERROR);
    }

    /* Failure Condition: open(2) */
    syscall(SYS_open, err, O_RDWR);


    /* Success condition: openat(2) */
    /* Currently tests for read-write (no-create) flag */
    if ((filedesc2 = openat(AT_FDCWD, sym, O_RDWR)) == ERROR){
        perror("openat");
        exit(ERROR);
    }

    /* Failure Condition: openat(2) */
    openat(AT_FDCWD, err, O_RDWR);

    close((int) filedesc1);
    close((int) filedesc2);

    /* File cleanup */
    int file1_ = unlink(sym);
    int file2_ = unlink(err);
    if ((file1_ == ERROR) || (file2_ == ERROR)){
        perror("unlink");
        exit(ERROR);
    }

}
