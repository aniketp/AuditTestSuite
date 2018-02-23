#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>

#define BUFFLEN 1024
#define ERROR (-1)

void main(){
    int filedesc;

    /* Success condition: openat(2) */
    /* Currently tests for read-write (no-create) flag */
    if ((filedesc = openat(AT_FDCWD ,"test", O_RDWR)) == ERROR){
        perror("open");
        exit(ERROR);
    }

    /* Failure Condition: openat(2) */
    openat(AT_FDCWD ,"ERROR", O_RDWR);

    close(filedesc);

}
