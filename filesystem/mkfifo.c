#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/types.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    int filedesc = 0;
    char *fifo1 = "/tmp/temp1", *fifo2 = "/tmp/temp2";
    mode_t mode = 0777;

    /* Success Condition: mkfifo(2) */
    if ((filedesc1 = mkfifo(fifo1, mode)) == ERROR){
        perror("mkfifo");
        exit(ERROR);
    }
    /* Failure condition: mkfifo(2) :: fifo already exists */
    mkfifo(fifo1, mode);


    /* Success condition: mkfifoat(2) */
    if ((filedesc2 = mkfifoat(filedesc, fifo2, mode)) == ERROR){
        perror("mkfifoat");
        exit(ERROR);
    }

    /* Failure condition: mkfifoat(2) :: fifo already exists */
    mkfifoat(filedesc, fifo2, mode);

    /* Fifo cleanup */
    int fifo1_ = unlink(fifo1);
    int fifo2_ = unlink(fifo2);
    if ((fifo1_ == ERROR) || (fifo2_ == ERROR)){
        perror("unlink");
        exit(ERROR);
    }
}
