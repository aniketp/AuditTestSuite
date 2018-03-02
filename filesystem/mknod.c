/* REQUIRES SUPERUSER PRIVILEGE */

#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>
#include<sys/types.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    int filedesc = 0;
    char *fifo1 = "/tmp/fifo1", *fifo2 = "/tmp/fifo2";
    dev_t dev = 0;

    /* Success Condition: mknod(2) */
    if ((filedesc1 = mknod(fifo1, S_IFIFO | S_IRWXO, dev)) == ERROR){
        perror("mknod");
        exit(ERROR);
    }

    /* Failure condition: mknod(2) :: fifo already exists */
    mknod(fifo1, S_IFIFO | S_IRWXO, dev);


    /* Success condition: mknodat(2) */
    if ((filedesc2 = mknodat(filedesc, fifo2, S_IFIFO | S_IRWXO, dev)) == ERROR){
        perror("mknodat");
        exit(ERROR);
    }

    /* Failure condition: mknodat(2) :: fifo already exists */
    mknodat(filedesc, fifo2, S_IFIFO | S_IRWXO, dev);

    /* Node cleanup */
    int fifo1_ = unlink(fifo1);
    int fifo2_ = unlink(fifo2);
    if ((fifo1_ == ERROR) || (fifo2_ == ERROR)){
        perror("unlink");
        exit(ERROR);
    }
}
