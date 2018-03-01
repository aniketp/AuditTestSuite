#include<stdio.h>
#include<stdlib.h>
#include<sys/stat.h>
#include<sys/types.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    int filedesc = 0;
    char *dir1 = "/tmp/temp1", *dir2 = "/tmp/temp2";
    mode_t mode = 0777;

    /* Success Condition: mkfifo(2) */
    if ((filedesc1 = mkfifo(dir1, mode)) == ERROR){
        perror("mkfifo");
        exit(ERROR);
    }
    /* Failure condition: mkfifo(2) :: fifo already exists */
    mkfifo(dir1, mode);


    /* Success condition: mkfifoat(2) */
    if ((filedesc2 = mkfifoat(filedesc, file2, mode)) == ERROR){
        perror("mkfifoat");
        exit(ERROR);
    }

    /* Failure condition: mkfifoat(2) :: fifo already exists */
    mkfifoat(filedesc, file2, mode);
}
