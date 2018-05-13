#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>

#define BUFFLEN 1024
#define ERROR (-1)

void main(){
    long int filedesc1, filedesc2;
    char *file1 = "templog1";
    char *file2 = "templog2";

    /* Create the file to be renamed */
    if (open(file1, O_CREAT) == ERROR){
        perror("open");
        exit(ERROR);
    }

    /* Success Condition: rename(2) */
    if ((filedesc1 = rename(file1, file2)) == ERROR){
        perror("rename");
        exit(ERROR);
    }

    /* Failure Condition: rename(2) */
    rename(file1, file2);


    /* Success condition: renameat(2) */
    if ((filedesc2 = renameat(AT_FDCWD, file2, AT_FDCWD, file1)) == ERROR){
        perror("renameat");
        exit(ERROR);
    }

    /* Failure Condition: renameat(2) */
    renameat(AT_FDCWD, file2, AT_FDCWD, file1);

    close((int) filedesc1);
    close((int) filedesc2);

    /* File cleanup */
    int file1_ = unlink(file1);
    int file2_ = unlink(file2);
    if ((file1_ == ERROR) || (file2_ == ERROR)){
        perror("unlink");
        exit(ERROR);
    }

}
