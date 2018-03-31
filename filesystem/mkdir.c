#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<sys/stat.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    char *dir1 = "/tmp/temp1", *dir2 = "/tmp/temp2";
    mode_t mode = 0777;

    /* Success Condition: mkdir(2) */
    if ((filedesc1 = mkdir(dir1, mode)) == ERROR){
        perror("mkdir");
        exit(ERROR);
    }
    /* Failure condition: mkdir(2) :: Directory already exists */
    mkdir(dir1, mode);


    /* Success condition: mkdirat(2) */
    if ((filedesc2 = mkdirat(AT_FDCWD, dir2, mode)) == ERROR){
        perror("mkdirat");
        exit(ERROR);
    }

    /* Failure condition: mkdirat(2) :: Directory already exists */
    mkdirat(AT_FDCWD, dir2, mode);

    /* Directory cleanup */
    int dir1_ = rmdir(dir1);
    int dir2_ = rmdir(dir2);
    if ((dir1_ == ERROR) || (dir2_ == ERROR)){
        perror("rmdir");
        exit(ERROR);
    }
}
