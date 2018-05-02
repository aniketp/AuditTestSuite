#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<fcntl.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    int fd1 = 0, fd2 = 0;
    char *file1 = "/tmp/file1", *file2 = "/tmp/file2";
    char *sym1 = "/tmp/sym1", *sym2 = "/tmp/sym2";

    /* Failure condition: link(2) :: file does not exist */
    link(file1, sym1);

    if (open(file1, O_RDONLY | O_CREAT, 0644) == ERROR){
        perror("open-create");
        exit(ERROR);
    }

    /* Success Condition: link(2) */
    if ((filedesc1 = link(file1, sym1)) == ERROR){
        perror("link");
        exit(ERROR);
    }

    /* Failure condition: linkat(2) :: file does not exist */
    linkat(fd1, file2, fd2, sym2, 0);

    if (open(file2, O_RDONLY | O_CREAT, 0644) == ERROR){
        perror("open-create");
        exit(ERROR);
    }

    /* Success condition: linkat(2) */
    if ((filedesc2 = linkat(fd1, file2, fd2, sym2, 0)) == ERROR){
        perror("linkat");
        exit(ERROR);
    }

    close((int) filedesc1);
    close((int) filedesc2);

    /* Hardlink and file cleanup */
    int file1_ = unlink(file1);
    int file2_ = unlink(file2);
    int sym1_ = unlink(sym1);
    int sym2_ = unlink(sym2);
    if ((file1_ == ERROR) || (file2_ == ERROR) || \
        (sym1_ == ERROR) || (sym2_ == ERROR)){
        perror("unlink");
        exit(ERROR);
    }
}
