#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    int filedesc = 0;
    char *file1 = "/tmp/temp1", *file2 = "/tmp/temp2"
    char *sym1 = "/tmp/sym1", *sym2 = "/tmp/sym2"

    /* Success Condition: symlink(2) */
    if ((filedesc1 = symlink(file1, sym1)) == ERROR){
        perror("symlink");
        exit(ERROR);
    }
    /* Failure condition: symlink(2) :: File already exists */
    symlink(file1, sym1);


    /* Success condition: symlinkat(2) */
    if ((filedesc2 = symlinkat(file2, filedesc, sym2)) == ERROR){
        perror("symlinkat");
        exit(ERROR);
    }

    /* Failure condition: symlinkat(2) :: File already exists */
    symlinkat(file2, filedesc, sym2);
}
