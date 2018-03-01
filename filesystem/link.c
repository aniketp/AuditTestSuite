#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>

#define ERROR (-1)

void main(){
    int filedesc1, filedesc2;
    int fd1 = 0, fd2 = 0;
    char *file1 = "/tmp/file1", *fifo2 = "/tmp/file2";
    char *sym1 = "/tmp/sym1", *sym2 = "/tmp/sym2";

    /* Failure condition: link(2) :: file does not exist */
    link(file1, sym1);

    /* TODO: Create file1 */

    /* Success Condition: link(2) */
    if ((filedesc1 = link(file1, sym1)) == ERROR){
        perror("link");
        exit(ERROR);
    }

    /* Failure condition: linkat(2) :: file does not exist */
    linkat(fd1, file2, fd2, sym2);

    /* TODO: Create file2 */

    /* Success condition: linkat(2) */
    if ((filedesc2 = linkat(fd1, file2, fd2, sym2)) == ERROR){
        perror("linkat");
        exit(ERROR);
    }
}
