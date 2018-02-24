#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

#define BUFFLEN 1024
#define ERROR (-1)

void main(){
    char buff1[BUFFLEN], buff2[BUFFLEN];
    int fd = 0;

    /* readlink(2), readlinkat(2) do not append '\0' at the end */
    memset(buff1, 0, sizeof(buff1));
    memset(buff2, 0, sizeof(buff2));

    /* Success condition: readlink(2) */
    if (readlink("templog1", buff1, sizeof(buff1)-1) == ERROR){
        perror("readlink");
        exit(ERROR);
    }

    /* Failure condition: readlink(2) */
    readlink("/tmp/ERROR", buff1, sizeof(buff1)-1);

    /* Success condition: readlinkat(2) */
    if (readlinkat(fd, "templog1", buff2, sizeof(buff2)-1) == ERROR){
        perror("readlinkat");
        exit(ERROR);
    }

    /* Failure condition: readlinkat(2) */
    readlinkat(fd, "/tmp/ERROR", buff2, sizeof(buff2)-1);

}