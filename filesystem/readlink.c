#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<string.h>

#define BUFFLEN 1024
#define ERROR (-1)

void main(){
    char buff1[BUFFLEN], buff2[BUFFLEN];
    char *sym = "/tmp/templog1";
    char *err = "/tmp/ERROR";
    int fd = 0;

    /* readlink(2), readlinkat(2) do not append '\0' at the end */
    memset(buff1, 0, sizeof(buff1));
    memset(buff2, 0, sizeof(buff2));

    /* Success condition: readlink(2) */
    if (readlink(sym, buff1, sizeof(buff1)-1) == ERROR){
        perror("readlink");
        exit(ERROR);
    }

    /* Failure condition: readlink(2) */
    readlink(err, buff1, sizeof(buff1)-1);

    /* Success condition: readlinkat(2) */
    if (readlinkat(fd, sym, buff2, sizeof(buff2)-1) == ERROR){
        perror("readlinkat");
        exit(ERROR);
    }

    /* Failure condition: readlinkat(2) */
    readlinkat(fd, err, buff2, sizeof(buff2)-1);

}