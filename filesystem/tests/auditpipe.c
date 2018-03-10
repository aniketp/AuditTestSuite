
#include<stdio.h>
#include<sys/stat.h>
#include<unistd.h>
#include<poll.h>
#include<fcntl.h>
#include<stdlib.h>

void main(){
    struct pollfd fds[1];
    int timeout = 5000;
    char buff[1024];
    char *dir = "audittest", *path = "templog.txt";
    mode_t mode = 0777;

    system("{ service auditd onestatus || \
        { service auditd onestart && touch started_auditd ; } ; } \
        > /dev/null 2>&1");

        /* Without sleep, auditd does not get time to initialize the process */
        sleep(1);

        /* Open auditpipe */
        fds[0].fd = open("/dev/auditpipe", O_RDWR);
        fds[0].events = POLLIN;

        mkdir(dir, mode);
        if (poll(fds, 1, timeout) < 0) {
            perror("poll");
            exit(EXIT_FAILURE);
        } else {
            if (fds[0].revents & POLLIN) {
                int n = read(fds[0].fd, buff, sizeof(buff));
                /* Store the buffer in a file */
                FILE *fd = fopen(path, "w");
                fwrite(buff, 1, sizeof(buff), fd);
                fclose(fd);
            }
            if (fds[0].revents & POLLHUP) {
                printf("Hangup\n" );
            }
        }

        close(fds[0].fd);
        system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
    }
