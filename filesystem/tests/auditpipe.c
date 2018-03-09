#include<stdio.h>
#include<unistd.h>
#include<poll.h>
#include<fcntl.h>
#include<stdlib.h>

void main(){
    struct pollfd fds[1];
    int timeout_msecs = 5000;

    system("{ service auditd onestatus || \
        { service auditd onestart && touch started_auditd ; } ; } \
         > /dev/null 2>&1");

    /* Without sleep, auditd does not get time to initialize and the process
     *triggers some POLLIN event which results in "Pollin Success" getting printed
     */
    sleep(1);

    /* Open auditpipe */
    fds[0].fd = open("/dev/auditpipe", O_RDWR);
    fds[0].events = POLLIN;

    if (poll(fds, 1, timeout_msecs) < 0) {
        perror("poll");
        exit(EXIT_FAILURE);
    } else {
        /* For loop currently redundant as there is only one file descriptor */
        for (int i=0; i<1; i++) {
            if (fds[i].revents & POLLIN) {
                printf("Pollin Success\n");
            }
            if (fds[i].revents & POLLHUP) {
                printf("Hangup\n" );
            }
        }
    }

    close(fds[0].fd);
    system("[ -f started_auditd ] && service auditd onestop > /dev/null 2>&1");
}
