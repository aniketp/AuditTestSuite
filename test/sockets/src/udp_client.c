#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define ERROR (-1)

void main(int argc, char ** argv) {
    int sockfd;
    struct sockaddr_in server;
    struct msghdr msg = {};
    struct iovec io;
    char send[] = "Test Message";

    int len = sizeof(struct sockaddr_in);

    if((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == ERROR){
        perror("Socket error");
        exit(ERROR);
    }

    bzero(&server, sizeof(server));
    server.sin_family = PF_INET;
    server.sin_port = htons(9000);
    inet_pton(PF_INET, "localhost", &server.sin_addr);

    msg.msg_name = &server;
    msg.msg_namelen = (socklen_t) len;
    io.iov_base = send;
    io.iov_len = sizeof(send);
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;

    /* Success Condition: sendmsg(2) */
    if((sendmsg(sockfd, &msg, MSG_OOB)) == ERROR){
        perror("Sendmsg error");
        exit(ERROR);
    }

    /* Failure Condition: sendmsg(2) */
    sendmsg(ERROR, &msg, MSG_OOB);

    close(sockfd);
}
