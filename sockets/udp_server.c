#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAXDATA 100
#define ERROR (-1)

int main(int argc, char **argv) {
    int sockfd, port;
    struct sockaddr_in server, *client;
    struct msghdr msg = {};
    struct iovec io;
    char buf[MAXDATA + 1], ip[16], *temp;
    ssize_t length;

    int len = sizeof(struct sockaddr_in);
    client = (struct sockaddr_in *) malloc (sizeof(struct sockaddr_in));

    if((sockfd = socket(PF_INET, SOCK_DGRAM, 0)) == ERROR){
        perror("Socket error");
        exit(ERROR);
    }

    bzero(&server, sizeof(server));
    server.sin_family = PF_INET;
    server.sin_addr.s_addr = htonl(INADDR_ANY);
    server.sin_port = htons(9000);

    if((bind(sockfd, (struct sockaddr *)&server, (socklen_t) len)) == ERROR){
        perror("Bind error");
        exit(ERROR);
    }

    msg.msg_name = client;
    msg.msg_namelen = (socklen_t) len;
    io.iov_base = buf;
    io.iov_len = MAXDATA;
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;


    /* Failure Condition: recvmsg(2) */
    recvmsg(ERROR, &msg, 0);

    /* Success Condition: recvmsg(2) */
    if((length = recvmsg(sockfd, &msg, 0)) == ERROR){
        perror("Recvmsg Error");
        exit(ERROR);
    }

    client = (struct sockaddr_in *)msg.msg_name;
    inet_ntop(PF_INET, &(client->sin_addr), ip, sizeof(ip));

    port = ntohs(client->sin_port);
    temp = msg.msg_iov[0].iov_base;
    temp[length] = '\0';

    //printf("Recieved message from %s[%d]: %s\n", ip, port, temp);

    close(sockfd);
}
