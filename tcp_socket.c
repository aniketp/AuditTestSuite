#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define MAX_DATA 512
#define ERROR (-1)

void main(int argc, char **argv){
    int sockfd;
    int clientfd;
    struct sockaddr_in server, client;
    socklen_t len;
    char data[MAX_DATA];
    char msg[] = "Message Sent\n";
    int tr=1;

    // Assigning addresses
    server.sin_family = PF_INET;            // IPv4
    server.sin_port = htons(9000);          // Port in network bytes
    server.sin_addr.s_addr = INADDR_ANY;    // All available interfaces
    bzero(&server.sin_zero, 8);             // Zero padding

    len = sizeof(struct sockaddr_in);


    /* Success Condition: socket(2) */
    if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == ERROR){
        perror("Socket error");
        exit(ERROR);
    }

    /* Failure Condition: socket(2) */
    socket(ERROR, SOCK_STREAM, 0);


    /* Success Condition: setsockopt(2) */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == ERROR) {
        perror("setsockopt");
        exit(ERROR);
    }

    /* Failure Condition: setsockopt(2) */
    setsockopt(ERROR, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int));


    /* Success Condition: bind(2) */
    if((bind(sockfd, (struct sockaddr *)&server, (socklen_t) len)) == ERROR){
        perror("Bind error");
        exit(ERROR);
    }

    /* Failure Condition: bind(2) */
    bind(ERROR, (struct sockaddr *)&server, (socklen_t) len);


    /* Success Condition: listen(2) */
    if((listen(sockfd, 1)) == ERROR){
        perror("Listen error");
        exit(ERROR);
    }

    /* Failure Condition: listen(2) */
    listen(ERROR, 1);


    /* Success Condition: accept(2) */
    if((clientfd = accept(sockfd, (struct sockaddr *)&client, &len)) == ERROR){
        perror("Accept error");
        exit(ERROR);
    }

    /* Failure Condition: accept(2) */
    accept(ERROR, (struct sockaddr *)&client, &len);


    /* Success Condition: connect(2) established while recieving message buffer */
    /* Failure Condition: connect(2) */
    connect(ERROR, (struct sockaddr *)&server, len);


    /* Success Condition: send(2) */
    if((send(clientfd, msg, strlen(msg), 0)) == ERROR){
        perror("Send error");
        exit(ERROR);
    }

    /* Failure Condition: send(2) */
    send(ERROR, msg, strlen(msg), 0);


    /* Failure Condition: recv(2) */
    recv(ERROR, data, MAX_DATA , 0);

    /* Success Condition: recv(2) */
    if((recv(clientfd, data, MAX_DATA , 0)) == ERROR){
        perror("Recv error");
        exit(ERROR);
    };


    /* TODO: Implement sendto(2), recvfrom(2), connect(2) here */

    // Close the connection
    close(clientfd);
}
