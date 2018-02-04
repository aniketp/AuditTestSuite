#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define ERROR (-1)
#define MAX_DATA 512

void main(int argc, char **argv){
    int sockfd, clientfd;
    struct sockaddr_in server, client;
    socklen_t len;
    char data[MAX_DATA];
    char msg[] = "Message Sent\n";
    ssize_t bytes_sent, data_len;
    int tr=1;

    // Creating Socket
    if((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == ERROR){
        perror("Socket error");
        exit(ERROR);
    }

    // Assigning addresses
    server.sin_family = PF_INET;            // IPv4
    server.sin_port = htons(9000);          // Port in network bytes
    server.sin_addr.s_addr = INADDR_ANY;    // All available interfaces
    bzero(&server.sin_zero, 8);             // Zero padding

    len = sizeof(struct sockaddr_in);

    // Kill "Address already in use" error message
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tr, sizeof(int)) == ERROR) {
        perror("setsockopt");
        exit(ERROR);
    }

    // Bind to the address
    if((bind(sockfd, (struct sockaddr *)&server, (socklen_t) len)) == ERROR){
        perror("Bind error");
        exit(ERROR);
    }

    //Listen for connections
    if((listen(sockfd, 1)) == ERROR){
        perror("Listen error");
        exit(ERROR);
    }

    // Accept connection from a client and return the new socket
    if((clientfd = accept(sockfd, (struct sockaddr *)&client, &len)) == ERROR){
        perror("Accept error");
        exit(ERROR);
    }

    // Print the connection information
    printf("New client connected from port no %d and IP %s\n",
           ntohs(client.sin_port), inet_ntoa(client.sin_addr));

    // Send the message after connection completes
    if((bytes_sent = send(clientfd, msg, strlen(msg), 0)) == ERROR){
        perror("Send error");
        exit(ERROR);
    }

    printf("Sent %d bytes to Client %s\n",
           (int) bytes_sent, inet_ntoa(client.sin_addr));

    // Keep sending the same data till no response from client
    data_len = recv(clientfd, data, MAX_DATA , 0);

    if(data_len){
        send(clientfd, data, (size_t) data_len, 0);
        data[data_len] = '\0';
        printf("Sent message: %s\n", data);
    }


    printf("Client disconnected\n");

    // Close the connection
    close(clientfd);
}
