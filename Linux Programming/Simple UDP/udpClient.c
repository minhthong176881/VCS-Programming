#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SERV_PORT 1255
#define MAXLINE 255

int main(int agrc, char **argv) {
    int sockfd, n, from_len;
    struct sockaddr_in servaddr, from_socket;
    socklen_t addrlen = sizeof(from_socket);
    char sendline[MAXLINE], recvline[MAXLINE];

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    printf("Socket created.\n");

    while (fgets(sendline, MAXLINE, stdin) != NULL)
    {
        printf("To server: %s", sendline);
        sendto(sockfd, sendline, strlen(sendline), 0, (struct sockaddr *) &servaddr, sizeof(servaddr));
        n = recvfrom(sockfd, recvline, MAXLINE, 0, (struct sockaddr *) &from_socket, &addrlen);
        recvline[n] = 0;
        printf("From server: %s %d %s", inet_ntoa(from_socket.sin_addr), htons(from_socket.sin_port), recvline);
    }
    
}