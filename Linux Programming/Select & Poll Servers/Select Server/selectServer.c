#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>

#define PORT 5500  /* Port that will be opened */
#define BACKLOG 20 /* Number of allowed connections */
#define BUFF_SIZE 1024

void processData(char *in, char *out);

int receiveData(int s, char *buff, int size, int flags);

int sendData(int s, char *buff, int size, int flags);

int main()
{
    int i, maxi, maxfd, listenfd, connfd, sockfd;
    int nready, client[FD_SETSIZE];
    ssize_t ret;
    fd_set readfds, allset;
    char sendBuff[BUFF_SIZE], recvBuff[BUFF_SIZE];
    socklen_t clilen;
    struct sockaddr_in cliaddr, servaddr;

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Error: ");
        return 0;
    }

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        perror("Error: ");
        return 0;
    }

    if (listen(listenfd, BACKLOG) == -1)
    {
        perror("Error: ");
        return 0;
    }

    maxfd = listenfd; // initialize
    maxi = -1;        // index into client[] array
    for (i = 0; i < FD_SETSIZE; i++)
    {
        client[i] = -1; // -1 indicates available entry
    }
    FD_ZERO(&allset);
    FD_SET(listenfd, &allset);

    while (1)
    {
        readfds = allset; // structure assignment
        nready = select(maxfd + 1, &readfds, NULL, NULL, NULL);
        if (nready < 0)
        {
            perror("Error: ");
            return 0;
        }

        if (FD_ISSET(listenfd, &readfds))
        { // new client connection
            clilen = sizeof(cliaddr);
            if (connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen) < 0)
            {
                perror("Error: ");
            }
            else
            {
                printf("You got a connection from %s\n", inet_ntoa(cliaddr.sin_addr));
                for (i = 0; i < FD_SETSIZE; i++)
                {
                    if (client[i] < 0)
                    {
                        client[i] = connfd; // save descriptor
                        break;
                    }
                }
                if (i == FD_SETSIZE)
                {
                    printf("Too many clients.\n");
                    close(connfd);
                }

                FD_SET(connfd, &allset); // add new descriptor to set
                if (connfd > maxfd)
                    maxfd = connfd; // for select
                if (i > maxi)
                    maxi = i; // max index in client[] array

                if (--nready <= 0)
                    continue; // no more readable desciptors
            }
        }

        for (i = 0; i <= maxi; i++)
        { // check all clients for data
            if ((connfd = client[i]) <= 0)
                continue;
            if (FD_ISSET(connfd, &readfds))
            {
                ret = receiveData(sockfd, recvBuff, BUFF_SIZE, 0);
                if (ret <= 0)
                {
                    FD_CLR(connfd, &allset);
                    close(connfd);
                    client[i] = -1;
                }
                else
                {
                    processData(recvBuff, sendBuff);
                    ret = sendData(sockfd, sendBuff, ret, 0);
                    if (ret <= 0)
                    {
                        FD_CLR(sockfd, &allset);
                        close(sockfd);
                        client[i] = -1;
                    }
                }

                if (--nready <= 0)
                    break; // no more readable descriptors
            }
        }
    }

    return 0;
}

void processData(char *in, char *out)
{
    strcpy(out, in);
}

int receiveData(int s, char *buff, int size, int flag)
{
    int n;
    n = recv(s, buff, size, flag);
    if (n < 0)
        perror("Error: ");
    return n;
}

int sendData(int s, char *buff, int size, int flag)
{
    int n;
    n = send(s, buff, size, flag);
    if (n < 0)
        perror("Error: ");
    return n;
}