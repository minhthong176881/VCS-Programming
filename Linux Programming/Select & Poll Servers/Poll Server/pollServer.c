#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <ctype.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <poll.h>
#include <limits.h>
#include <time.h>

#define LISTENQ 121
#define BUF_SIZE 1024
#define PORT 5500

// write "n" bytes to a descriptor
ssize_t writen(int fd, char *ptr, size_t n) {
    ssize_t nleft = n, nwritten;

    while (nleft > 0) {
        if ((nwritten = write(fd, ptr, nleft)) <= 0) {
            if (nwritten < 0 && errno == EINTR) {
                nwritten = 0; // call write() again
            } else return -1;
        }

        nleft -= nwritten;
        ptr += nwritten;
    }

    return n;
}

// void usage(char *program) {
//     fprintf(stderr, "usage: %s port\n", program);
// }

int main(int argc, char **argv) {
    int nready, i, maxi, listenfd, connfd, sockfd;
    socklen_t clilen;
    struct sockaddr_in cliaddr, servaddr;
    char buf[BUF_SIZE];
    const int OPEN_MAX = 121; // maximum number of opened files
    struct pollfd clients[OPEN_MAX];
    ssize_t n;
    int pool_timeout = 6000; // time for poll to wait

    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        fprintf(stderr, "Error: socket\n");
        return EXIT_FAILURE;
    } else {
        printf("Create listen socket %d\n", listenfd);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        perror("Error");
        return EXIT_FAILURE;
    }

    if (listen(listenfd, LISTENQ) < 0) {
        fprintf(stderr, "Error: listen\n");
        return EXIT_FAILURE;
    }

    clients[0].fd = listenfd;
    clients[0].events = POLLRDNORM;

    for (i = 1; i < OPEN_MAX; i++) {
        clients[i].fd = -1; // -1 indicates available entry
    }


    maxi = 0; // max index into clients array

    while (1) {
        nready = poll(clients, maxi + 1, pool_timeout);

        if (nready < 0) {
            continue;
        }

        if (nready == 0) {
            break;
        }

        // check new connection
        if (clients[0].revents & POLLRDNORM) {
            clilen = sizeof(cliaddr);
            if ((connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &clilen)) < 0) {
                fprintf(stderr, "Error: accept\n");
                return EXIT_FAILURE;
            }

            printf("Accept socket %d (%s:%hu)\n", connfd, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

            // save client socket into clients array
            for (i = 0; i < OPEN_MAX; i++) {
                if (clients[i].fd < 0) {
                    clients[i].fd = connfd;
                    break;
                }
            }

            // no enough space in clients array
            if (i == OPEN_MAX) {
                fprintf(stderr, "Error: too many clients\n");
                close(connfd);
            }

            clients[i].events = POLLRDNORM;

            if (i > maxi) maxi = i;

            // no more readable file descriptors
            if (--nready <= 0) continue;
        }

        for (i = 1; i <= maxi; i++) {
            if ((sockfd = clients[i].fd) < 0) continue;

            // if the client is readable or errors occur
            if (clients[i].revents && (POLLWRNORM | POLLERR)) {
                n = read(sockfd, buf, BUF_SIZE);

                if (n < 0) {
                    fprintf(stderr, "Error: read from socket %d\n", sockfd);
                    close(sockfd);
                    clients[i].fd = -1;
                } else if (n == 0) { // connection closed by client
                    printf("Close socket %d\n", sockfd);
                    close(sockfd);
                    clients[i].fd = -1;
                } else {
                    printf("Read %zu bytes from socket %d\n", n, sockfd);
                    writen(sockfd, buf, n);
                }

                // no more readable file descriptors
                if (--nready <= 0) {
                    break;
                }
            }
        }
    }

    printf("-----------------------------------\n");
    printf("Poll timeout, closing connection...\n");
    close(listenfd);
    printf("-----------------------------------\n");
    printf("Done!\n");
    return EXIT_SUCCESS;
}