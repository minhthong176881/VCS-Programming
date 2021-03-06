#include <wolfssl/options.h>
#include <stdio.h>                  /* standard in/out procedures */
#include <stdlib.h>                 /* defines system calls */
#include <string.h>                 /* necessary for memset */
#include <netdb.h>
#include <sys/socket.h>             /* used for all socket calls */
#include <netinet/in.h>             /* used for sockaddr_in */
#include <arpa/inet.h>
#include <wolfssl/ssl.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>

#define SERV_PORT   11111           /* define our server port number */
#define MSGLEN      4096

static int cleanup = 0;                 /* To handle shutdown */
struct sockaddr_in servAddr;        /* our server's address */
struct sockaddr_in cliaddr;         /* the client's address */

int main(int argc, char** argv)
{
    /* Loc short for "location" */
    char        caCertLoc[] = "./certs/rootCA.crt";
    char        servCertLoc[] = "./certs/server.crt";
    char        servKeyLoc[] = "./certs/server.key";
    WOLFSSL_CTX* ctx;
    /* Variables for awaiting datagram */
    int           on = 1;
    int           res = 1;
    int           connfd = 0;
    int           recvLen = 0;    /* length of message */
    int           listenfd = 0;   /* Initialize our socket */
    WOLFSSL*      ssl = NULL;
    socklen_t     cliLen;
    socklen_t     len = sizeof(int);
    unsigned char b[MSGLEN];      /* watch for incoming messages */
    char          buff[MSGLEN];   /* the incoming message */

    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Set ctx to DTLS 1.2 */
    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        printf("wolfSSL_CTX_new error.\n");
        return 1;
    }
    /* Load CA certificates */
    if (wolfSSL_CTX_load_verify_locations(ctx,caCertLoc,0) != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", caCertLoc);
        return 1;
    }
    /* Load server certificates */
    if (wolfSSL_CTX_use_certificate_file(ctx, servCertLoc, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", servCertLoc);
        return 1;
    }
    /* Load server Keys */
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, servKeyLoc, SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", servKeyLoc);
        return 1;
    }

    /* Await Datagram */
    ;

    while (cleanup != 1) {
        /* Create a UDP/IP socket */
        if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
            printf("Cannot create socket.\n");
            cleanup = 1;
            break;
        }
        printf("Socket allocated\n");

        /* clear servAddr each loop */
        memset((char *)&servAddr, 0, sizeof(servAddr));

        servAddr.sin_family      = AF_INET;
        servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servAddr.sin_port        = htons(SERV_PORT);

        /* Eliminate socket already in use error */
        res = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0) {
            printf("Setsockopt SO_REUSEADDR failed.\n");
            cleanup = 1;
            break;
        }

        /* Bind Socket */
        if (bind(listenfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
            printf("Bind failed.\n");
            cleanup = 1;
            break;
        }

        printf("Awaiting client connection on port %d\n", SERV_PORT);

        /* Create the WOLFSSL Object */
        if ((ssl = wolfSSL_new(ctx)) == NULL) {
            printf("wolfSSL_new error.\n");
            break;
        }

        /* set the session ssl to client connection port */
        wolfSSL_set_fd(ssl, listenfd);

        for (;;) {
            cliLen = sizeof(cliaddr);
            connfd = (int)recvfrom(listenfd, (char *)&b, sizeof(b), MSG_PEEK, (struct sockaddr*)&cliaddr, &cliLen);

            if (connfd < 0) {
                printf("No clients in que, enter idle state\n");
                close(listenfd);
                continue;
            }
            else if (connfd > 0) {
                if (connect(listenfd, (const struct sockaddr *)&cliaddr,sizeof(cliaddr)) != 0) {
                    printf("Udp connect failed.\n");
                    break;
                }
            }
            else {
                printf("Recvfrom failed.\n");
                break;
            }
            printf("Datagram has arrived!\n");

            if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
                int e = wolfSSL_get_error(ssl, 0);

                printf("error = %d, %s\n", e, wolfSSL_ERR_reason_error_string(e));
                printf("SSL_accept failed.\n");
                break;
            }

            if ((recvLen = wolfSSL_read(ssl, buff, sizeof(buff)-1)) > 0) {
                printf("Received %d bytes from %s:%hu\n", recvLen, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

                buff[recvLen] = '\0';
                buff[recvLen-1] = '\0';
            }
            else if (recvLen < 0) {
                int readErr = wolfSSL_get_error(ssl, 0);
                if(readErr != SSL_ERROR_WANT_READ) {
                    printf("SSL_read failed.\n");
                    break;
                }
            }

            if (recvLen == 0) break;

            if (wolfSSL_write(ssl, buff, recvLen) < 0) {
                printf("wolfSSL_write fail.\n");
                break;
            }
            else {
                printf("Sending reply.\n");
            }

            printf("Reply sent \"%s\"\n", buff);
        }

        wolfSSL_set_fd(ssl, 0);
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        cleanup = 0;

        printf("Client left cont to idle state\n");
        printf("--------------------------------------------\n");
    }
    
    /* cleanup */
    if (cleanup == 1) {
        wolfSSL_set_fd(ssl, 0);
        wolfSSL_shutdown(ssl);
        wolfSSL_free(ssl);
        close(listenfd);
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}