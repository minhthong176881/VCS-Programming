#include <wolfssl/options.h>
#include <unistd.h>
#include <wolfssl/ssl.h>
#include <netdb.h>
#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXLINE   4096
#define SERV_PORT 11111

int main (int argc, char** argv)
{
    /* standard variables used in a dtls client*/
    int             n = 0;
    int             sockfd = 0;
    int             err1;
    int             readErr;
    struct          sockaddr_in servAddr;
    WOLFSSL*        ssl = 0;
    WOLFSSL_CTX*    ctx = 0;
    char            cert_array[]  = "./certs/rootCA.crt";
    char*           certs = cert_array;
    char            sendLine[MAXLINE];
    char            recvLine[MAXLINE - 1];

    /* Program argument checking */
    if (argc != 2) {
        printf("usage: udpcli <IP address>\n");
        return 1;
    }

    /* Initialize wolfSSL before assigning ctx */
    wolfSSL_Init();

    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new error.\n");
        return 1;
    }

    /* Load certificates into ctx variable */
    if (wolfSSL_CTX_load_verify_locations(ctx, certs, 0) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading %s, please check the file.\n", certs);
        return 1;
    }

    /* Assign ssl variable */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        printf("unable to get ssl object");
        return 1;
    }

    /* servAddr setup */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
    if (inet_pton(AF_INET, argv[1], &servAddr.sin_addr) < 1) {
        printf("Error and/or invalid IP address");
        return 1;
    }

    wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
       printf("cannot create a socket.");
       return 1;
    }

    /* Set the file descriptor for ssl and connect with ssl variable */
    wolfSSL_set_fd(ssl, sockfd);
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
	    err1 = wolfSSL_get_error(ssl, 0);
	    printf("err = %d, %s\n", err1, wolfSSL_ERR_reason_error_string(err1));
	    printf("SSL_connect failed");
        return 1;
    }

    printf("Connected to server.\n");

    for (;;) {
        printf("Insert message to the server: ");
        memset(sendLine, '\0', (strlen(sendLine) + 1));
        fgets(sendLine, MAXLINE, stdin);

        if (strcmp(sendLine, "quit\n") == 0) {
            break;
        }
        
        if ((wolfSSL_write(ssl, sendLine, strlen(sendLine))) != strlen(sendLine)) {
            printf("SSL_write failed");
        }

        /* n is the # of bytes received */
        n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1);

        if (n < 0) {
            readErr = wolfSSL_get_error(ssl, 0);
            if (readErr != SSL_ERROR_WANT_READ) {
                printf("wolfSSL_read failed");
            }
        }

        if (n == 0) printf("Connection closed!\n");

        /* Add a terminating character to the generic server message */
        recvLine[n] = '\0';
        printf("Server acknowledgment: %s\n", recvLine);
    }

    printf("--------------------------------------------\n");
    
    /* cleanup */
    printf("Closing connection...\n");
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    printf("Done.\n");

    return 0;
}