#include <stdio.h>                  /* standard in/out procedures */
#include <stdlib.h>                 /* defines system calls */
#include <string.h>                 /* necessary for memset */
#include <netdb.h>
#include <sys/socket.h>             /* used for all socket calls */
#include <netinet/in.h>             /* used for sockaddr_in */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"

#define SERV_PORT 11111
#define MSGLEN 4096

static int cleanup = 0; // to handle shutdown
struct sockaddr_in servaddr, cliaddr;

void sig_handler(const int sig);

SSL_CTX* initServerCtx(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms(); // load & register all cryptos, etc.
    SSL_load_error_strings(); // load all error messages
    method = TLSv1_2_server_method();
    ctx = SSL_CTX_new(method);
    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void loadCertificates(SSL_CTX *ctx, char* certFile, char* keyFile) {
    // set the local certificate from certFile
    if (SSL_CTX_use_certificate_file(ctx, certFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // set the private key from keyFile
    if (SSL_CTX_use_PrivateKey_file(ctx, keyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate.\n");
        abort();
    }
}

void showCerts(SSL* ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); // get certificates
    if (cert != NULL) {
        printf("Server certificates: \n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else printf("No certificates.\n");
}

int main(int argc, char **argv) {
    // cert and key files
    char caCertLoc[] = "../certs/ca-cert.pem";
    char servCertLoc[] = "./mycert.pem";
    char servKeyLoc [] = "./mycert.pem";
    SSL_CTX *ctx;

    int on = 1;
    int res = 1;
    int connfd = 0;
    int recvLen = 0;
    int listenfd = 0;
    SSL *ssl;
    socklen_t clilen;
    socklen_t len = sizeof(int);
    unsigned char b[MSGLEN];
    char buff[MSGLEN];
    char ack[] = "I hear you fashizzle!\n";

    // initalize the SSL library
    SSL_library_init();
    ctx = initServerCtx(); // initialize SSL
    loadCertificates(ctx, servCertLoc, servKeyLoc); // load certs

    while (cleanup != 1) {
        // create a UDP/IP socket 
        if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
            printf("Cannot create socket.\n");
            break;
        }
        printf("Socket allocated\n");

        // clear servAddr each loop
        memset((char *)&servaddr, 0, sizeof(servaddr));

        servaddr.sin_family      = AF_INET;
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
        servaddr.sin_port        = htons(SERV_PORT);

        // eliminate socket already in use error 
        res = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
        if (res < 0) {
            printf("Setsockopt SO_REUSEADDR failed.\n");
            break;
        }

        // bind socket 
        if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
            printf("Bind failed.\n");
            break;
        }

        printf("Awaiting client connection on port %d\n", SERV_PORT);

        clilen = sizeof(cliaddr);
        connfd = (int)recvfrom(listenfd, (char *)&b, sizeof(b), MSG_PEEK, (struct sockaddr *) &cliaddr, &clilen);

        if (connfd < 0) {
            printf("No client in queue, enter idle state.\n");
            close(listenfd);
            continue;
        } else if (connfd > 0) {
            if (connect(listenfd, (const struct sockaddr *) &cliaddr, sizeof(cliaddr)) != 0) {
                printf("Udp connect failed.\n");
                break;
            }
        }
        else {
            printf("Recvfrom failed.\n");
            break;
        }
        printf("Connected.\n");

        // create SSL object
        if ((ssl = SSL_new(ctx)) == NULL) {
            printf("SSL_new error.\n");
            break;
        }

        SSL_set_fd(ssl, listenfd);

        if (SSL_accept(ssl) <= 0) {
            int e = SSL_get_error(ssl, 0);
            printf("error = %d\n", e);
            printf("SSL_accept failed.\n");
            break;
        }

        if ((recvLen = SSL_read(ssl, buff, sizeof(buff)-1)) > 0) {
            printf("heard %d bytes.\n", recvLen);

            buff[recvLen] = 0;
            printf("I heard this: \"%s\"\n", buff);
        } else if (recvLen < 0) {
            int readErr = SSL_get_error(ssl, 0);
            if(readErr != SSL_ERROR_WANT_READ) {
                printf("SSL_read failed.\n");
                break;
            }
        }

        if (SSL_write(ssl, ack, sizeof(ack)) < 0) {
            printf("SSL_write failed.\n");
            break;
        } else {
            printf("Sending reply.\n");
        }

        printf("Reply sent \"%s\"\n", ack);

        SSL_set_fd(ssl, 0);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(listenfd);
        cleanup = 0;

        printf("Client left cont to idle state.\n");
    }

    if (cleanup == 1) {
        SSL_set_fd(ssl, 0);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(listenfd);
    }

    SSL_CTX_free(ctx);

    return 0;
}