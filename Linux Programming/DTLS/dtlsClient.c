#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAXLINE 4096
#define SERV_ADDR "127.0.0.1"
#define SERV_PORT 11111

SSL_CTX* initCTX(void) {
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms(); // load cryptos
    SSL_load_error_strings(); // bring in and register error messages
    method = TLSv1_2_client_method(); // create new client-method instance
    ctx = SSL_CTX_new(method); //create new context

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    return ctx;
}

void showCerts(SSL* ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_certificate(ssl); // get the server's certificate
    if (cert != NULL) {
        printf("Server certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
    } else printf("Info: No client certificates configured.\n");
}

int main(int argc, char **argv) {
    int n = 0;
    int sockfd = 0;
    struct sockaddr_in servaddr;
    char sendline[MAXLINE], recvline[MAXLINE-1];
    SSL *ssl;
    SSL_CTX *ctx;
    int ret;
    int err;

    SSL_library_init();

    ctx = initCTX();
    ssl = SSL_new(ctx);
    printf("checkpoint 1\n");
    if (ssl == NULL) {
        printf("Unable to get ssl object.\n");
        return 1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(SERV_ADDR);
    servaddr.sin_port = htons(SERV_PORT);

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("Cannot create a socket.\n");
        return 1;
    }

    printf("checkpoint 2\n");

    SSL_set_fd(ssl, sockfd);

    ret = SSL_connect(ssl);
    if (ret < 0) {
        printf("checkpoint 3\n");
        err = SSL_get_error(ssl, ret);
        printf("err = %d, %s\n", err, ERR_error_string(err, NULL));
        return 1;
    }

    printf("Connected with %s encryption.\n", SSL_get_cipher(ssl));

    showCerts(ssl); // get any certs

    if(fgets(sendline, MAXLINE, stdin) != NULL) {
        if ((SSL_write(ssl, sendline, strlen(sendline))) != strlen(sendline)) {
            printf("SSL_write failed.\n");
        }

        n = SSL_read(ssl, recvline, sizeof(recvline) - 1);

        if (n < 0) {
            ERR_print_errors_fp(stderr);
        }

        recvline[n] = '\0';
        fputs(recvline, stdout);
    }

    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);

    return 0;
}