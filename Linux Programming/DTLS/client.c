#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define SERV_PORT 1255
#define BUFFER_SIZE (1<<16)

int main(int agrc, char **argv) {
    int sockfd, retval;
    struct sockaddr_in servaddr;
    int len;
    char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
    SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio;
	int reading = 0;
	struct timeval timeout;
    int messagenumber = 5;

    memset(&servaddr, 0, sizeof(servaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);
    servaddr.sin_addr.s_addr = inet_addr(argv[1]);

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    printf("Socket created.\n");

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLS_client_method());

    if (!SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	SSL_CTX_set_verify_depth (ctx, 2);
	SSL_CTX_set_read_ahead(ctx, 1);

	ssl = SSL_new(ctx);

    // create BIO, connect and set to already connected
    bio = BIO_new_dgram(sockfd, BIO_CLOSE);
    if (connect(sockfd, (struct sockaddr *) &servaddr, sizeof(struct sockaddr_in))) {
        perror("connect");
    }

    BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &servaddr);

    SSL_set_bio(ssl, bio, bio);

    retval = SSL_connect(ssl);

    if (retval <= 0) {
        printf("SSL_connect error!\n");
		exit(EXIT_FAILURE);
	}

    // set and activate timeouts 
	timeout.tv_sec = 3;
	timeout.tv_usec = 0;
	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);
	printf ("\nConnected to %s\n",
			inet_ntop(AF_INET, &servaddr.sin_addr, addrbuf, INET_ADDRSTRLEN));

    if (SSL_get_peer_certificate(ssl)) {
        printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
    }

    while (!(SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN)) {

		if (messagenumber > 0) {
			len = SSL_write(ssl, buf, 100);

            if (len < 0) {
                printf("SSL_write error.\n");
                break;
            }
            if (len == 0) {
                break;
            }
            printf("wrote %d bytes\n", (int) len);
			messagenumber--;

            if (messagenumber == 0)
			    SSL_shutdown(ssl);
		}

        reading = 1;
		while (reading) {
			len = SSL_read(ssl, buf, sizeof(buf));

            if (len < 0) {
                printf("SSL_read error.\n");
                break;
            }

            if (len == 0) {
                break;
            }

            printf("read %d bytes\n", (int) len);
			reading = 0;
		}
	}

	close(sockfd);
	printf("Connection closed.\n");

    return 0; 
}