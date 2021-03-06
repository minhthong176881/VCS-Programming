#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define SERV_PORT 5500
#define BUFFER_SIZE          (1<<16)
#define COOKIE_SECRET_LENGTH 16

unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
int cookie_initialized = 0;

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	struct sockaddr_in peer;

    // initialize a random secret
    if (!cookie_initialized) {
        if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH)) {
            printf("Error setting random cookie secret.\n");
            return 0;
        }
        cookie_initialized = 1;
    }

    // read peer information
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    // create buffer with peer's address and port
    length = 0;
    length += sizeof(struct in_addr);
    length += sizeof(in_port_t);
    buffer = (unsigned char*) OPENSSL_malloc(length);

    if (buffer == NULL) {
        printf("out of memory.\n");
        return 0;
    }

    memcpy(buffer, &peer.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.sin_port), &peer.sin_addr, sizeof(struct in_addr));

    // calculate HMAC of buffer using the secret
    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
        (const unsigned char*) buffer, length, result, &resultlength);
    
    OPENSSL_free(buffer);

    memcpy(cookie, result, resultlength);
    *cookie_len = resultlength;

    return 1;
}

int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char *buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength;
	struct sockaddr_in peer;

    if (!cookie_initialized) return 0;

    // read peer information
    (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

    // create buffer with peer's address and port
    length = 0;
    length += sizeof(struct in_addr);
    length += sizeof(in_port_t);
    
    buffer = (unsigned char*) OPENSSL_malloc(length);
    if (buffer == NULL) {
        printf("out of memory\n");
        return 0;
    }

    memcpy(buffer, &peer.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t), &peer.sin_addr, sizeof(struct in_addr));

    // calculate HMAC of buffer using the secret
    HMAC(EVP_sha1(), (const void*) cookie_secret, COOKIE_SECRET_LENGTH,
        (const unsigned char*) buffer, length, result, &resultlength);
    
    OPENSSL_free(buffer);

    if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0) {
        return 1;
    }

    return 0;
}

struct pass_info {
	struct sockaddr_in server_addr, client_addr;
	SSL *ssl;
};

int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	return 1;
}

void connection_handle(void *info) {
    ssize_t len;
	char buf[BUFFER_SIZE];
	char addrbuf[INET6_ADDRSTRLEN];
	struct pass_info *pinfo = (struct pass_info*) info;
	SSL *ssl = pinfo->ssl;
	int fd, reading = 0, ret;
	const int on = 1;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;

    OPENSSL_assert(pinfo->client_addr.sin_family == pinfo->server_addr.sin_family);
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("Create socket error.\n");
        close(fd);
        free(info);
        SSL_free(ssl);
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t) sizeof(on));

    if (bind(fd, (struct sockaddr *) &pinfo->server_addr, sizeof(struct sockaddr_in))) {
        perror("Bind failed!");
        close(fd);
        free(info);
        SSL_free(ssl);
    }
    if (connect(fd, (struct sockaddr *) &pinfo->client_addr, sizeof(struct sockaddr_in))) {
        perror("Connect failed!");
        close(fd);
        free(info);
        SSL_free(ssl);
    }

    // set new fd and set BIO to connected
    BIO_set_fd(SSL_get_rbio(ssl), fd, BIO_NOCLOSE);
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pinfo->client_addr);

    // finish handshake
    do {
        ret = SSL_accept(ssl);
    } while (ret == 0);
    if (ret < 0) {
        perror("SSL_accept");
        printf("%s\n", ERR_error_string(ERR_get_error(), buf));
        close(fd);
        free(info);
        SSL_free(ssl);
    }

    // set and active timeouts
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

    printf("Accept connection from %s:%d\n", 
            inet_ntop(AF_INET, &pinfo->client_addr.sin_addr, addrbuf, INET_ADDRSTRLEN),
            ntohs(pinfo->client_addr.sin_port));
    
    if (SSL_get_peer_certificate(ssl)) {
        printf ("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
							  1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf ("\n------------------------------------------------------------\n\n");
    }

    while (!(SSL_get_shutdown(ssl) && SSL_RECEIVED_SHUTDOWN) && num_timeouts < max_timeouts) {
        reading = 1;
        while (reading) {
            len = SSL_read(ssl, buf, sizeof(buf));

            switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					printf("read %d bytes\n", (int) len);
					reading = 0;
					break;
				case SSL_ERROR_WANT_READ:
					// handle socket timeouts
					if (BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_GET_RECV_TIMER_EXP, 0, NULL)) {
						num_timeouts++;
						reading = 0;
					}
					// try again 
					break;
				case SSL_ERROR_ZERO_RETURN:
					reading = 0;
					break;
				case SSL_ERROR_SSL:
					printf("SSL read error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
                    close(fd);
                    free(info);
                    SSL_free(ssl);
					break;
				default:
					printf("Unexpected error while reading!\n");
                    close(fd);
                    free(info);
                    SSL_free(ssl);
					break;
			}
        }

        if (len > 0) {
            len = SSL_write(ssl, buf, len);
            switch (SSL_get_error(ssl, len)) {
				case SSL_ERROR_NONE:
					printf("wrote %d bytes\n", (int) len);
					break;
				case SSL_ERROR_WANT_WRITE:
					// can't write because of a renegotiation, retry sending this message...
					break;
				case SSL_ERROR_WANT_READ:
					// continue with reading
					break;
				case SSL_ERROR_SSL:
					printf("SSL write error: ");
					printf("%s (%d)\n", ERR_error_string(ERR_get_error(), buf), SSL_get_error(ssl, len));
                    close(fd);
                    free(info);
                    SSL_free(ssl);
					break;
				default:
					printf("Unexpected error while writing!\n");
                    close(fd);
                    free(info);
					break;
			}
        }
    }

    SSL_shutdown(ssl);
}

int main() {
    int sockfd, res;
    struct sockaddr_in servaddr, cliaddr;
    socklen_t len = sizeof(int);
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    struct timeval timeout;
    struct pass_info *info;
    const int on = 1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servaddr, 0, sizeof(struct sockaddr_storage));
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);

    res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &on, len);
    if (res < 0) {
        printf("Setsockopt SO_REUSEADDR failed.\n");
        return 0;
    }

    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLS_server_method());

    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

    if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");
    
    // Client has to authenticate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);

    if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) >= 0) {
        printf("Server is running at port %d\n", SERV_PORT);
    } else {
        perror("Bind failed!");
        return 0;
    }

    while (1) {
        memset(&cliaddr, 0, sizeof(cliaddr));
        len = sizeof(cliaddr);
        
        // create BIO
        bio = BIO_new_dgram(sockfd, BIO_NOCLOSE);

        // Set and activate timeouts 
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

        ssl = SSL_new(ctx);

        SSL_set_bio(ssl, bio, bio);

        // enable cookie exchange
        SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);

        // listen until new DTLS connections coming
        while (DTLSv1_listen(ssl, (BIO_ADDR *) &cliaddr) <= 0);

        info = (struct pass_info*) malloc (sizeof(struct pass_info));
        memcpy(&info->server_addr, &servaddr, sizeof(struct sockaddr_storage));
        memcpy(&info->client_addr, &cliaddr, sizeof(struct sockaddr_storage));
        info->ssl = ssl;

        connection_handle(info);
    }

    return 0;
}