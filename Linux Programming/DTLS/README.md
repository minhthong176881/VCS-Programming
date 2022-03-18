# Implement DTLS

## OpenSSL

- OpenSSL is a software library for applications that secure communications over computer network against eavesdropping or need to identify the party at the other end.
- It is widely used by Internet servers, including the majority of HTTPS websites.
- Install: `sudo apt-get install libssl-dev`

## Server

- The server will execute the following actions:
  - Initiate SSL library and SSL context:

    ```C
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLS_server_method());
    ```

  - Load the certificate and key of the server:

    ```C
    if (!SSL_CTX_use_certificate_file(ctx, "certs/server-cert.pem", SSL_FILETYPE_PEM))
        printf("\nERROR: no certificate found!");

    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/server-key.pem", SSL_FILETYPE_PEM))
        printf("\nERROR: no private key found!");

    if (!SSL_CTX_check_private_key (ctx))
        printf("\nERROR: invalid private key!");
    ```

  - Set cookie generate and verify callback function for the SSL context.

    ```C
    SSL_CTX_set_cookie_generate_cb(ctx, generate_cookie);
    SSL_CTX_set_cookie_verify_cb(ctx, &verify_cookie);
    ```

    - Generate cookie:
      - Create a cookie secret if not initialized.
      - Copy client address and port into a buffer.
      - Calculate HMAC of the buffer using the cookie secret.
      - The calculated result is the cookie that server will send to client in the HelloVerifyRequest.
    - Verify cookie:
      - Copy client address and port into a buffer.
      - Calculate HMAC of the buffer using the cookie secret.
      - Compare calculated result with cookie value created above.
  - Setup server socket:

    ```C
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&servaddr, 0, sizeof(struct sockaddr_storage));
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(SERV_PORT);

    if (bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr)) >= 0) {
        printf("Server is running at port %d\n", SERV_PORT);
    } else {
        perror("Bind failed!");
        return 0;
    }
    ```

- Do SSL accept to finish the handshake phase:

    ```C
    do {
        ret = SSL_accept(ssl);
    } while (ret == 0);
    ```

- Read the message and acknowledge the message using `SSL_read()` and `SSL_write()`.
- Close socket, shutdown and free SSL.

## Client

- The client will execute the following actions:
  - Initiate SSL library and SSL context:

    ```C
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(DTLS_client_method());
    ```

  - Load certificate and key of the client:

    ```C
    if (!SSL_CTX_use_certificate_file(ctx, "certs/client-cert.pem" SSL_FILETYPE_PEM))
        printf("\nERROR: no certificate found!");
    if (!SSL_CTX_use_PrivateKey_file(ctx, "certs/client-key.pem", SSL_FILETYPE_PEM))
        printf("\nERROR: no private key found!");

    if (!SSL_CTX_check_private_key (ctx))
        printf("\nERROR: invalid private key!");
    ```

  - Initiate the handshake with the server:

    ```C
    retval = SSL_connect(ssl);
    ```

  - Send and receive message using `SSL_read()` and `SSL_write()`.
  - Close socket, free and shutdown SSL.

## How to run?

- Compile files using *make*: `make all`
- Run server: `./server`
- Run client: `./client 127.0.0.1`
- Start to insert the message to send to the server.
