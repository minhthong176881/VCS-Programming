# DTLS Server

## wolfSSL

- The wolfSSL embedded TLS library is a lightweight, portable, C-language-based SSL/TLS library that supports DTLS protocol.
- Installation:
  - `sudo apt-get install autoconf libtool make execstack`
  - `git clone https://github.com/wolfSSL/wolfssl.git`
  - `cd wolfssl`
  - `./autogen.sh`
  - `./configure --enable-dtls`
  - `make`
  - `sudo make install`
  - `export LD_LIBRARY_PATH=/usr/local/lib`

## Server

- The DTLS server will execute the following actions:
  - Initialize wolfSSL:

    ```C
    /* Initialize wolfSSL */
    wolfSSL_Init();

    /* Set ctx to DTLS 1.2 */
    if ((ctx = wolfSSL_CTX_new(wolfDTLSv1_2_server_method())) == NULL) {
        printf("wolfSSL_CTX_new error.\n");
        return 1;
    }
    ```

  - Load CA certificate, server certificate and server secret key into SSL context:
  
    ```C
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
    ```

    - All the certificates and keys will be used to encrypt data sent between server and client. This encryption will be of type DTLS version 1.2: `wolfDTLSv1_2_server_method()`.
    - Setup server socket:

    ```C
     /* Create a UDP/IP socket */
    if ((listenfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        printf("Cannot create socket.\n");
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
        break;
    }

    /* Bind Socket */
    if (bind(listenfd, (struct sockaddr*)&servAddr, sizeof(servAddr)) < 0) {
        printf("Bind failed.\n");
        break;
    }

    printf("Awaiting client connection on port %d\n", SERV_PORT);
    ```

  - Await datagram arrival:

    ```C
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
    printf("Connected!\n");
    ```

    - *connfd* is used to peek at any incoming messages, check if there is a message waiting to be read or not.
  - Using wolfSSL to open a session with client:

    ```C
    wolfSSL_set_fd(ssl, listenfd);

    if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
        int e = wolfSSL_get_error(ssl, 0);

        printf("error = %d, %s\n", e, wolfSSL_ERR_reason_error_string(e));
        printf("SSL_accept failed.\n");
        break;
    }
    ```

    - Check if the client is using an acceptable cipher suite by making a call to `wolfSSL_accept`.
  - Read the message and acknowledge the message:

    ```C
    if ((recvLen = wolfSSL_read(ssl, buff, sizeof(buff)-1)) > 0) {
        printf("Received %d bytes from %s:%hu\n", recvLen, inet_ntoa(cliaddr.sin_addr), ntohs(cliaddr.sin_port));

        buff[recvLen] = '\0';
    }
    else if (recvLen < 0) {
        int readErr = wolfSSL_get_error(ssl, 0);
        if(readErr != SSL_ERROR_WANT_READ) {
            printf("SSL_read failed.\n");
            break;
        }
    }

    if (wolfSSL_write(ssl, buff, recvLen) < 0) {
        printf("wolfSSL_write fail.\n");
        break;
    }
    else {
        printf("Sending reply.\n");
    }

    printf("Reply sent \"%s\"\n", buff);
    ```

  - Free the memory:

    ```C
    wolfSSL_set_fd(ssl, 0);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    cleanup = 0;
    ```

## Client

- The DTLS client will execute the following actions:
  - Initialize wolfSSL:

    ```C
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
    ```

    - In order for a client to talk to DTLS encrypted server, the client will have to have certificates to verify the encryption, accept the key, and perform a DTLS handshake. This can be archieved by using `wolfDTLSv1_2_client_method`.
  - Load certificates and assign ssl variable:

    ```C
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
    ```

  - Set peer to the server: `wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));`.
  - Connect to the server:

    ```C
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        err1 = wolfSSL_get_error(ssl, 0);
        printf("err = %d, %s\n", err1, wolfSSL_ERR_reason_error_string(err1));
        printf("SSL_connect failed");
        return 1;
    }
    ```

  - Read and write to the server:

    ```C
    printf("Insert message to the server: ");
    memset(sendLine, '\0', (strlen(sendLine) + 1));
    // fgets(sendLine, MAXLINE, stdin);
    scanf("%s", sendLine);
    
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
    ```

- Cleanup: shutdown wolfSSL, free memory and close socket.
  
    ```C
    /* cleanup */
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    ```

## How to run?

- Compile files using *make*: `make all`
- Run server: `./server`
- Run client: `./client 127.0.0.1`
- Start to insert the message to send to the server.