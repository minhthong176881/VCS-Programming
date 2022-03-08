#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <libgen.h>
#include <pthread.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 5500
#define BUFF_SIZE 1024

void *connectionHandler();

int main() {
    int no_threads = 0;
    pthread_t threads[120];

    while (no_threads < 120)
    {
        if (pthread_create(&threads[no_threads], NULL, connectionHandler, NULL) < 0) {
            perror("Error");
            return 0;
        }

        no_threads++;
    }

    int k = 0;
    for (k = 0; k < 120; k++) {
        pthread_join(threads[k], NULL);
    }

    // close(client_sock);
    return 0;
}

void *connectionHandler() {
    int client_sock;
    struct sockaddr_in server_addr;

    client_sock = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    server_addr.sin_port = htons(SERVER_PORT);
    
    if (connect(client_sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Error");
        return 0;
    }

    printf("Connected to the server with socket %d!\n", client_sock);

    sleep(5);

    char buff[BUFF_SIZE + 1];
    int msg_len, bytes_sent, bytes_received;

    memset(buff, '\0', (strlen(buff) + 1));
    sprintf(buff, "%d", client_sock);
    msg_len = strlen(buff);

    bytes_sent = send(client_sock, buff, msg_len, 0);
    if (bytes_sent < 0) {
        perror("Send error");
    }
    
    bytes_received = recv(client_sock, buff, BUFF_SIZE, 0);
    if (bytes_received < 0) {
        perror("Receive error");
    } else if (bytes_received == 0) {
        printf("Connection closed.\n");
        return 0;
    }
    buff[bytes_received] = '\0';
    printf("Acknowledge from the server: %s\n", buff);

    sleep(5);
    printf("Close connection: %d\n", client_sock);
    close(client_sock);
    return 0;
}