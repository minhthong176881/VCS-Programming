#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <ctype.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <pthread.h>

void *connectionHandler(void *);

int main() {
    char server_msg[100] = "Hello from Server\n";
    int server_socket;
    
    server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket == -1) {
        perror("Socket error: ");
        exit(EXIT_FAILURE);
    }
    else printf("Socket created succesffully!\n");

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(9999);

    if (bind(server_socket, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
        printf("Bind failed!\n");
        exit(1);
    }
    else printf("Socket binded successfully!\n");

    if ((listen(server_socket, 100)) != 0) {
        printf("Listen failed!\n");
        exit(0);
    }
    else printf("Server is listening...\n");

    int no_threads = 0;
    pthread_t threads[100];
    while (no_threads < 100) {
        printf("Listening...\n");
        int client_socket = accept(server_socket, NULL, NULL);
        puts("Connection accepted.\n");
        if (pthread_create(&threads[no_threads], NULL, connectionHandler, &client_socket) < 0) {
            perror("Could not create thread!");
            return 1;
        }

        if (client_socket < 0) {
            printf("Server accept failed.\n");
            exit(0);
        }
        else printf("Server accept the client...\n");

        puts("Handler assigned!\n");

        no_threads++;
    }

    int k = 0;
    for (k = 0; k < 100; k++) {
        pthread_join(threads[k], NULL);
    }

    close(server_socket);

    return 0;
}

void *connectionHandler(void *client_socket) {
    int socket = *(int*) client_socket;
    int read_len;
    char server_msg[100] = "Hello from the server.\n";
    int send_status;
    send_status = send(socket, server_msg, sizeof(server_msg), 0);

    char client_msg[100];

    while ((read_len = recv(socket, client_msg, 100, 0)) > 0) {
        // end of string marker
        client_msg[read_len] = '\0';
        if (strcmp(client_msg, "exit") == 0) break;
        send_status = send(socket, client_msg, strlen(client_msg), 0);
    }

    return 0;
}