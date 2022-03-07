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

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 5500
#define BUFF_SIZE 1024

int main() {
    int client_sock, connectFailed;
    char buff[BUFF_SIZE + 1];
    struct sockaddr_in server_addr;
    int msg_len, bytes_sent, bytes_received;

    client_sock = socket(AF_INET, SOCK_STREAM, 0);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(SERVER_ADDR);
    server_addr.sin_port = htons(SERVER_PORT);

    connectFailed = connect(client_sock, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (connectFailed) {
        // printf("Error! Cannot connect to the server! Client exit imediately!");
        perror("Error");
        return 0;
    }

    while(1) {
        printf("\nInsert string to send: ");
    
        memset(buff, '\0', (strlen(buff) + 1));
        fgets(buff, BUFF_SIZE, stdin);
        msg_len = strlen(buff);

        bytes_sent = send(client_sock, buff, msg_len, 0);
        if (bytes_sent < 0) {
            perror("Send error: ");
        }

        if (strcmp(buff, "exit\n") == 0) break;
        
        bytes_received = recv(client_sock, buff, BUFF_SIZE, 0);
        if (bytes_received < 0) {
            perror("Receive error: ");
        } else if (bytes_received == 0) {
            printf("Connection closed.\n");
            break;
        }
        buff[bytes_received] = '\0';
        printf("Echo message from the server: %s", buff);
    }

    close(client_sock);
    return 0;
}