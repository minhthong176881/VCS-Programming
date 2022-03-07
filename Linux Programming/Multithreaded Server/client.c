#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main() {
    int network_socket;
    network_socket = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(9999);

    int connection_status = connect(network_socket, (struct sockaddr *) &server_addr, sizeof(server_addr));
    if (connection_status == -1) {
        printf("The connection has error!\n");
    }
    if (connection_status == 0) {
        char response[256];
        while(1) {
            recv(network_socket, &response, 256, 0);
            printf("Enter a message to echo: ");
            scanf("%s", &response);
            int send_status = send(network_socket, response, strlen(response), 0);
            if (strcmp(response, "exit") == 0) break;
            printf("Echo message from the server: %s\n", response);
        }
    }

    close(network_socket);

    return 0;
}