CFLAGS = -Wall -g
CC = gcc

all: clean serverBuild clientBuild

.PHONY: client server

server: cleanServer serverBuild

client: cleanClient clientBuild

serverBuild:
	${CC} echoServer.c ${CFLAGS} -o server

clientBuild:
	${CC} echoClient.c ${CFLAGS} -o client

cleanServer:
	rm -f server

cleanClient:
	rm -f client

clean:
	rm -f client server