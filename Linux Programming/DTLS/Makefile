CFLAGS = -Wall -g
CC = gcc
LIB = -L/usr/lib -lssl -lcrypto

all: clean serverBuild clientBuild

.PHONY: client server

server: cleanServer serverBuild

client: cleanClient clientBuild

serverBuild:
	${CC} ${CFLAGS} -o server dtlsServer.c ${LIB}

clientBuild:
	${CC} ${CFLAGS} -o client dtlsClient.c ${LIB}

cleanServer:
	rm -f server

cleanClient:
	rm -f client

clean:
	rm -f client server