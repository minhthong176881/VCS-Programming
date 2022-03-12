CFLAGS = -Wall -g
CC = gcc
LIB = -I/usr/local/include -L/usr/local/lib -lwolfssl

all: clean serverBuild clientBuild

.PHONY: client server

server: cleanServer serverBuild

client: cleanClient clientBuild

serverBuild:
	${CC} ${CFLAGS} -o server server.c ${LIB}

clientBuild:
	${CC} ${CFLAGS} -o client client.c ${LIB}

cleanServer:
	rm -f server

cleanClient:
	rm -f client

clean:
	rm -f client server