CFLAGS = -Wall -g -LLIBDIR -pthread
CC = gcc
LIB = -I/usr/local/include -L/usr/local/lib -lwolfssl

all: clean serverBuild clientBuild serverThreadedBuild

.PHONY: client server

server: cleanServer serverBuild serverThreadedBuild

client: cleanClient clientBuild

serverBuild:
	${CC} ${CFLAGS} -o server server.c ${LIB}

clientBuild:
	${CC} ${CFLAGS} -o client client.c ${LIB}

serverThreadedBuild:
	${CC} ${CFLAGS} -o server-threaded server-threaded.c ${LIB}

cleanServer:
	rm -f server

cleanClient:
	rm -f client

clean:
	rm -f client server serverThreadedBuild