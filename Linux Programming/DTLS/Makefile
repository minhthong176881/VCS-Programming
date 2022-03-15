CFLAGS = -std=c99 -pedantic -Wall -g -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-overlength-strings
CC = gcc
INCLUDES    = -I/usr/local/include
LFLAGS      = -L/usr/local/lib
LIBS        = -lssl -lcrypto -pthread -lm -ldl

all: clean serverBuild clientBuild

.PHONY: client server

server: cleanServer serverBuild

client: cleanClient clientBuild

serverBuild:
	${CC} server.c ${CFLAGS} $(INCLUDES) -o server $(LFLAGS) $(LIBS)

clientBuild:
	${CC} client.c ${CFLAGS} $(INCLUDES) -o client $(LFLAGS) $(LIBS)

cleanServer:
	rm -f server

cleanClient:
	rm -f client

clean:
	rm -f client server