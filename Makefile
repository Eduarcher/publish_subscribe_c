all:
	gcc -Wall -c common.c
	gcc -Wall client.cpp common.o -lpthread -o cliente
	gcc -Wall server.cpp common.o -lpthread -o servidor

clean:
	rm common.o cliente servidor servidor
