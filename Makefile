all:
	gcc -Wall -c common.c
	gcc -Wall client.cpp common.o -lpthread -o client
	gcc -Wall server.cpp common.o -lpthread -o server

clean:
	rm common.o client server server
