#include "common.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
void usage(int argc, char **argv) {
	printf("usage: %s <server IP> <server port>\n", argv[0]);
	printf("example: %s 127.0.0.1 51511\n", argv[0]);
	exit(EXIT_FAILURE);
}

#define BUFSZ 1024

void * client_receive_subthread(int s_sock){
    char buf[BUFSZ];
    while(1){
        memset(buf, 0, BUFSZ);
        recv(s_sock, buf, BUFSZ, 0);
        printf("%s", buf);
    }
}

int main(int argc, char **argv) {
	if (argc < 3) {
		usage(argc, argv);
	}

	struct sockaddr_storage storage;
	if (0 != addrparse(argv[1], argv[2], &storage)) {
		usage(argc, argv);
	}

	int s;
	s = socket(storage.ss_family, SOCK_STREAM, 0);
	if (s == -1) {
		logexit("socket");
	}
	struct sockaddr *addr = (struct sockaddr *)(&storage);
	if (0 != connect(s, addr, sizeof(storage))) {
		logexit("connect");
	}

	char addrstr[BUFSZ];
	addrtostr(addr, addrstr, BUFSZ);

	printf("connected to %s\n", addrstr);

    pthread_t tid;
    pthread_create(&tid, NULL, client_receive_subthread, s);

	char buf[BUFSZ];
	memset(buf, 0, BUFSZ);
	while(1) {
        printf("mensagem> ");
        fgets(buf, BUFSZ - 1, stdin);
        size_t count = send(s, buf, strlen(buf) + 1, 0);
        if (count != strlen(buf) + 1) {
            logexit("send");
        }
    }
	close(s);
	exit(EXIT_SUCCESS);
}

#pragma clang diagnostic pop