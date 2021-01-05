#include "common.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>

#include <sys/socket.h>
#include <sys/types.h>

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
#define BUFSZ 1024

void usage(int argc, char **argv) {
    printf("usage: %s <v4|v6> <server port>\n", argv[0]);
    printf("example: %s v4 51511\n", argv[0]);
    exit(EXIT_FAILURE);
}

void logexit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int addrparse(const char *addrstr, const char *portstr,
              struct sockaddr_storage *storage) {
    if (addrstr == NULL || portstr == NULL) {
        return -1;
    }

    uint16_t port = (uint16_t)atoi(portstr); // unsigned short
    if (port == 0) {
        return -1;
    }
    port = htons(port); // host to network short

    struct in_addr inaddr4; // 32-bit IP address
    if (inet_pton(AF_INET, addrstr, &inaddr4)) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)storage;
        addr4->sin_family = AF_INET;
        addr4->sin_port = port;
        addr4->sin_addr = inaddr4;
        return 0;
    }

    struct in6_addr inaddr6; // 128-bit IPv6 address
    if (inet_pton(AF_INET6, addrstr, &inaddr6)) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = port;
        // addr6->sin6_addr = inaddr6
        memcpy(&(addr6->sin6_addr), &inaddr6, sizeof(inaddr6));
        return 0;
    }

    return -1;
}

void addrtostr(const struct sockaddr *addr, char *str, size_t strsize) {
    int version;
    char addrstr[INET6_ADDRSTRLEN + 1] = "";
    uint16_t port;

    if (addr->sa_family == AF_INET) {
        version = 4;
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        if (!inet_ntop(AF_INET, &(addr4->sin_addr), addrstr,
                       INET6_ADDRSTRLEN + 1)) {
            logexit("ntop");
        }
        port = ntohs(addr4->sin_port); // network to host short
    } else if (addr->sa_family == AF_INET6) {
        version = 6;
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        if (!inet_ntop(AF_INET6, &(addr6->sin6_addr), addrstr,
                       INET6_ADDRSTRLEN + 1)) {
            logexit("ntop");
        }
        port = ntohs(addr6->sin6_port); // network to host short
    } else {
        logexit("unknown protocol family.");
    }
    if (str) {
        snprintf(str, strsize, "IPv%d %s %hu", version, addrstr, port);
    }
}

int server_sockaddr_init(const char *proto, const char *portstr,
                         struct sockaddr_storage *storage) {
    uint16_t port = (uint16_t)atoi(portstr); // unsigned short
    if (port == 0) {
        return -1;
    }
    port = htons(port); // host to network short

    memset(storage, 0, sizeof(*storage));
    if (0 == strcmp(proto, "v4")) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)storage;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = INADDR_ANY;
        addr4->sin_port = port;
        return 0;
    } else if (0 == strcmp(proto, "v6")) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = in6addr_any;
        addr6->sin6_port = port;
        return 0;
    } else {
        return -1;
    }
}

struct client_data {
    int csock;
    struct sockaddr_storage storage;
    char tags[10][30];
    int last_tag;
};

void * client_thread(void *data) {
    struct client_data *cdata = (struct client_data *)data;
    struct sockaddr *caddr = (struct sockaddr *)(&cdata->storage);

    char caddrstr[BUFSZ];
    addrtostr(caddr, caddrstr, BUFSZ);
    printf("[log] connection from %s\n", caddrstr);

    while (true) {
        char buf[BUFSZ];
        memset(buf, 0, BUFSZ);
        size_t count = recv(cdata->csock, buf, BUFSZ - 1, 0);

        // Interpretar a mensagem aqui, buf
        printf("INTERPRETANDO: %s", buf);
        char delim[] = " "; // Delimitador da mensagem
        char *ptr = strtok(buf, delim);
        while (ptr != NULL) {
            printf("Word: '%s'\n", ptr);

            // Check if the word starts with '+'
            if (ptr[0] == 43) {
                //Add word without '+' and last character
                char *newString = ptr + 1; // remove '+' from the start
                if (newString[strlen(newString) - 1] == '\n') {  // Remove newline '\n' if exists
                    newString[strlen(newString) - 1] = '\0';
                }
                strcpy(cdata->tags[cdata->last_tag], newString); //Put subscribed word in a vector of this user
                printf("Subscribed %s\n", cdata->tags[cdata->last_tag]);
                cdata->last_tag += 1;
            }

                // Check if the word starts with '-'
            else if (ptr[0] == 45) {
                // Find word if exists
                char *newString = ptr + 1; // remove '-' from the start
                if (newString[strlen(newString) - 1] == '\n') { // Remove newline '\n' if exists
                    newString[strlen(newString) - 1] = '\0';
                }

                // Verify if already subscribed
                int i;
                for (i = 0; i <= cdata->last_tag; ++i) {
                    if (strcmp(newString, cdata->tags[i]) == 0) {
                        // if exist, unsubscribe
                        printf("Unsubscribed %s\n", cdata->tags[i]);

                        // verify if we need to 'move' subscriptions on the array to not have any empty
                        if (i < cdata->last_tag) {
                            int j;
                            for (j = i; j < cdata->last_tag; ++j) {
                                strcpy(cdata->tags[j], cdata->tags[j + 1]);
                            }
                        }
                        cdata->last_tag -= 1;
                        break;
                    }
                }
            }
            ptr = strtok(NULL, delim);
        }
        printf("[msg] %s, %d bytes: %s\n", caddrstr, (int)count, buf);
        char buf2[BUFSZ];
        sprintf(buf2, "Test Message!\n");
        count = send(cdata->csock, buf2, strlen(buf2) + 1, 0);
        if (count != strlen(buf2) + 1) {
            logexit("send fail");
        }
        printf("Send?");
    }
    //close(cdata->csock);
    //pthread_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argc, argv);
    }

    struct sockaddr_storage storage;
    if (0 != server_sockaddr_init(argv[1], argv[2], &storage)) {
        usage(argc, argv);
    }

    int s;
    s = socket(storage.ss_family, SOCK_STREAM, 0);
    if (s == -1) {
        logexit("socket");
    }

    int enable = 1;
    if (0 != setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int))) {
        logexit("setsockopt");
    }

    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if (0 != bind(s, addr, sizeof(storage))) {
        logexit("bind");
    }

    if (0 != listen(s, 10)) {
        logexit("listen");
    }

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("bound to %s, waiting connections\n", addrstr);

    while (1) {
        struct sockaddr_storage cstorage;
        struct sockaddr *caddr = (struct sockaddr *)(&cstorage);
        socklen_t caddrlen = sizeof(cstorage);

        int csock = accept(s, caddr, &caddrlen);
        if (csock == -1) {
            logexit("accept");
        }

        struct client_data *cdata = (client_data*)malloc(sizeof(*cdata));
        if (!cdata) {
            logexit("malloc");
        }
        cdata->csock = csock;
        memcpy(&(cdata->storage), &cstorage, sizeof(cstorage));
        cdata->last_tag = 0;

        pthread_t tid;
        pthread_create(&tid, NULL, client_thread, cdata);
    }
    printf("exiting server");
    exit(EXIT_SUCCESS);
}

#pragma clang diagnostic pop