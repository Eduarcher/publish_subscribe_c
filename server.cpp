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
#define BUFSZ 501

char published_message[BUFSZ] = "";
int kill_them_all = 0;

void usage(int argc, char **argv) {
    printf("usage: %s <server port>\n", argv[0]);
    printf("example: %s 51511\n", argv[0]);
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
    char tags[256][30];
    int last_tag;
};


void * client_publish_subthread(void *data){
    printf("Publication subthread online\n");
    struct client_data *cdata = (struct client_data *)data;
    char latest_message[BUFSZ];
    strcpy(latest_message, published_message);

    while(true){
        if(strcmp(latest_message, published_message) == 0){
            usleep(50000);
        }
        else{
            send(cdata->csock, published_message, strlen(published_message) + 1, 0);
            strcpy(latest_message, published_message);
        }
    }
}


void * client_thread(void *data) {
    struct client_data *cdata = (struct client_data *)data;
    struct sockaddr *caddr = (struct sockaddr *)(&cdata->storage);

    int kill_sig = 0;
    int send_return_message = 0;

    char caddrstr[BUFSZ];
    addrtostr(caddr, caddrstr, BUFSZ);
    printf("[log] connection from %s\n", caddrstr);

    while (kill_sig == 0 and kill_them_all == 0) {
        char buf[BUFSZ];
        char buf2[BUFSZ];
        memset(buf, 0, BUFSZ);
        size_t count = recv(cdata->csock, buf, BUFSZ - 1, 0);

        // Interpretar a mensagem aqui, buf
        printf("INTERPRETANDO: %s\n", buf);
        char full_message[BUFSZ];
        strcpy(full_message, buf);
        char delim[] = " "; // Delimitador da mensagem
        char *word = strtok(buf, delim);
        while (word != NULL) {
            // Check if the word starts with '+'
            if (word[0] == 43) {
                //Add word without '+' and last character
                char *cleanWord = word + 1; // remove '+' from the start
                if (cleanWord[strlen(cleanWord) - 1] == '\n') {  // Remove newline '\n' if exists
                    cleanWord[strlen(cleanWord) - 1] = '\0';
                }

                // Verify if already subscribed
                int i;
                int already_sub = 0;
                for (i = 0; i <= cdata->last_tag; ++i) {
                    if (strcmp(cleanWord, cdata->tags[i]) == 0) {
                        // if exist, do not subscribe
                        sprintf(buf2, "already subscribed +%s\n", cleanWord);
                        already_sub = 1;
                        send_return_message = 1;
                        break;
                    }
                }
                // if not sub already, sub right now
                if (already_sub == 0){
                    strcpy(cdata->tags[cdata->last_tag], cleanWord); //Put subscribed word in a vector of this user
                    sprintf(buf2, "subscribed +%s\n", cleanWord);
                    cdata->last_tag += 1;
                    send_return_message = 1;
                }
            }

            // Check if the word starts with '-'
            else if (word[0] == 45) {
                // Find word if exists
                char *cleanWord = word + 1; // remove '-' from the start
                if (cleanWord[strlen(cleanWord) - 1] == '\n') { // Remove newline '\n' if exists
                    cleanWord[strlen(cleanWord) - 1] = '\0';
                }

                // Verify if already subscribed
                int i;
                int not_sub = 0;
                for (i = 0; i <= cdata->last_tag; ++i) {
                    if (strcmp(cleanWord, cdata->tags[i]) == 0) {
                        // if exist, unsubscribe
                        sprintf(buf2, "unsubscribed -%s\n", cleanWord);

                        // verify if we need to 'move' subscriptions on the array to not have any empty space (the famous 'dança das cadeiras')
                        if (i < cdata->last_tag) {
                            int j;
                            for (j = i; j < cdata->last_tag; ++j) {
                                strcpy(cdata->tags[j], cdata->tags[j + 1]);
                            }
                        }
                        cdata->last_tag -= 1;
                        not_sub = 1;
                        send_return_message = 1;
                        break;
                    }
                }
                // If not sub, send 'not sub' message
                if (not_sub == 0){
                    sprintf(buf2, "not subscribed -%s\n", cleanWord);
                    send_return_message = 1;
                }
            }

            // Kill server?
            else if(strcmp(word, "##kill\n") == 0){
//                kill_sig = 1; // this only kill the user
                kill_them_all = 1;
                logexit("ending this shit right now");
            }

            // if not tag, then check for '#'
            else if (word[0] == 35) {
                strcpy(published_message, full_message);
            }

            word = strtok(NULL, delim);
        }
        //printf("[msg] %s, %d bytes: %s\n", caddrstr, (int)count, buf);

        // Send the return message (if user session not killed)
        if (kill_sig != 1 and send_return_message == 1){
            count = send(cdata->csock, buf2, strlen(buf2), 0);
            if (count != strlen(buf2)) {
                logexit("send fail");
            }
        }
        send_return_message = 0;
    }
    close(cdata->csock);
    pthread_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        usage(argc, argv);
    }

    struct sockaddr_storage storage;
    if (0 != server_sockaddr_init("v4", argv[1], &storage)) {
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
        pthread_t tid2;
        // Thread to update tags and server-client interaction
        pthread_create(&tid, NULL, client_thread, cdata);

        // Thread to watch for messages to publish
        pthread_create(&tid2, NULL, client_publish_subthread, cdata);
    }
    printf("exiting server");
    exit(EXIT_SUCCESS);
}

#pragma clang diagnostic pop