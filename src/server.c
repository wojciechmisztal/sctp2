#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include "sctp2.h"

void cleanup() {
    printf("\n--- cleanup ---\n");
}

void stop(int signo) {
    exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);

    int sfd;
    char* buf;
    buf = malloc(1024 * sizeof(char));
    struct sockaddr** saddrs;
    int saddrs_len = argc - 1;
    saddrs = malloc(saddrs_len * sizeof(struct sockaddr*));

    atexit(cleanup);
    signal(SIGINT, stop);
    sfd = sctp2_socket(saddrs_len);
    for(int i = 0; i < saddrs_len; i++) {
        saddrs[i] = malloc(sizeof(struct sockaddr_in));
        memset(saddrs[i], 0, sizeof(struct sockaddr_in));
        struct sockaddr_in* saddr_in = (struct sockaddr_in*)saddrs[i];

        char* ip_addr = strtok(argv[i + 1], ":");
        char* port = strtok(NULL, ":");
        saddr_in->sin_family = AF_INET;
        saddr_in->sin_port = htons(atoi(port));
        saddr_in->sin_addr.s_addr = inet_addr(ip_addr);
    }
    sctp2_bind(sfd, saddrs);

    while(1) {
        int rfd = sctp2_accept(sfd);
        int result = 0;
        do {
            result = sctp2_recv(rfd, buf, 6);
            printf("%.*s", result, buf);
        } while(result != 0);
        printf("\n");
        close(sfd);
    }
    return EXIT_SUCCESS;
}
