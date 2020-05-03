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
    struct sockaddr** saddrs;
    int saddrs_len = argc - 1;
    saddrs = malloc((argc - 1) * sizeof(struct sockaddr*));

    atexit(cleanup);
    signal(SIGINT, stop);
    sfd = sctp2_socket(saddrs_len);
    for(int i = 0; i < saddrs_len; i++) {
        saddrs[i] = malloc(sizeof(struct sockaddr_in));
        memset(saddrs[i], 0, sizeof(struct sockaddr_in));
        struct sockaddr_in* saddr_in = (struct sockaddr_in*)saddrs[i];
        saddr_in->sin_family = AF_INET;
        saddr_in->sin_port = 0;
        saddr_in->sin_addr.s_addr = inet_addr(argv[i + 1]);
    }
    sctp2_connect(sfd, (struct sockaddr**) saddrs);
    while(1) {
        sctp2_send(sfd, "abcdefghijk", 12);
        //int result = sctp2_recv(sfd, &buf, 10);
        //printf("Received result: ");
        //printf("%s", buf + 20);
        //printf(", size: %d\n", result);
        sleep(100);
    }
    close(sfd);
    return EXIT_SUCCESS;
}
