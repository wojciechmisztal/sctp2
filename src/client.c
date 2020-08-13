#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include "sctp2.h"

#define CLIENT_BUF 256

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
    FILE *fp;
    void* buf;
    buf = malloc(CLIENT_BUF * sizeof(void));
    int saddrs_len = argc - 2;
    saddrs = malloc((argc - 2) * sizeof(struct sockaddr*));
    char* filename = argv[argc - 1];

    fp = fopen(filename,"rb");
    if(fp == NULL){
        perror("Error opening file .. \n");
        exit(0);
    }

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
    sctp2_connect(sfd, (struct sockaddr**) saddrs);
    int fread_result = 0;
    do {
        fread_result = fread(buf, sizeof(void), CLIENT_BUF, fp);
        sctp2_send(sfd, buf, fread_result);
    } while(fread_result != 0);
    //int result = sctp2_recv(sfd, &buf, 10);
    //printf("Received result: ");
    //printf("%s", buf + 20);
    //printf(", size: %d\n", result);
    sctp2_close(sfd);
    fclose(fp);
    return EXIT_SUCCESS;
}
