#include "sctp2.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

extern int errno;

int sctp2_socket_id = 1;
int** sctp2_sockets = NULL;
size_t sctp2_sockets_count = 0;
size_t sctp2_saddrs_len = 0;

struct sockaddr*** sctp2_addr = NULL;


int sctp2_socket(size_t saddrs_len) {
    sctp2_saddrs_len = saddrs_len;
    return __sctp2_create_and_add_socket();
}

void sctp2_bind(int sfd, struct sockaddr** saddrs) {

    __sctp2_add_sockaddrs(sfd, saddrs);

    for(int i = 0; i < sctp2_saddrs_len; i++) {
        bind(sctp2_sockets[sfd][i], sctp2_addr[sfd][i], sizeof(struct sockaddr));
    }
}

int sctp2_accept(int sfd) {
    int rfd;
    char buf[BUF_LEN];
    struct sockaddr** saddrs;
    saddrs = malloc(sctp2_saddrs_len * sizeof(struct sockaddr*));
    for(int i = 0; i < sctp2_saddrs_len; i++){
        saddrs[i] = malloc(sizeof(struct sockaddr));
        memset(saddrs[i], 0, sizeof(struct sockaddr));
    }
    // 3 way handshake
    int result = __sctp2_recv_new_connection(sfd, buf, BUF_LEN, saddrs);
    struct sctp2hdr* hdr = (struct sctp2hdr*) (buf + IPHDR_LEN);
    if(hdr->type == SCTP2_TYPE_SYN) {
        printf("Accept: SYN\n");
         rfd = __sctp2_create_and_add_socket();
        __sctp2_add_sockaddrs(rfd, saddrs);
        __sctp2_send_other(rfd, SCTP2_TYPE_SYN_ACK);
        __sctp2_connect_socket(rfd, saddrs);
        result = __sctp2_recv_other(rfd, buf, BUF_LEN);
        hdr = (struct sctp2hdr*) (buf + IPHDR_LEN);
        if(hdr->type == SCTP2_TYPE_ACK) {
            printf("Accept: ACK\n");
        }
    }
    for(int j = 0 + IPHDR_LEN; j < result; ++j)
        printf("%x", ((uint8_t*) buf)[j]);
    printf(", size: %d\n", result);
    return rfd;
}

void sctp2_send(int sfd, char* msg, size_t buf_len) {
    __sctp2_send_data(sfd, msg, buf_len);
}

int sctp2_connect(int sfd, struct sockaddr** saddrs) {
    char buf[BUF_LEN];
    __sctp2_add_sockaddrs(sfd, saddrs);
    __sctp2_connect_socket(sfd, saddrs);

    // 3 way handshake
    __sctp2_send_other(sfd, SCTP2_TYPE_SYN);
    int result = __sctp2_recv_other(sfd, buf, BUF_LEN);
    struct sctp2hdr* hdr = (struct sctp2hdr*) (buf + IPHDR_LEN);
    if(hdr->type == SCTP2_TYPE_SYN_ACK) {
        printf("Accept: SYNACK\n");
        __sctp2_send_other(sfd, SCTP2_TYPE_ACK);
    }
    return 0;
}

int sctp2_recv(int sfd, char* buf, size_t buf_len) {
    int result = __sctp2_recv_data(sfd, buf, buf_len);
    /*printf("Received result: ");
    for(int j = 0; j < result; ++j) //20 == length of an ip header
        printf("%c", ((uint8_t*) buf)[j]);
    printf(", size: %d\n", result);*/
    return result;
}

int sctp2_close(int sfd) {
    char buf[BUF_LEN];
    __sctp2_send_other(sfd, SCTP2_TYPE_FIN);
    int result = __sctp2_recv_other(sfd, buf, BUF_LEN);
    

}


int __sctp2_create_and_add_socket() {
    int sfd = sctp2_sockets_count;
    sctp2_sockets_count++;
    sctp2_sockets = realloc(sctp2_sockets, sctp2_sockets_count * sizeof(int*));
    if(sctp2_sockets == 0){
        perror("Sockaddr memory allocation error!");
        exit(0);
    }
    sctp2_sockets[sfd] = malloc(sctp2_saddrs_len * sizeof(int));
    if(sctp2_sockets[sfd] == 0){
        perror("Socket memory allocation error!");
        exit(0);
    }
    for(int i = 0; i < sctp2_saddrs_len; i++) {
        sctp2_sockets[sfd][i] = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP2);

        if(sctp2_sockets[sfd][i] < 0) {
            perror("Socket creation error!");
            exit(0);
        }
    }
    sctp2_addr = realloc(sctp2_addr, sctp2_sockets_count * sizeof(struct sockaddr*));
    sctp2_addr[sfd] = malloc(sctp2_saddrs_len * sizeof(struct sockaddr*));
    memset(sctp2_addr[sfd], 0, sctp2_saddrs_len * sizeof(char));
    return sfd;
}

void __sctp2_connect_socket(int sfd, struct sockaddr** saddrs) {
    for(int i = 0; i < sctp2_saddrs_len; i++) {
        connect(sctp2_sockets[sfd][i], saddrs[i], sizeof(struct sockaddr));
    }
}

void __sctp2_add_sockaddrs(int sfd, struct sockaddr** saddrs) {
    for(int i = 0; i < sctp2_saddrs_len; i++){
        sctp2_addr[sfd][i] = malloc(sizeof(struct sockaddr));
        memcpy(sctp2_addr[sfd][i], saddrs[i], sizeof(struct sockaddr));
    }
}

void __sctp2_send_data(int sfd, char* buf, size_t buf_len) {
    char buf_other[BUF_LEN];
    int msg_send_len = buf_len > DATA_MSG_LEN ? buf_len : DATA_MSG_LEN;
    int result;
    struct sctp2hdr* shdr;
    shdr = malloc(sizeof(struct sctp2hdr) + msg_send_len * sizeof(char));
    memset(shdr, 0, sizeof(struct sctp2hdr) + msg_send_len * sizeof(char));
    shdr->type = SCTP2_TYPE_DATA;
    for(int i = 0; i * DATA_MSG_LEN < buf_len; i++) {
        int cur_chan = i % sctp2_saddrs_len;
        strncpy(&shdr->msg, buf + i * DATA_MSG_LEN, DATA_MSG_LEN); 
        shdr->number = i;

        __sctp2_print("Send to", sctp2_sockets[sfd][cur_chan], sctp2_addr[sfd][cur_chan]);
        result = sendto(sctp2_sockets[sfd][cur_chan], shdr, sizeof(struct sctp2hdr) + DATA_MSG_LEN * sizeof(char), 0, sctp2_addr[sfd][cur_chan], sizeof(struct sockaddr));
        if(result < 0) {
            perror("Send error");
        }
    }
    free(shdr);
}

void __sctp2_send_other(int sfd, short type) {
    char buf[BUF_LEN];
    int result;
    struct sctp2hdr* shdr;

    shdr = malloc(sizeof(struct sctp2hdr));
    memset(shdr, 0, sizeof(struct sctp2hdr));
    shdr->type = type;
    for(int i = 0; i < sctp2_saddrs_len; i++) {
        __sctp2_print("Send to", sctp2_sockets[sfd][i], sctp2_addr[sfd][i]);
        result = sendto(sctp2_sockets[sfd][i], shdr, sizeof(struct sctp2hdr) + buf_len * sizeof(char), 0, sctp2_addr[sfd][i], sizeof(struct sockaddr));
        if(result < 0) {
            perror("Send error");
        }
    }
    free(shdr);
}

int __sctp2_recv_new_connection(int sfd, char* buf, size_t buf_len, struct sockaddr** saddrs) {
    int result = -1;
    for(int i = 0; i < sctp2_saddrs_len; i++) {
        socklen_t saddr_len = sizeof(struct sockaddr);
        result = recvfrom(sctp2_sockets[sfd][i], buf, BUF_LEN, 0, saddrs[i], &saddr_len);
        if(result < 0){
            perror("Recv error");
        }
        __sctp2_print("Recv from", sctp2_sockets[sfd][i], saddrs[i]);

    }
    return result;
}

int __sctp2_recv_data(int sfd, char* buf, size_t buf_len) {
    int msg_recv_len = DATA_MSG_LEN;
    int result;
    char* buf_recv = malloc((IPHDR_LEN + SCTP2HDR_LEN + msg_recv_len) * sizeof(char));

    for(int i = 0; i * DATA_MSG_LEN < buf_len; i++) {
        int cur_chan = i % sctp2_saddrs_len;

        __sctp2_print("Recv from", sctp2_sockets[sfd][cur_chan], sctp2_addr[sfd][cur_chan]);
        result = recv(sctp2_sockets[sfd][cur_chan], buf_recv, IPHDR_LEN + SCTP2HDR_LEN + msg_recv_len, 0);
        if(result < 0) {
            perror("Recv error");
        }

        struct sctp2hdr* shdr  = buf_recv + IPHDR_LEN;

        memcpy(buf + i * DATA_MSG_LEN, buf_recv + IPHDR_LEN + SCTP2HDR_LEN, msg_recv_len);
    }
    free(buf_recv);
    return result - IPHDR_LEN - SCTP2HDR_LEN;
}

int __sctp2_recv_other(int sfd, char* buf, size_t buf_len) {
    int result = -1;
    for(int i = 0; i < sctp2_saddrs_len; i++) {
        socklen_t saddr_len = sizeof(struct sockaddr);
        result = recv(sctp2_sockets[sfd][i], buf, buf_len, 0);
        if(result < 0){
            perror("Recv error");
        }
        __sctp2_print("Recv from", sctp2_sockets[sfd][i], sctp2_addr[sfd][i]);
        printf("Result: %s, number: %d\n", buf + IPHDR_LEN + SCTP2HDR_LEN, ((struct sctp2hdr*)(buf + IPHDR_LEN))->number);

    }
    return result;
}

void __sctp2_print(char* msg, int sfd, struct sockaddr* saddr) {
    printf("%s address:  %s, socket: %d\n", msg, inet_ntoa(((struct sockaddr_in *)saddr)->sin_addr), sfd);
}
