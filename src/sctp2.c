#include "sctp2.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

extern int errno;

struct sock_filter __sctp2_filter_other[] = {  // ip proto 222 port 0x1234, ipv4
    { 0x30, 0, 0, 0x00000009 }, // Load IP proto
    { 0x15, 0, 5, IPPROTO_SCTP2 }, // Goto drop if proto is not IPPROTO_SCTP2
    { 0x30, 0, 0, 0x00000018 }, // Load SCTP2 type
    { 0x15, 2, 0, 0x00000002 }, // Goto success if type is SYN, further check if not
    { 0x15, 1, 0, 0x00000003 }, // Goto success if type is SYN_ACK, futher check if not
    { 0x15, 0, 1, 0x00000004 }, // Goto success if type is ACK, drop if not
    { 0x6, 0, 0, 0x00040000 }, // Success
    { 0x6, 0, 0, 0x00000000 }, // Drop
};


struct sock_fprog __sctp2_bpf_other = {
  .len = (sizeof(__sctp2_filter_other) / sizeof(__sctp2_filter_other[0])),
  .filter = __sctp2_filter_other
};

size_t __sctp2_sockets_count = 0;
size_t __sctp2_saddrs_len = 0;

struct __sctp2_sock** sctp2_sockets = NULL;


int sctp2_socket(size_t saddrs_len) {
    __sctp2_saddrs_len = saddrs_len;
    return __sctp2_create_and_add_socket();
}

void sctp2_bind(int sfd, struct sockaddr** saddrs) {

    __sctp2_add_sockaddrs(sfd, saddrs);

    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        setsockopt(sctp2_sockets[sfd]->sockets[i], SOL_SOCKET, SO_ATTACH_FILTER, &__sctp2_bpf_other, sizeof(__sctp2_bpf_other));
        bind(sctp2_sockets[sfd]->sockets[i], sctp2_sockets[sfd]->saddrs[i], sizeof(struct sockaddr));
    }
}

int sctp2_accept(int sfd) {
    int rfd;
    char buf[BUF_LEN];
    struct sockaddr** saddrs;
    saddrs = malloc(__sctp2_saddrs_len * sizeof(struct sockaddr*));
    for(int i = 0; i < __sctp2_saddrs_len; i++){
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
    struct __sctp2_msg_data msgs[MSG_WINDOW];
    int channel = 0;
    int msg_sent_number = 0;
    while(msg_sent_number * DATA_MSG_LEN < buf_len) {
        struct __sctp2_msg_data* cur_msg = &(msgs[msg_sent_number % MSG_WINDOW]); // FIXME doesn't have to be modulo
        cur_msg->number = msg_sent_number; 
        cur_msg->channel = channel; 
        cur_msg->buf_len = DATA_MSG_LEN; // FIXME last element can have different length
        cur_msg->msg = msg + msg_sent_number * DATA_MSG_LEN;
        __sctp2_send_data(sfd, cur_msg);

        __sctp2_recv_data_ack(sfd, cur_msg);

        channel = (channel + 1) % __sctp2_saddrs_len;
        msg_sent_number++;
    }
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
    return result;
}

int sctp2_recv(int sfd, char* buf, size_t buf_len) {
    struct __sctp2_msg_data msgs[MSG_WINDOW];
    int start_number = sctp2_sockets[sfd]->cur_number;
    int result = 0;

    while((sctp2_sockets[sfd]->cur_number - start_number) * DATA_MSG_LEN < buf_len) {
        int cur_recv_number = sctp2_sockets[sfd]->cur_number - start_number;
        struct __sctp2_msg_data* cur_msg = &(msgs[cur_recv_number % MSG_WINDOW]); // FIXME doesn't have to be modulo
        cur_msg->number = sctp2_sockets[sfd]->cur_number; 
        cur_msg->channel = sctp2_sockets[sfd]->cur_chan; 
        cur_msg->buf_len = buf_len > DATA_MSG_LEN * (cur_recv_number + 1) ? DATA_MSG_LEN : buf_len - DATA_MSG_LEN * cur_recv_number; // FIXME last element can have different length
        cur_msg->msg = malloc(buf_len * sizeof(char));

        result += __sctp2_recv_data(sfd, cur_msg);
        __sctp2_send_data_ack(sfd, cur_msg);

        strncpy(buf + cur_recv_number * DATA_MSG_LEN, cur_msg->msg, DATA_MSG_LEN); 

        sctp2_sockets[sfd]->cur_chan = (sctp2_sockets[sfd]->cur_chan + 1) % __sctp2_saddrs_len;
        sctp2_sockets[sfd]->cur_number++;

        free(cur_msg->msg);
    }

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
    
    return result;
}


int __sctp2_create_and_add_socket() {
    int sfd = __sctp2_sockets_count;
    __sctp2_sockets_count++;

    sctp2_sockets = realloc(sctp2_sockets, __sctp2_sockets_count * sizeof(struct __sctp2_sock*));
    sctp2_sockets[sfd] = malloc(sizeof(struct __sctp2_sock));

    sctp2_sockets[sfd]->sockets = malloc(__sctp2_saddrs_len * sizeof(short));
    if(sctp2_sockets == 0){
        perror("Sockaddr memory allocation error!");
        exit(0);
    }
    if(sctp2_sockets[sfd] == 0){
        perror("Socket memory allocation error!");
        exit(0);
    }
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        sctp2_sockets[sfd]->sockets[i] = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP2);

        if(sctp2_sockets[sfd]->sockets[i] < 0) {
            perror("Socket creation error!");
            exit(0);
        }
    }
    sctp2_sockets[sfd]->cur_chan = 0;
    sctp2_sockets[sfd]->cur_number = 0;
    sctp2_sockets[sfd]->saddrs = malloc(__sctp2_saddrs_len * sizeof(struct sockaddr*));
    memset(sctp2_sockets[sfd]->saddrs, 0, __sctp2_saddrs_len * sizeof(char));
    return sfd;
}

void __sctp2_connect_socket(int sfd, struct sockaddr** saddrs) {
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        connect(sctp2_sockets[sfd]->sockets[i], saddrs[i], sizeof(struct sockaddr));
    }
}

void __sctp2_add_sockaddrs(int sfd, struct sockaddr** saddrs) {
    for(int i = 0; i < __sctp2_saddrs_len; i++){
        sctp2_sockets[sfd]->saddrs[i] = malloc(sizeof(struct sockaddr));
        memcpy(sctp2_sockets[sfd]->saddrs[i], saddrs[i], sizeof(struct sockaddr));
    }
}

void __sctp2_send_data(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    struct sctp2hdr* shdr;
    shdr = malloc(sizeof(struct sctp2hdr) + buf_data->buf_len * sizeof(char));
    memset(shdr, 0, sizeof(struct sctp2hdr) + buf_data->buf_len * sizeof(char));
    shdr->type = SCTP2_TYPE_DATA;

    strncpy(shdr->msg, buf_data->msg, DATA_MSG_LEN); 
    shdr->number = buf_data->number;

    __sctp2_print("Send to", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);
    printf("Sent: %.*s\n", (int)buf_data->buf_len, buf_data->msg);
    result = sendto(sctp2_sockets[sfd]->sockets[buf_data->channel], shdr, sizeof(struct sctp2hdr) + DATA_MSG_LEN * sizeof(char), 0, sctp2_sockets[sfd]->saddrs[buf_data->channel], sizeof(struct sockaddr));
    if(result < 0) {
        perror("Send error");
    }
    free(shdr);
}

void __sctp2_send_data_ack(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    struct sctp2hdr* shdr;
    shdr = malloc(sizeof(struct sctp2hdr));
    memset(shdr, 0, sizeof(struct sctp2hdr));
    shdr->type = SCTP2_TYPE_DATA_ACK;
    shdr->number = buf_data->number;

    __sctp2_print("Reply to", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);
    result = sendto(sctp2_sockets[sfd]->sockets[buf_data->channel], shdr, sizeof(struct sctp2hdr), 0, sctp2_sockets[sfd]->saddrs[buf_data->channel], sizeof(struct sockaddr));
    if(result < 0) {
        perror("Send error");
    }

    free(shdr);
}

void __sctp2_send_other(int sfd, short type) {
    int result;
    struct sctp2hdr* shdr;

    shdr = malloc(sizeof(struct sctp2hdr));
    memset(shdr, 0, sizeof(struct sctp2hdr));
    shdr->type = type;
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        __sctp2_print("Send to", shdr->type, sctp2_sockets[sfd]->sockets[i], sctp2_sockets[sfd]->saddrs[i]);
        result = sendto(sctp2_sockets[sfd]->sockets[i], shdr, sizeof(struct sctp2hdr), 0, sctp2_sockets[sfd]->saddrs[i], sizeof(struct sockaddr));
        if(result < 0) {
            perror("Send error");
        }
    }
    free(shdr);
}

int __sctp2_recv_new_connection(int sfd, char* buf, size_t buf_len, struct sockaddr** saddrs) {
    int result = -1;
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        socklen_t saddr_len = sizeof(struct sockaddr);
        result = recvfrom(sctp2_sockets[sfd]->sockets[i], buf, BUF_LEN, 0, saddrs[i], &saddr_len);
        if(result < 0){
            perror("Recv error");
        }
        struct sctp2hdr* shdr = (struct sctp2hdr*) (buf + IPHDR_LEN);

        __sctp2_print("Recv from", shdr->type, sctp2_sockets[sfd]->sockets[i], saddrs[i]);

    }
    return result;
}

int __sctp2_recv_data(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    char* buf_recv = malloc(IPHDR_LEN + SCTP2HDR_LEN + buf_data->buf_len * sizeof(char));


    result = recv(sctp2_sockets[sfd]->sockets[buf_data->channel], buf_recv, IPHDR_LEN + SCTP2HDR_LEN + buf_data->buf_len, 0);
    if(result < 0) {
        perror("Recv error");
    }
    struct sctp2hdr* shdr = (struct sctp2hdr*) (buf_recv + IPHDR_LEN);

    __sctp2_print("Recv from", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);

    buf_data->number = shdr->number;
    memcpy(buf_data->msg, buf_recv + IPHDR_LEN + SCTP2HDR_LEN, buf_data->buf_len);
    printf("Recv: %s\n", buf_recv + IPHDR_LEN + SCTP2HDR_LEN);

    free(buf_recv);
    return result - IPHDR_LEN - SCTP2HDR_LEN;
}

int __sctp2_recv_data_ack(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    char* buf_recv = malloc(IPHDR_LEN + SCTP2HDR_LEN);


    result = recv(sctp2_sockets[sfd]->sockets[buf_data->channel], buf_recv, IPHDR_LEN + SCTP2HDR_LEN, 0);
    if(result < 0) {
        perror("Recv error");
    }
    struct sctp2hdr* shdr = (struct sctp2hdr*) (buf_recv + IPHDR_LEN);

    __sctp2_print("Recv reply", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);

    free(buf_recv);
    return result - IPHDR_LEN - SCTP2HDR_LEN;

}

int __sctp2_recv_other(int sfd, char* buf, size_t buf_len) {
    int result = -1;
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        result = recv(sctp2_sockets[sfd]->sockets[i], buf, buf_len, 0);
        if(result < 0){
            perror("Recv error");
        }
        struct sctp2hdr* shdr = (struct sctp2hdr*) (buf + IPHDR_LEN);

        __sctp2_print("Recv from", shdr->type, sctp2_sockets[sfd]->sockets[i], sctp2_sockets[sfd]->saddrs[i]);
        //printf("Result: %s, number: %d\n", buf + IPHDR_LEN + SCTP2HDR_LEN, ((struct sctp2hdr*)(buf + IPHDR_LEN))->number);

    }
    return result;
}

void __sctp2_print(char* msg, int type, int sfd, struct sockaddr* saddr) {
    printf("%s, type: %s, address:  %s, socket: %d\n", msg, __sctp2_type_to_str(type), inet_ntoa(((struct sockaddr_in *)saddr)->sin_addr), sfd);
}

char* __sctp2_type_to_str(int type) {
    switch(type) {
        case 0:
            return "DATA";
        case 1:
            return "DATA_ACK";
        case 2:
            return "SYN";
        case 3:
            return "SYN_ACK";
        case 4:
            return "ACK";
        case 5:
            return "FIN";
        case 6:
            return "RST";
        default:
            return "Unknown!";
    }
}
