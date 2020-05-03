#ifndef SCTP2_H 
#define SCTP2_H
#include <netinet/in.h>

#define SCTP2_TYPE_DATA 0
#define SCTP2_TYPE_DATA_ACK 1
#define SCTP2_TYPE_SYN 2
#define SCTP2_TYPE_SYN_ACK 3
#define SCTP2_TYPE_ACK 4
#define SCTP2_TYPE_FIN 5
#define SCTP2_TYPE_RST 6

#define IPPROTO_SCTP2 222
#define BUF_LEN 28
#define DATA_MSG_LEN 2 
#define IPHDR_LEN 20
#define SCTP2HDR_LEN 8

struct sctp2hdr {
    short source;
    short dest;
    short type; 
    short number; // used to be u_int8_t
    char msg[];
};

int sctp2_socket_id;
int** sctp2_sockets;
size_t sctp2_sockets_count;
size_t sctp2_saddrs_len;

struct sockaddr*** sctp2_addr;


int sctp2_socket(size_t saddrs_len);

void sctp2_bind(int sfd, struct sockaddr** saddrs);

void sctp2_listen();

int sctp2_accept(int sfd);

void sctp2_send(int sfd, char* msg, size_t buf_len);

int sctp2_connect(int sfd, struct sockaddr** saddrs);

int sctp2_recv(int sfd, char* buf, size_t buf_len);

int sctp2_close(int sfd);


int __sctp2_create_and_add_socket();

void __sctp2_connect_socket(int sfd, struct sockaddr** saddrs);

void __sctp2_add_sockaddrs(int sfd, struct sockaddr** saddrs);

void __sctp2_send_data(int sfd, char* buf, size_t buf_len);

void __sctp2_send_other(int sfd, short type);

int __sctp2_recv_new_connection(int sfd, char* buf, size_t buf_len, struct sockaddr** saddrs);

int __sctp2_recv_data(int sfd, char* buf, size_t buf_len);

int __sctp2_recv_other(int sfd, char* buf, size_t buf_len);

void __sctp2_print(char* msg, int sfd, struct sockaddr* saddr);

#endif
