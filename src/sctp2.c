#include "sctp2.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/filter.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h>

extern int errno;

struct sock_filter __sctp2_filter_other[] = {  // ipv4 only
    { 0x30, 0, 0, 0x00000009 }, // Load IP proto
    { 0x15, 0, 5, IPPROTO_SCTP2 }, // Goto drop if proto is not IPPROTO_SCTP2
    { 0x30, 0, 0, 0x00000018 }, // Load SCTP2 type
    { 0x15, 2, 0, SCTP2_TYPE_SYN }, // Goto success if type is SYN, further check if not
    { 0x15, 1, 0, SCTP2_TYPE_SYN_ACK }, // Goto success if type is SYN_ACK, futher check if not
    { 0x15, 0, 1, SCTP2_TYPE_ACK }, // Goto success if type is ACK, drop if not
    { 0x6, 0, 0, 0x00040000 }, // Success
    { 0x6, 0, 0, 0x00000000 }, // Drop
};

struct sock_filter __sctp2_filter_data[] = {  // ipv4 only
    { 0x30, 0, 0, 0x00000009 }, // Load IP proto
    { 0x15, 0, 5, IPPROTO_SCTP2 }, // Goto drop if proto is not IPPROTO_SCTP2
    { 0x30, 0, 0, 0x00000018 }, // Load SCTP2 type
    { 0x15, 2, 0, SCTP2_TYPE_DATA }, // Goto success if type is DATA, further check if not
    { 0x15, 1, 0, SCTP2_TYPE_DATA_ACK }, // Goto success if type is DATA_ACK, futher check if not
    { 0x15, 0, 1, SCTP2_TYPE_FIN }, // Goto success if type is FIN, drop if not
    { 0x6, 0, 0, 0x00040000 }, // Success
    { 0x6, 0, 0, 0x00000000 }, // Drop
};



struct sock_fprog __sctp2_bpf_other = {
  .len = (sizeof(__sctp2_filter_other) / sizeof(__sctp2_filter_other[0])),
  .filter = __sctp2_filter_other
};

struct sock_fprog __sctp2_bpf_data = {
  .len = (sizeof(__sctp2_filter_data) / sizeof(__sctp2_filter_data[0])),
  .filter = __sctp2_filter_data
};

size_t __sctp2_sockets_count = 0;
size_t __sctp2_saddrs_len = 0;

struct __sctp2_sock** sctp2_sockets = NULL;


int sctp2_socket(size_t saddrs_len) {
    __sctp2_saddrs_len = saddrs_len;
    int sfd = __sctp2_add_sctp2_sock();
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        __sctp2_add_socket(sfd, i);
    }
    return sfd;
}

void sctp2_bind(int sfd, struct sockaddr** saddrs) {

    __sctp2_add_sockaddrs(sfd, saddrs);

    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        setsockopt(sctp2_sockets[sfd]->sockets[i], SOL_SOCKET, SO_ATTACH_FILTER, &__sctp2_bpf_other, sizeof(__sctp2_bpf_other));
        bind(sctp2_sockets[sfd]->sockets[i], sctp2_sockets[sfd]->saddrs[i], sizeof(struct sockaddr));
    }
}

int sctp2_accept(int sfd) {
    struct sockaddr** saddrs;
    saddrs = malloc(__sctp2_saddrs_len * sizeof(struct sockaddr*));
    for(int i = 0; i < __sctp2_saddrs_len; i++){
        saddrs[i] = malloc(sizeof(struct sockaddr));
        memset(saddrs[i], 0, sizeof(struct sockaddr));
    }

    sctp2_sockets[sfd]->open_sockets_len = __sctp2_saddrs_len;

    // 3 way handshake
    
    int rfd = __sctp2_recv_new_connection(sfd, saddrs);
    return rfd;
}

void sctp2_send(int sfd, char* msg, size_t buf_len) {
    struct __sctp2_msg_data msgs[MSG_WINDOW];
    memset(&msgs, 0, sizeof(struct __sctp2_msg_data) * MSG_WINDOW);
    int channel = 0;
    int start_number = sctp2_sockets[sfd]->cur_number;
    int msg_sent_number = sctp2_sockets[sfd]->cur_number;
    int msg_replied_number = sctp2_sockets[sfd]->cur_number;
    while((msg_sent_number - start_number) * DATA_MSG_LEN < buf_len) {
        struct __sctp2_msg_data* cur_msg = &(msgs[msg_sent_number % MSG_WINDOW]); // FIXME doesn't have to be modulo
        while (cur_msg->replied == MSG_NOT_REPLIED) {
            __sctp2_check_ack_and_resend_data(sfd, msgs, msg_sent_number, &msg_replied_number);
        }
        cur_msg->number = msg_sent_number; 
        cur_msg->type = SCTP2_TYPE_DATA;
        cur_msg->channel = channel; 
        cur_msg->buf_len = DATA_MSG_LEN < buf_len ? DATA_MSG_LEN : buf_len; // FIXME last element can have different length
        cur_msg->msg = msg + (msg_sent_number - start_number)* DATA_MSG_LEN;
    //printf("sendmsg type: %d, number: %d, channel: %d, buf_len: %d\n", cur_msg->type, cur_msg->number, cur_msg->channel, cur_msg->buf_len);

        __sctp2_send_data(sfd, cur_msg);

        cur_msg->replied = MSG_NOT_REPLIED; 
        msg_sent_number++;
        sctp2_sockets[sfd]->cur_number = msg_sent_number;

        channel = (channel + 1) % sctp2_sockets[sfd]->open_sockets_len;
    }
    int msg_to_check = 0;
    while(msg_sent_number != msg_replied_number) {
        struct __sctp2_msg_data* cur_msg = &(msgs[msg_to_check % MSG_WINDOW]); // FIXME doesn't have to be modulo
        if (cur_msg->replied == MSG_NOT_REPLIED) {
            __sctp2_check_ack_and_resend_data(sfd, msgs, msg_to_check, &msg_replied_number);
        }
        msg_to_check = (msg_to_check + 1) % MSG_WINDOW;
    }
}

int sctp2_connect(int sfd, struct sockaddr** saddrs) {
    __sctp2_add_sockaddrs(sfd, saddrs);
    __sctp2_connect_sockets(sfd, saddrs);

    __sctp2_send_new_connection(sfd);
    // 3 way handshake
    /*__sctp2_send_other_all(sfd, SCTP2_TYPE_SYN);
    int result = __sctp2_recv_other(sfd, buf, BUF_LEN);
    struct sctp2hdr* hdr = (struct sctp2hdr*) (buf + IPHDR_LEN);
    if(hdr->type == SCTP2_TYPE_SYN_ACK) {
        printf("Accept: SYNACK\n");
        __sctp2_send_other_all(sfd, SCTP2_TYPE_ACK);
    }*/
    return 0;
}

int sctp2_recv(int sfd, char* buf) {
    struct __sctp2_msg_data msgs[MSG_WINDOW];
    int start_number = sctp2_sockets[sfd]->cur_number;
    int result = 0;

    if(sctp2_sockets[sfd]->open_sockets_len == 0) {
        return 0;
    }

    do {
        int cur_recv_number = sctp2_sockets[sfd]->cur_number - start_number;
        struct __sctp2_msg_data* cur_msg = &(msgs[cur_recv_number % MSG_WINDOW]); // FIXME doesn't have to be modulo
        cur_msg->number = sctp2_sockets[sfd]->cur_number; 
        cur_msg->type = SCTP2_TYPE_DATA; 
        cur_msg->channel = sctp2_sockets[sfd]->cur_chan; 
        cur_msg->buf_len = DATA_MSG_LEN;
        cur_msg->msg = malloc(DATA_MSG_LEN * sizeof(char));
        if(cur_msg->number > 100) {
            cur_msg->channel = 0;
            printf("Aaaaaaa\n");
        }

        int recv_res = -1;
        while (recv_res == -1 || (cur_msg->type != SCTP2_TYPE_DATA && cur_msg->type != SCTP2_TYPE_FIN)) {
            recv_res = __sctp2_recv_data(sfd, cur_msg);
            printf("number: %d\n", cur_msg->number);
        }
        //printf("recvmsg type: %d, number: %d, channel: %d, buf_len: %d\n", cur_msg->type, cur_msg->number, cur_msg->channel, cur_msg->buf_len);
        __sctp2_send_data_ack(sfd, cur_msg);
        if(cur_msg->type == SCTP2_TYPE_FIN) {
            if(sctp2_sockets[sfd]->sockets[cur_msg->channel] != -1) {
                sctp2_sockets[sfd]->sockets[cur_msg->channel] = -1;
                sctp2_sockets[sfd]->open_sockets_len--;
                if(sctp2_sockets[sfd]->open_sockets_len == 0) {
                    return result;
                }

                do {
                    sctp2_sockets[sfd]->cur_chan = (sctp2_sockets[sfd]->cur_chan + 1) % __sctp2_saddrs_len;
                } while(sctp2_sockets[sfd]->sockets[sctp2_sockets[sfd]->cur_chan] == -1);
            }
        }
        else {
            if(cur_msg->number < start_number) {
                continue;
            }
            result += recv_res;

            memcpy(buf, cur_msg->msg, DATA_MSG_LEN); 

            sctp2_sockets[sfd]->cur_chan = (sctp2_sockets[sfd]->cur_chan + 1) % sctp2_sockets[sfd]->open_sockets_len;
            sctp2_sockets[sfd]->cur_number++;
        }

        free(cur_msg->msg);
    } while(result == 0);

    /*printf("Received result: ");
    for(int j = 0; j < result; ++j) //20 == length of an ip header
        printf("%c", ((uint8_t*) buf)[j]);
    printf(", size: %d\n", result);*/
    return result;
}

int sctp2_close(int sfd) {
    char buf[BUF_LEN];
    __sctp2_send_other_all(sfd, SCTP2_TYPE_FIN);
    int result = __sctp2_recv_other(sfd, buf, BUF_LEN);
    
    return result;
}


int __sctp2_add_sctp2_sock() {
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

    sctp2_sockets[sfd]->cur_chan = 0;
    sctp2_sockets[sfd]->cur_number = 0;
    sctp2_sockets[sfd]->open_sockets_len = 0;
    sctp2_sockets[sfd]->saddrs = malloc(__sctp2_saddrs_len * sizeof(struct sockaddr*));
    memset(sctp2_sockets[sfd]->saddrs, 0, __sctp2_saddrs_len * sizeof(char));
    return sfd;
}

void __sctp2_add_socket(int sfd, int i) {
    sctp2_sockets[sfd]->sockets[i] = socket(AF_INET, SOCK_RAW, IPPROTO_SCTP2);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = SCTP2_TIMEOUT_USEC;
    setsockopt(sctp2_sockets[sfd]->sockets[i], SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    if(sctp2_sockets[sfd]->sockets[i] < 0) {
        perror("Socket creation error!");
        exit(0);
    }

    sctp2_sockets[sfd]->cur_chan = (sctp2_sockets[sfd]->cur_chan + 1) % __sctp2_saddrs_len;
}

void __sctp2_connect_sockets(int sfd, struct sockaddr** saddrs) {
    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        __sctp2_connect_socket(sfd, i, saddrs[i]);
    }
}

void __sctp2_connect_socket(int sfd, int i, struct sockaddr* saddr) {
    connect(sctp2_sockets[sfd]->sockets[i], saddr, sizeof(struct sockaddr));
}


void __sctp2_add_sockaddrs(int sfd, struct sockaddr** saddrs) {
    for(int i = 0; i < __sctp2_saddrs_len; i++){
        __sctp2_add_sockaddr(sfd, i, saddrs[i]);
    }
}

void __sctp2_add_sockaddr(int sfd, int i, struct sockaddr* saddr) {
    sctp2_sockets[sfd]->saddrs[i] = malloc(sizeof(struct sockaddr));
    memcpy(sctp2_sockets[sfd]->saddrs[i], saddr, sizeof(struct sockaddr));
}

void __sctp2_send_data(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    struct sctp2hdr* shdr;
    shdr = malloc(sizeof(struct sctp2hdr) + buf_data->buf_len * sizeof(char));
    memset(shdr, 0, sizeof(struct sctp2hdr) + buf_data->buf_len * sizeof(char));

    memcpy(shdr->msg, buf_data->msg, buf_data->buf_len); 
    shdr->number = buf_data->number;
    shdr->type = SCTP2_TYPE_DATA;

    __sctp2_print("Send to", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);
    if(DEBUG) {
        printf("Sent: %.*s\n", (int)buf_data->buf_len, buf_data->msg);
    }
    result = sendto(sctp2_sockets[sfd]->sockets[buf_data->channel], shdr, sizeof(struct sctp2hdr) + buf_data->buf_len * sizeof(char), 0, sctp2_sockets[sfd]->saddrs[buf_data->channel], sizeof(struct sockaddr));
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

void __sctp2_send_other_single(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    int channel;
    struct sctp2hdr* shdr;

    shdr = malloc(sizeof(struct sctp2hdr));
    memset(shdr, 0, sizeof(struct sctp2hdr));
    shdr->type = buf_data->type;
    channel = buf_data->channel;

    __sctp2_print("Send to", shdr->type, sctp2_sockets[sfd]->sockets[channel], sctp2_sockets[sfd]->saddrs[channel]);
    result = sendto(sctp2_sockets[sfd]->sockets[channel], shdr, sizeof(struct sctp2hdr), 0, sctp2_sockets[sfd]->saddrs[channel], sizeof(struct sockaddr));
    if(result < 0) {
        perror("Send error");
    }

    free(shdr);

}

void __sctp2_send_other_all(int sfd, short type) {
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

void __sctp2_send_new_connection(int sfd) {
    int result;
    int cur_chan = 0;
    struct __sctp2_msg_data* msgs;
    struct sctp2hdr* shdr;
    char buf[BUF_LEN];
    
    msgs = malloc(__sctp2_saddrs_len * sizeof(struct __sctp2_msg_data));
    memset(msgs, 0, __sctp2_saddrs_len * sizeof(struct __sctp2_msg_data));

    shdr = malloc(sizeof(struct sctp2hdr));
    memset(shdr, 0, sizeof(struct sctp2hdr));
    shdr->type = SCTP2_TYPE_SYN;

    for(int i = 0; i < __sctp2_saddrs_len; i++) {
        msgs[i].type = SCTP2_TYPE_SYN;
        msgs[i].channel = i;
        msgs[i].replied = 0;

        __sctp2_print("Send to", shdr->type, sctp2_sockets[sfd]->sockets[i], sctp2_sockets[sfd]->saddrs[i]);
        result = send(sctp2_sockets[sfd]->sockets[i], shdr, sizeof(struct sctp2hdr), 0);
        if(result < 0) {
            perror("Send error");
        }
    }

    while(sctp2_sockets[sfd]->open_sockets_len < __sctp2_saddrs_len) {

        result = recv(sctp2_sockets[sfd]->sockets[cur_chan], buf, BUF_LEN, 0);
        if(result < 0) {
            if(errno == EAGAIN) {
                do {
                    cur_chan = (cur_chan + 1) % __sctp2_saddrs_len;
                } while(msgs[cur_chan].replied != 0);
                continue;
            }
            perror("Recv error");
        }
        struct sctp2hdr* shdr_recv = (struct sctp2hdr*) (buf + IPHDR_LEN);
        if(shdr_recv->type == SCTP2_TYPE_SYN_ACK) {
            if(msgs[cur_chan].replied == 0) {
            __sctp2_print("Recv from", shdr_recv->type, sctp2_sockets[sfd]->sockets[cur_chan], sctp2_sockets[sfd]->saddrs[cur_chan]);
                msgs[cur_chan].replied += 1;
                sctp2_sockets[sfd]->open_sockets_len++;
            }
            shdr->type = SCTP2_TYPE_ACK;
            __sctp2_print("Send to", shdr->type, sctp2_sockets[sfd]->sockets[cur_chan], sctp2_sockets[sfd]->saddrs[cur_chan]);
            result = sendto(sctp2_sockets[sfd]->sockets[cur_chan], shdr, sizeof(struct sctp2hdr), 0, sctp2_sockets[sfd]->saddrs[cur_chan], sizeof(struct sockaddr));

            if(sctp2_sockets[sfd]->open_sockets_len < __sctp2_saddrs_len) {
                do {
                    cur_chan = (cur_chan + 1) % __sctp2_saddrs_len;
                } while(msgs[cur_chan].replied != 0);
            }
        }

    }

    free(shdr);
}

int __sctp2_recv_new_connection(int sfd, struct sockaddr** saddrs) {
    char buf[BUF_LEN];
    int result = -1;
    int cur_chan = 0;
    int* synced_sockets;
    int opened_sockets_count = 0;
    int ackd_sockets_count = 0;
    struct sctp2hdr* shdr_syn_ack;

    synced_sockets = malloc(__sctp2_saddrs_len * sizeof(int));
    memset(synced_sockets, 0, __sctp2_saddrs_len * sizeof(int));

    shdr_syn_ack = malloc(sizeof(struct sctp2hdr));
    memset(shdr_syn_ack, 0, sizeof(struct sctp2hdr));
    shdr_syn_ack->type = SCTP2_TYPE_SYN_ACK;

    int rfd = __sctp2_add_sctp2_sock();

    while(opened_sockets_count < __sctp2_saddrs_len || ackd_sockets_count < __sctp2_saddrs_len) { 
        socklen_t saddr_len = sizeof(struct sockaddr);
        result = recvfrom(sctp2_sockets[sfd]->sockets[cur_chan], buf, BUF_LEN, 0, saddrs[cur_chan], &saddr_len);
        if(result < 0){
            if(errno == EAGAIN) {
                do {
                    cur_chan = (cur_chan + 1) % __sctp2_saddrs_len;
                } while(synced_sockets[cur_chan] == 2);
                continue;
            }
            perror("Recv error");
        }
        struct sctp2hdr* shdr_syn = (struct sctp2hdr*) (buf + IPHDR_LEN);
        if(shdr_syn->type == SCTP2_TYPE_SYN) {
            __sctp2_print("Recv from", shdr_syn->type, sctp2_sockets[sfd]->sockets[cur_chan], saddrs[cur_chan]);
            __sctp2_print("Send to", shdr_syn_ack->type, sctp2_sockets[sfd]->sockets[cur_chan], saddrs[cur_chan]);

            result = sendto(sctp2_sockets[sfd]->sockets[cur_chan], shdr_syn_ack, sizeof(struct sctp2hdr), 0, saddrs[cur_chan], sizeof(struct sockaddr));

            if(synced_sockets[cur_chan] == 0) {
                __sctp2_add_socket(rfd, cur_chan);
                __sctp2_add_sockaddr(rfd, cur_chan, saddrs[cur_chan]);
                __sctp2_connect_socket(rfd, cur_chan, saddrs[cur_chan]);
                setsockopt(sctp2_sockets[rfd]->sockets[cur_chan], SOL_SOCKET, SO_ATTACH_FILTER, &__sctp2_bpf_data, sizeof(__sctp2_bpf_data));

                opened_sockets_count++;
                synced_sockets[cur_chan] = 1;
            }

            if(opened_sockets_count < __sctp2_saddrs_len) {
                do {
                    cur_chan = (cur_chan + 1) % __sctp2_saddrs_len;
                } while(synced_sockets[cur_chan] != 0);
            }

        }
        if(shdr_syn->type == SCTP2_TYPE_ACK) {
            __sctp2_print("Recv from", shdr_syn->type, sctp2_sockets[sfd]->sockets[cur_chan], saddrs[cur_chan]);
            if(synced_sockets[cur_chan] == 1) {
                ackd_sockets_count++;
                synced_sockets[cur_chan] = 2;
            }

            if(ackd_sockets_count < __sctp2_saddrs_len) {
                do {
                    cur_chan = (cur_chan + 1) % __sctp2_saddrs_len;
                } while(synced_sockets[cur_chan] != 1);
            }
        }

    }

    sctp2_sockets[rfd]->open_sockets_len = opened_sockets_count;

    free(synced_sockets);
    return rfd;
}

int __sctp2_recv_data(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    char* buf_recv = malloc(IPHDR_LEN + SCTP2HDR_LEN + buf_data->buf_len * sizeof(char));
    memset(buf_recv, 0, IPHDR_LEN + SCTP2HDR_LEN + buf_data->buf_len * sizeof(char));


    result = recv(sctp2_sockets[sfd]->sockets[buf_data->channel], buf_recv, IPHDR_LEN + SCTP2HDR_LEN + buf_data->buf_len, 0);
    if(result < 0) {
        if(errno == EAGAIN) {
            sctp2_sockets[sfd]->cur_chan = (sctp2_sockets[sfd]->cur_chan + 1) % sctp2_sockets[sfd]->open_sockets_len;
            return -1;
        }
        perror("Recv error");
    }
    struct sctp2hdr* shdr = (struct sctp2hdr*) (buf_recv + IPHDR_LEN);

    __sctp2_print("Recv from", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);

    buf_data->number = shdr->number;
    buf_data->type = shdr->type;
    memcpy(buf_data->msg, buf_recv + IPHDR_LEN + SCTP2HDR_LEN, buf_data->buf_len);
    if (DEBUG) {
        printf("Recv: %s\n", buf_recv + IPHDR_LEN + SCTP2HDR_LEN);
    }

    free(buf_recv);
    return result - IPHDR_LEN - SCTP2HDR_LEN;
}

int __sctp2_recv_data_ack(int sfd, struct __sctp2_msg_data* buf_data) {
    int result;
    char* buf_recv = malloc(IPHDR_LEN + SCTP2HDR_LEN);


    result = recv(sctp2_sockets[sfd]->sockets[buf_data->channel], buf_recv, IPHDR_LEN + SCTP2HDR_LEN, 0);
    if(result < 0) {
        if(errno == EAGAIN) {
            return -1;
        }
        perror("Recv error");
    }
    struct sctp2hdr* shdr = (struct sctp2hdr*) (buf_recv + IPHDR_LEN);

    buf_data->number = shdr->number;
    buf_data->type = shdr->type;

    __sctp2_print("Recv reply", shdr->type, sctp2_sockets[sfd]->sockets[buf_data->channel], sctp2_sockets[sfd]->saddrs[buf_data->channel]);

    free(buf_recv);
    return result - IPHDR_LEN - SCTP2HDR_LEN;

}

int __sctp2_recv_other(int sfd, char* buf, size_t buf_len) {
    int result = -1;
    for(int i = 0; i < sctp2_sockets[sfd]->open_sockets_len; i++) {
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

void __sctp2_check_ack_and_resend_data(int sfd, struct __sctp2_msg_data* msgs, int msg_to_check, int* msg_replied_number){
    struct __sctp2_msg_data* cur_msg = &(msgs[msg_to_check % MSG_WINDOW]); // FIXME doesn't have to be modulo
    //printf("msg type: %d, number: %d, channel: %d, buf_len: %d\n", cur_msg->type, cur_msg->number, cur_msg->channel, cur_msg->buf_len);
    struct __sctp2_msg_data* ack;
    ack = malloc(sizeof(struct __sctp2_msg_data));
    memset(ack, 0, sizeof(struct __sctp2_msg_data));
    ack->channel = cur_msg->channel;
    int result_ack = __sctp2_recv_data_ack(sfd, ack);

    //printf("recvack type: %d, number: %d, channel: %d, buf_len: %d, result_ack %d\n", ack->type, ack->number, ack->channel, ack->buf_len, result_ack);
    if(result_ack == -1) { //if timeout FIXME
        cur_msg->channel = (cur_msg->channel + 1) % sctp2_sockets[sfd]->open_sockets_len;
        if(cur_msg->type == SCTP2_TYPE_DATA) {

            __sctp2_send_data(sfd, cur_msg);
        }
        else {
        }
    }
    else {
        (*msg_replied_number)++;
        msgs[ack->number % MSG_WINDOW].replied = MSG_REPLIED;
    }

}

void __sctp2_print(char* msg, int type, int sfd, struct sockaddr* saddr) {
    if(DEBUG) {
        printf("%s, type: %s, address:  %s, socket: %d\n", msg, __sctp2_type_to_str(type), inet_ntoa(((struct sockaddr_in *)saddr)->sin_addr), sfd);
    }
}

char* __sctp2_type_to_str(int type) {
    switch(type) {
        case SCTP2_TYPE_DATA:
            return "DATA";
        case SCTP2_TYPE_DATA_ACK:
            return "DATA_ACK";
        case SCTP2_TYPE_SYN:
            return "SYN";
        case SCTP2_TYPE_SYN_ACK:
            return "SYN_ACK";
        case SCTP2_TYPE_ACK:
            return "ACK";
        case SCTP2_TYPE_FIN:
            return "FIN";
        case SCTP2_TYPE_RST:
            return "RST";
        default:
            return "Unknown!";
    }
}
