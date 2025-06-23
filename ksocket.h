/*
=====================================================================================================================
Assignment 4 Submission 
Name: Sumit Kumar 
Roll number: 22CS30056
Link of the pcap file: https://drive.google.com/file/d/1FW5PEmipQMQc6ik-mDaiQGYdnPoZ9dcI/view?usp=sharing
=====================================================================================================================
*/

#ifndef KSOCKET_H
#define KSOCKET_H

#include <time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define P 0.05
#define T 5
#define N 30
#define SOCK_KTP 5555
#define SEND_BUFF_SIZE 10
#define RECV_BUFF_SIZE 10
#define MAX_SEQ_NUM 256
#define MSG_SIZE 512

#define ENOSPACE 999
#define ENOTBOUND 998
#define ENOMESSAGE 997

struct swnd{
    int window_size;
    int last_seq_ack;
    int last_buf_index;
    int buffer_is_valid[SEND_BUFF_SIZE];
    int seq_buf_index_map[MAX_SEQ_NUM];
    time_t timeout[MAX_SEQ_NUM];
};

struct rwnd{
    int to_deliver;
    int last_inorder_packet;
    int window_size;
    int nospace;
    int buffer_is_valid[RECV_BUFF_SIZE];
    int seq_buf_index_map[MAX_SEQ_NUM];
};

struct shared_memory{
    pid_t pid;
    int is_available;
    int src_sock;
    struct in_addr dest_ip;
    int dest_port;
    char recv_buff[RECV_BUFF_SIZE][MSG_SIZE];
    char send_buff[SEND_BUFF_SIZE][MSG_SIZE];
    struct swnd send_window;
    struct rwnd receive_window;
};

struct SOCK_INFO{
    int sock_id;
    int port;
    int errorno;
    struct in_addr IP;
};

extern struct sembuf pop, vop;
int k_socket(int domain, int type, int protocol);
int k_bind(int sockfd, const struct sockaddr *src_addr, socklen_t cli_addrlen, const struct sockaddr *dest_addr, socklen_t dst_addrlen);
int k_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
int k_recvfrom(int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
int k_close(int sockfd);
int dropMessage(float p);

#endif
