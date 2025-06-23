/*
=====================================================================================================================
Assignment 4 Submission 
Name: Sumit Kumar 
Roll number: 22CS30056
Link of the pcap file: https://drive.google.com/file/d/1FW5PEmipQMQc6ik-mDaiQGYdnPoZ9dcI/view?usp=sharing
=====================================================================================================================
*/

/*
    * User 1 sends messages to user2 from a file
    * Running with DSLEEP_MESSAGES gives sleep messages
    * Run with DRANDOM_MESSAGE defined to send random messages with sequence numbers
    * Run without DRANDOM_MESSAGE to send messages from a file
    * The end of the file is marked by sending a message with all characters as '$'
*/

#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>

#define WAITING_TIME 1
#define INPUT_FILE "input.txt"

#ifdef DRANDOM_MESSAGE
int generate_message_of_length(char *buf, int len, int seq_num){
    sprintf(buf, "%4d", seq_num);
    for (int i = 4; i < len - 1; i++)
    {
        buf[i] = '-';
    }
    buf[len - 2] = '\n';
    buf[len - 1] = '\0';
    return 0;
}
#endif

void signal_handler(int signum){
    printf("\nSignal %d received\n", signum);
    printf("Exiting\n");
    exit(EXIT_SUCCESS);
}

int main(int argc,char* argv[]){
    if(argc!=5){
        printf("Usage: %s <IP_SOURCE_1> <PORT_SOURCE_1> <IP_DESTINATION_2> <PORT_DESTINATION_2>\n",argv[0]);
        printf("-----------------------------------------------------------------------------\n");
        printf("\tCleaning process:\n");
        printf("\t-----------------\n");
        printf("\tmake -f libmake clean\n");
        printf("\tmake -f initmake clean\n");
        printf("\tmake -f usermake clean\n");
        printf("\n");
        printf("\tNow compile the files:\n");
        printf("\t------------------------\n");
        printf("\tmake -f libmake\n");
        printf("\tmake -f initmake\n");
        printf("\tmake -f usermake\n");
        printf("\n");
        printf("\tNow run the files:\n");
        printf("\t-------------------\n");
        printf("\tRun ./initksocket (in the first terminal)\n");
        printf("\tExample: If the server runs at port 5000 and the client runs at 6000\n");
        printf("\tRun ./user1 127.0.0.1 5000 127.0.0.1 6000 (in the second terminal)\n");
        printf("\tRun ./user2 127.0.0.1 6000 127.0.0.1 5000 (in the third terminal)\n");
        printf("-----------------------------------------------------------------------------\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);

    int fd = k_socket(AF_INET, SOCK_KTP, 0);
    if (fd == -1){
        perror("k_socket");
        exit(EXIT_FAILURE);
    }

    printf("Socket created successfully\n");
    
    struct sockaddr_in src_addr, dest_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = htons(atoi(argv[2]));
    src_addr.sin_addr.s_addr = inet_addr(argv[1]);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(atoi(argv[4]));
    dest_addr.sin_addr.s_addr = inet_addr(argv[3]);
    int ret;
    ret = k_bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (ret == -1){
        perror("k_bind");
        exit(EXIT_FAILURE);
    }
    printf("Bind successful from IP addr %s and port %d to IP addr %s and port %d\n", inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port), inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port));

#ifdef DRANDOM_MESSAGE
    char buf[MSG_SIZE];
    int count = 1;
    while (1){
        generate_message_of_length(buf, MSG_SIZE, count);
        ret = k_sendto(fd, buf, MSG_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (ret == -1){
            if (errno == ENOSPACE){
#ifdef DSLEEP_MESSAGES
                printf("Buffer is currently Full. Sleeping for %d seconds\n", WAITING_TIME);
#endif
                sleep(WAITING_TIME);
                continue;
            }
            else{
                perror("k_sendto");
                exit(EXIT_FAILURE);
            }
        }
        else{
            printf("Sent: %d\n", count);
            count++;
        }
        if (count >= 100){
            break;
        }
    }
    char end[MSG_SIZE];
    for (int i = 0; i < MSG_SIZE; i++){
        end[i] = '$';
    }
    while (1){
        ret = k_sendto(fd, end, MSG_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (ret == -1){
            if (errno == ENOSPACE){
#ifdef DSLEEP_MESSAGES
                printf("Buffer is currently Full. Sleeping for %d seconds\n", WAITING_TIME);
#endif
                sleep(WAITING_TIME);
                continue;
            }
            else{
                perror("k_sendto");
                exit(EXIT_FAILURE);
            }
        }
        else{
            printf("End Sent\n");
            break;
        }
    }

    while (1)
    {
    }
    exit(EXIT_SUCCESS);
#else
    FILE *fp = fopen(INPUT_FILE, "r");
    if (fp == NULL){
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    int count = 1;
    char buf[MSG_SIZE];

    while (fgets(buf, MSG_SIZE, fp) != NULL){
        while (1){
            ret = k_sendto(fd, buf, MSG_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (ret == -1){
                if (errno == ENOSPACE){
#ifdef DSLEEP_MESSAGES
                    printf("Buffer is currently Full. Sleeping for %d seconds\n", WAITING_TIME);
#endif
                }
                else{
                    perror("k_sendto");
                    exit(EXIT_FAILURE);
                }
            }
            else{
                printf("Sent Message No: %d\n", count);
                count++;
                break;
            }
            sleep(WAITING_TIME);
        }
    }
    char end[MSG_SIZE];
    for (int i = 0; i < MSG_SIZE; i++){
        end[i] = '$';
    }
    while (1){
        ret = k_sendto(fd, end, MSG_SIZE, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (ret == -1){
            if (errno == ENOSPACE){
#ifdef DSLEEP_MESSAGES
                printf("Buffer is currently Full. Sleeping for %d seconds\n", WAITING_TIME);
#endif
                sleep(WAITING_TIME);
            }
            else{
                perror("k_sendto");
                exit(EXIT_FAILURE);
            }
        }
        else{
            printf("End Sent\n");
            break;
        }
    }
    fclose(fp);

    while (1){}
    exit(EXIT_SUCCESS);
#endif
}
