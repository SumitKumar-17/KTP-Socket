/*
=====================================================================================================================
Assignment 4 Submission 
Name: Sumit Kumar 
Roll number: 22CS30056
Link of the pcap file: https://drive.google.com/file/d/1FW5PEmipQMQc6ik-mDaiQGYdnPoZ9dcI/view?usp=sharing
=====================================================================================================================
*/

/*
* User 2 receives messages from user1 and writes to a file
* Running with DSLEEP_MESSAGES gives sleep messages
*/

#include "ksocket.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>

#define WAITING_TIME 1
#define OUTPUT_FILE "output.txt"

void signal_handler(int signum){
    printf("\nSignal %d received\n", signum);
    printf("Exiting\n");
    exit(EXIT_SUCCESS);
}

int main(int argc,char* argv[])
{   
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
    int ret = k_bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (ret == -1){
        perror("k_bind");
        exit(EXIT_FAILURE);
    }
    printf("Bind successful from IP addr %s and port %d to IP addr %s and port %d\n", inet_ntoa(src_addr.sin_addr), ntohs(src_addr.sin_port), inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port));

    char recv_buf[MSG_SIZE];
    FILE *fp = fopen(OUTPUT_FILE, "w");
    int count = 1;
    while (1){
        ret = k_recvfrom(fd, recv_buf, MSG_SIZE, 0, (struct sockaddr *)&dest_addr, (socklen_t *)&dest_addr);
        if (ret == -1){
            if (errno == ENOMESSAGE){
#ifdef DSLEEP_MESSAGES
                printf("No data received. Sleeping for %d seconds\n", WAITING_TIME);
#endif
                sleep(WAITING_TIME);
                continue;
            }
            else{
                perror("k_recvfrom");
                exit(EXIT_FAILURE);
            }
        }
        else{
            char print_buf[MSG_SIZE + 1];
            for (int i = 0; i < MSG_SIZE; i++){
                print_buf[i] = recv_buf[i];
            }
            print_buf[MSG_SIZE] = '\0';
            printf("Received Message No: %d\n", count++);
            int isend = 1;
            for (int i = 0; i < MSG_SIZE; i++){
                if (recv_buf[i] != '$'){
                    isend = 0;
                    break;
                }
            }
            if (isend){
#ifdef DSLEEP_MESSAGES
                printf("End of file\n");
#endif
                fclose(fp);
                break;
            }
            if (fprintf(fp, "%s", print_buf) < 0){
                perror("fprintf");
                exit(EXIT_FAILURE);
            }
        }
    }
    printf("File written successfully\n");
    
    while (1){}
    exit(EXIT_FAILURE);
}
