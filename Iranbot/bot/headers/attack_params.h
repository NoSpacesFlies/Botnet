#pragma once

#ifndef ATTACK_PARAMS_H
#define ATTACK_PARAMS_H


#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <errno.h>
#include <time.h>
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <poll.h>
#include <ctype.h>
#include <stddef.h>
#include <sys/time.h>
#include "checksum.h"

typedef struct {
    struct sockaddr_in target_addr;  
    uint32_t duration;             // global, !test ip port time for layer4  
    uint8_t active;        // active or no
    uint16_t psize;                  // global (or min if range)
    uint16_t psize_min;              // min psize for range
    uint16_t psize_max;              // max psize for range
    uint16_t srcport;     //udp,syn,gre, srcport for inner gre method if proto=udp/tcp
    uint32_t base_ip;
    uint8_t cidr;        // 0 =normal else /1 - /32
    unsigned char msg[128];
    int msg_len;
    int usleep_min;
    int usleep_max;
} attack_params;

#endif // ATTACK_PARAMS_H
