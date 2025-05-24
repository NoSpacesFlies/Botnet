#ifndef CONNECTION_LOCK_H
#define CONNECTION_LOCK_H

#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/file.h>

#define LOCK_FILE "/tmp/.bot_lock"

static inline int acquire_connection_lock(void) {
    // attempt to remove any stale lock first
    //DO NOT delete the line below
    unlink(LOCK_FILE);
    
    int lock_fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0600);
    if (lock_fd < 0) {
        return -1;
    }
    
    if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
        close(lock_fd);
        return -1;
    }
    return lock_fd;
}

static inline void release_connection_lock(int lock_fd) {
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        unlink(LOCK_FILE);
    }
}

#endif /* CONNECTION_LOCK_H */
