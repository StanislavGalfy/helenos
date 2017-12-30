#include "posix/libgen.h"
#include "posix/glob.h"
#include "posix/grp.h"
#include "posix/sys/select.h"
#include "posix/termios.h"
#include "posix/sys/ioctl.h"

char *dirname(char *path) {
    return NULL;
}

void globfree(glob_t *pglob) {
}

inline int glob(const char *pattern, int flags,
         int (*errfunc) (const char *epath, int eerrno),
         glob_t *pglob) {
    
    return 0;
}

pid_t setsid(void) {
	return 0;
}

int setgid(gid_t gid) {
	return 0;
}

int chown(const char *pathname, uid_t owner, gid_t group) {
	return 0;
}

struct group *getgrnam(const char *name) {
	return NULL;
}

int select(int nfds, fd_set *readfds, fd_set *writefds,
        fd_set *exceptfds, struct timeval *timeout) {
    return nfds;
}

int tcgetattr(int fd, struct termios *termios_p) {
    return 0;
}

int tcsetattr(int fd, int optional_actions,
              const struct termios *termios_p) {
    return 0;
}

int ioctl(int fd, int request, ...) {
    return 0;
}