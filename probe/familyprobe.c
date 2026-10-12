/* Which address families can this sandbox open a socket in?
 *
 * Written to check the fix for the vsock escape: AF_VSOCK must be refused, while the
 * families ordinary work needs must keep working. Compile and run inside the sandbox
 * image, with and without the hardened seccomp profile, and compare.
 *
 * Build: gcc -O0 -w -o familyprobe familyprobe.c
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct entry {
    int family;
    const char *name;
};

int main(void) {
    struct entry entries[] = {
        {40, "AF_VSOCK"},   /* the escape */
        {38, "AF_ALG"},
        {17, "AF_PACKET"},
        {30, "AF_TIPC"},
        {44, "AF_XDP"},
        {1, "AF_UNIX"},     /* must keep working: the MCP bridge needs it */
        {2, "AF_INET"},     /* must keep working: the point of the sandbox */
        {10, "AF_INET6"},
        {16, "AF_NETLINK"}, /* must keep working: glibc/Node use it */
    };
    int count = (int)(sizeof(entries) / sizeof(entries[0]));

    for (int i = 0; i < count; i++) {
        errno = 0;
        int fd = socket(entries[i].family, SOCK_STREAM, 0);
        if (fd < 0) {
            printf("%-10s (%2d)  DENIED   %s (errno %d)\n", entries[i].name, entries[i].family,
                   strerror(errno), errno);
        } else {
            printf("%-10s (%2d)  allowed\n", entries[i].name, entries[i].family);
            close(fd);
        }
    }
    return 0;
}
