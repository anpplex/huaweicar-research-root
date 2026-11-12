#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>

int main(void)
{
    errno = 0;
    long r = syscall(SYS_setresgid, getgid(), getgid(), getgid());
    printf("rc=%ld errno=%d gid=%d pid=%d\n", r, errno, getgid(), getpid());
    return 0;
}
