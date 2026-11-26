/*
 * ex_swap.c — swapon / swapoff: attach and detach a swap backing device.
 *
 * Thin wrappers over /dev/zmem.  swapon hands the kernel a whole-disk name
 * (typically /dev/zram0, which zmem created) to page against; swapoff
 * releases it.  CactOS does not migrate swapped-out pages back to RAM, so
 * swapoff is refused while any are still out — detach an idle device.  Root
 * only, like mount.
 */

#include "common/ex_util.h"

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#include <ioctl_abi.h>

#define SWAP_NODE "/dev/zmem"

static int swap_ctl(const char *prog, const char *dev, uint32_t cmd) {
    int attach = (cmd == CACT_ZMEM_SWAP_ATTACH);

    int fd = open(SWAP_NODE, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: cannot open %s: %s\n", prog, SWAP_NODE, strerror(errno));
        return 1;
    }
    int rc = ioctl(fd, cmd, (void *)dev);
    close(fd);
    if (rc == 0) {
        printf("%s: %s %s\n", prog, dev, attach ? "enabled" : "disabled");
        return 0;
    }

    /* CactOS's ioctl() returns the negated errno in the return value and does
     * not set errno. */
    int e = rc < 0 ? -rc : rc;
    const char *why = (e == EPERM)  ? "operation not permitted (root only)"
                    : (e == ENODEV) ? "no such device"
                    : (e == EBUSY)  ? "still has pages swapped out (not migrated back)"
                    :                 "invalid argument";
    fprintf(stderr, "%s: %s: %s\n", prog, dev, why);
    return 1;
}

static const char swapon_usage[] =
    "usage: swapon <device>\n"
    "Start using a block device as swap (e.g. /dev/zram0).\n";

static const char swapoff_usage[] =
    "usage: swapoff <device>\n"
    "Stop using a block device as swap.\n";

int cact_ub_swapon(char **argv, int argc) {
    if (argc < 2) {
        write(STDOUT_FILENO, swapon_usage, sizeof(swapon_usage) - 1);
        return 2;
    }
    return swap_ctl("swapon", argv[1], CACT_ZMEM_SWAP_ATTACH);
}

int cact_ub_swapoff(char **argv, int argc) {
    if (argc < 2) {
        write(STDOUT_FILENO, swapoff_usage, sizeof(swapoff_usage) - 1);
        return 2;
    }
    return swap_ctl("swapoff", argv[1], CACT_ZMEM_SWAP_DETACH);
}
