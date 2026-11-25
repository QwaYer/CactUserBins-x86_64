/*
 * ex_zmem.c — zmemctl: control tool for the compressed-memory backends.
 *
 * One node, one tool: /dev/zmem takes typed ioctls (CACT_ZMEM_*) that
 * configure and enable in a single atomic call, and /proc/zmem reports what
 * they did.  There are no sysfs text knobs and no separate zram/zswap tools —
 * `zmemctl` drives both, and reads its own state back from /proc/zmem.
 *
 *   show                                             print the current state
 *   zswap on [--limit PCT] [--level N] [--writeback]
 *   zswap off
 *   zram create <size> [--name NAME] [--level N]
 *   zram destroy <name>
 *
 * Control needs root (the kernel rejects it otherwise); `show` does not.
 */

#include "common/ex_util.h"

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>

#include <ioctl_abi.h>

#define ZMEM_NODE "/dev/zmem"
#define ZMEM_PROC "/proc/zmem"

/* Limit used when `zswap on` is given without --limit; matches the kernel's
 * own boot default so the command line and the tool agree. */
#define ZMEM_DEFAULT_PCT 20u

static const char zmem_usage[] =
    "usage: zmemctl <command> [args]\n"
    "Compressed-memory control (/dev/zmem; state in /proc/zmem).\n"
    "  show                                             show current state\n"
    "  zswap on [--limit PCT] [--level N] [--writeback] enable the swap cache\n"
    "  zswap off                                        stop accepting pages\n"
    "  zram create <size> [--name NAME] [--level N]     create a RAM block dev\n"
    "  zram destroy <name>                              remove it (not while swap)\n"
    "Sizes take a K/M/G suffix (512M).  Control needs root.\n";

static int zmem_open(void) {
    int fd = open(ZMEM_NODE, O_RDONLY);
    if (fd < 0)
        fprintf(stderr, "zmemctl: cannot open %s: %s\n", ZMEM_NODE, strerror(errno));
    return fd;
}

/* Report a refused ioctl.  CactOS's ioctl() hands back the kernel's raw value
 * and does not reliably set errno on this path; the kernel's -1 is also shared
 * by "needs root" and the device-level failures, so the hint names the possible
 * causes instead of quoting an errno that is not there. */
static int zmem_refused(const char *hint) {
    fprintf(stderr, "zmemctl: %s\n", hint);
    return 1;
}

/* `show`: relay /proc/zmem verbatim, so the tool and `cat /proc/zmem` agree. */
static int zmem_show(void) {
    size_t len = 0;
    char *buf = cact_ub_read_all(ZMEM_PROC, &len);
    if (!buf) {
        fprintf(stderr, "zmemctl: cannot read %s: %s\n", ZMEM_PROC, strerror(errno));
        return 1;
    }
    cact_ub_write_all(STDOUT_FILENO, buf, len);
    free(buf);
    return 0;
}

/* Parse "25%" or "25" as a percentage in 1..100. */
static int zmem_pct(const char *s, uint32_t *out) {
    char *end;
    long v = strtol(s, &end, 10);
    if (end == s)
        return -1;
    if (*end == '%')
        end++;
    if (*end != '\0' || v < 1 || v > 100)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

static int zmem_zswap(char **argv, int argc) {
    int i = 2;
    if (i >= argc) {
        fprintf(stderr, "zmemctl: zswap needs 'on' or 'off'\n");
        return 1;
    }

    cact_zmem_zswap_t a;
    memset(&a, 0, sizeof(a));

    if (strcmp(argv[i], "off") == 0) {
        int fd = zmem_open();
        if (fd < 0) return 1;
        int rc = ioctl(fd, CACT_ZMEM_ZSWAP_SET, &a);   /* enabled = 0 */
        close(fd);
        if (rc != 0) return zmem_refused("zswap off refused (needs root)");
        printf("zswap off\n");
        return 0;
    }
    if (strcmp(argv[i], "on") != 0) {
        fprintf(stderr, "zmemctl: zswap: expected 'on' or 'off', got '%s'\n", argv[i]);
        return 1;
    }

    a.enabled       = 1;
    a.max_pool_pct  = ZMEM_DEFAULT_PCT;
    for (i++; i < argc; i++) {
        if (strcmp(argv[i], "--limit") == 0) {
            if (++i >= argc || zmem_pct(argv[i], &a.max_pool_pct) != 0) {
                fprintf(stderr, "zmemctl: --limit needs a percentage (1..100, '25%' or '25')\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--level") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "zmemctl: --level needs a number\n");
                return 1;
            }
            a.compress_level = atoi(argv[i]);
        } else if (strcmp(argv[i], "--writeback") == 0) {
            a.writeback = 1;
        } else {
            fprintf(stderr, "zmemctl: zswap: unexpected argument '%s'\n", argv[i]);
            return 1;
        }
    }

    int fd = zmem_open();
    if (fd < 0) return 1;
    int rc = ioctl(fd, CACT_ZMEM_ZSWAP_SET, &a);
    close(fd);
    if (rc != 0) return zmem_refused("zswap on refused (needs root, or bad limit / out of memory)");
    printf("zswap on (limit %u%%, level %d%s)\n", a.max_pool_pct,
           (int)a.compress_level, a.writeback ? ", writeback" : "");
    return 0;
}

static int zmem_zram(char **argv, int argc) {
    int i = 2;
    if (i >= argc) {
        fprintf(stderr, "zmemctl: zram needs 'create' or 'destroy'\n");
        return 1;
    }

    if (strcmp(argv[i], "destroy") == 0) {
        if (++i >= argc) {
            fprintf(stderr, "zmemctl: zram destroy needs a name\n");
            return 1;
        }
        int fd = zmem_open();
        if (fd < 0) return 1;
        int rc = ioctl(fd, CACT_ZMEM_ZRAM_DESTROY, argv[i]);
        close(fd);
        if (rc != 0)
            return zmem_refused("zram destroy refused (needs root; no such device, or it backs swap)");
        printf("destroyed %s\n", argv[i]);
        return 0;
    }

    if (strcmp(argv[i], "create") != 0) {
        fprintf(stderr, "zmemctl: zram: expected 'create' or 'destroy', got '%s'\n", argv[i]);
        return 1;
    }

    if (++i >= argc) {
        fprintf(stderr, "zmemctl: zram create needs a size (e.g. 512M)\n");
        return 1;
    }
    long size = cact_ub_parse_size(argv[i]);
    if (size <= 0) {
        fprintf(stderr, "zmemctl: bad size '%s'\n", argv[i]);
        return 1;
    }

    cact_zmem_zram_create_t a;
    memset(&a, 0, sizeof(a));
    a.size_bytes = (uint64_t)size;
    strcpy(a.name, "zram0");                       /* default; --name overrides */
    for (i++; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0) {
            if (++i >= argc || strlen(argv[i]) >= sizeof(a.name)) {
                fprintf(stderr, "zmemctl: --name needs a name of at most %u characters\n",
                        (unsigned)sizeof(a.name) - 1);
                return 1;
            }
            strcpy(a.name, argv[i]);
        } else if (strcmp(argv[i], "--level") == 0) {
            if (++i >= argc) {
                fprintf(stderr, "zmemctl: --level needs a number\n");
                return 1;
            }
            a.compress_level = atoi(argv[i]);
        } else {
            fprintf(stderr, "zmemctl: zram create: unexpected argument '%s'\n", argv[i]);
            return 1;
        }
    }

    int fd = zmem_open();
    if (fd < 0) return 1;
    int rc = ioctl(fd, CACT_ZMEM_ZRAM_CREATE, &a);
    close(fd);
    if (rc != 0) return zmem_refused("zram create refused (needs root; bad size, name in use, or out of memory)");
    printf("created /dev/%s (%llu MiB)\n", a.name, (unsigned long long)(a.size_bytes >> 20));
    return 0;
}

int cact_ub_zmemctl(char **argv, int argc) {
    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "help") == 0) {
        write(STDOUT_FILENO, zmem_usage, sizeof(zmem_usage) - 1);
        return argc < 2 ? 2 : 0;
    }
    if (strcmp(argv[1], "show") == 0)
        return zmem_show();
    if (strcmp(argv[1], "zswap") == 0)
        return zmem_zswap(argv, argc);
    if (strcmp(argv[1], "zram") == 0)
        return zmem_zram(argv, argc);

    fprintf(stderr, "zmemctl: unknown command '%s' (try --help)\n", argv[1]);
    return 2;
}
