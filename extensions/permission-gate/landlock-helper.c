/*
 * pi-sandbox-landlock
 *
 * Apply a Landlock filesystem policy, then exec a command.
 *
 *   pi-sandbox-landlock [--rw PATH]... -- COMMAND [ARGS...]
 *
 * Policy: everything on the filesystem is read-only (and executable), and
 * each --rw path (and its subtree) becomes fully read/writable. The caller
 * is responsible for passing an absolute, existing directory per --rw (the
 * TypeScript layer resolves to the deepest existing ancestor).
 *
 * The helper is deliberately dependency-free: raw syscalls, no
 * <linux/landlock.h> needed, so it compiles on any glibc system with a
 * Landlock-capable kernel (>= 5.13). It supports both syscall conventions:
 *
 *   old (kernel <= 6.12):  landlock_create_ruleset(attr, abi)
 *                          path_beneath { s32 parent_fd; u32 allowed_access; }
 *   new (kernel  >= 6.13): landlock_create_ruleset(attr, size, flags)
 *                          path_beneath { u64 allowed_access; s32 parent_fd; } packed
 *
 * Detection: the VERSION query (attr=NULL, size=0, flags=1) succeeds only on
 * the new convention; on the old one it is interpreted as (NULL, abi=0) and
 * returns EINVAL.
 *
 * PR_SET_NO_NEW_PRIVS is set before restrict_self (a Landlock requirement);
 * as a side effect setuid escalation (sudo & co) fails inside the sandbox.
 *
 * Exit status: the exec'd command's status (execvp replaces the process).
 * Any policy/spawn failure exits non-zero WITHOUT running the command
 * (fail-closed).
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>

/* Syscall numbers: 444/445/446 on both x86_64 and aarch64 (stable since
 * 5.13). Prefer the kernel headers when present. */
#ifdef __has_include
#if __has_include(<asm/unistd.h>)
#include <asm/unistd.h>
#endif
#endif
#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#else
#error "pi-sandbox-landlock: unsupported architecture"
#endif
#endif
#define PI_LL_CREATE __NR_landlock_create_ruleset
#define PI_LL_ADD_RULE (__NR_landlock_create_ruleset + 1)
#define PI_LL_RESTRICT_SELF (__NR_landlock_create_ruleset + 2)

/* Stable access-flag values (see include/uapi/linux/landlock.h). */
#define A_READ_FILE (1ULL << 0)    /* ABI 1 */
#define A_WRITE_FILE (1ULL << 1)   /* ABI 1 */
#define A_EXECUTE (1ULL << 2)      /* ABI 1 */
#define A_READ_DIR (1ULL << 3)     /* ABI 1 */
#define A_REMOVE_FILE (1ULL << 4)  /* ABI 1 */
#define A_RENAME_FILE (1ULL << 5)  /* ABI 1 */
#define A_MAKE_EXEC (1ULL << 6)    /* ABI 1 */
#define A_IOCTL_DEV (1ULL << 7)    /* ABI 2 */
#define A_TRUNCATE (1ULL << 8)     /* ABI 2 */
#define A_REFER (1ULL << 9)        /* ABI 3: source of link()/rename() */

#define RULE_PATH_BENEATH 1
#define CREATE_RULESET_VERSION (1U)
#define MAX_RW_PATHS 64

/* New convention: 16-byte ruleset attr (fs + net handled masks). */
struct ruleset_attr {
    unsigned long long handled_access_fs;
    unsigned long long handled_access_net;
};

/* New convention path-beneath (kernel >= 6.13): note the field order and
 * packing — do not reorder. */
struct pb_new {
    unsigned long long allowed_access;
    int parent_fd;
} __attribute__((packed));

/* Old convention path-beneath (kernel <= 6.12). */
struct pb_old {
    int parent_fd;
    unsigned int allowed_access;
};

static int ll_create_new(const struct ruleset_attr *attr, unsigned int flags) {
    return (int)syscall(PI_LL_CREATE, attr, sizeof(*attr), flags);
}

static int ll_create_old(const struct ruleset_attr *attr, unsigned int abi) {
    return (int)syscall(PI_LL_CREATE, attr, abi);
}

static int ll_add_rule_new(int ruleset_fd, const struct pb_new *pb) {
    return (int)syscall(PI_LL_ADD_RULE, ruleset_fd, RULE_PATH_BENEATH, pb, 0U);
}

static int ll_add_rule_old(int ruleset_fd, const struct pb_old *pb) {
    return (int)syscall(PI_LL_ADD_RULE, ruleset_fd, RULE_PATH_BENEATH, pb, 0U);
}

static int ll_restrict_self(int ruleset_fd) {
    return (int)syscall(PI_LL_RESTRICT_SELF, ruleset_fd, 0U);
}

/* New-convention ABI version query; -1 on old-convention kernels (where the
 * call is misread as (attr=NULL, abi=0) and rejected with EINVAL). */
static int query_new_version(void) {
    return (int)syscall(PI_LL_CREATE, (void *)0, 0, CREATE_RULESET_VERSION);
}

static unsigned long long handled_set(int abi) {
    unsigned long long handled = A_READ_FILE | A_WRITE_FILE | A_EXECUTE | A_READ_DIR |
                                 A_REMOVE_FILE | A_RENAME_FILE | A_MAKE_EXEC;
    if (abi >= 2)
        handled |= A_IOCTL_DEV | A_TRUNCATE;
    if (abi >= 3)
        handled |= A_REFER;
    return handled;
}

int main(int argc, char **argv) {
    const char *rw_paths[MAX_RW_PATHS];
    int n_rw = 0;
    int i;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0)
            break;
        if (strcmp(argv[i], "--rw") == 0 && i + 1 < argc) {
            if (n_rw >= MAX_RW_PATHS) {
                fprintf(stderr, "pi-sandbox-landlock: too many --rw paths (max %d)\n", MAX_RW_PATHS);
                return 2;
            }
            rw_paths[n_rw++] = argv[++i];
        } else {
            fprintf(stderr, "usage: pi-sandbox-landlock [--rw PATH]... -- COMMAND [ARGS...]\n");
            return 2;
        }
    }
    if (i >= argc || i + 1 >= argc) {
        fprintf(stderr, "usage: pi-sandbox-landlock [--rw PATH]... -- COMMAND [ARGS...]\n");
        return 2;
    }
    i += 1; /* skip "--"; argv[i] is the command, argv[i+1..] its args */

    int new_style = query_new_version();
    int abi;
    int ruleset;
    if (new_style >= 1) {
        abi = new_style;
        struct ruleset_attr attr = {handled_set(abi), 0};
        ruleset = ll_create_new(&attr, 0);
        if (ruleset < 0) {
            fprintf(stderr, "pi-sandbox-landlock: landlock_create_ruleset: %s\n", strerror(errno));
            return 3;
        }
    } else {
        /* Old convention: probe the highest supported ABI (kernel rejects
         * higher ABIs with EINVAL). */
        struct ruleset_attr probe = {A_READ_FILE, 0};
        abi = 0;
        for (int candidate = 5; candidate >= 1; candidate--) {
            int fd = ll_create_old(&probe, (unsigned int)candidate);
            if (fd >= 0) {
                abi = candidate;
                close(fd);
                break;
            }
            if (errno != EINVAL) {
                fprintf(stderr, "pi-sandbox-landlock: landlock_create_ruleset: %s\n", strerror(errno));
                return 3;
            }
        }
        if (abi == 0) {
            fprintf(stderr, "pi-sandbox-landlock: kernel does not support Landlock (need >= 5.13)\n");
            return 3;
        }
        struct ruleset_attr attr = {handled_set(abi), 0};
        ruleset = ll_create_old(&attr, (unsigned int)abi);
        if (ruleset < 0) {
            fprintf(stderr, "pi-sandbox-landlock: landlock_create_ruleset: %s\n", strerror(errno));
            return 3;
        }
    }

    unsigned long long ro_access = A_READ_FILE | A_READ_DIR | A_EXECUTE;
    unsigned long long rw_access = handled_set(abi);

    /* Rule 1: everything is readable and executable. */
    int root_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        fprintf(stderr, "pi-sandbox-landlock: open /: %s\n", strerror(errno));
        return 3;
    }
    if (new_style >= 1) {
        struct pb_new pb = {ro_access, root_fd};
        if (ll_add_rule_new(ruleset, &pb) < 0) {
            fprintf(stderr, "pi-sandbox-landlock: add_rule /: %s\n", strerror(errno));
            return 3;
        }
    } else {
        struct pb_old pb = {root_fd, (unsigned int)ro_access};
        if (ll_add_rule_old(ruleset, &pb) < 0) {
            fprintf(stderr, "pi-sandbox-landlock: add_rule /: %s\n", strerror(errno));
            return 3;
        }
    }
    close(root_fd);

    /* Rules 2..n: each --rw path is fully accessible. */
    for (int k = 0; k < n_rw; k++) {
        int fd = open(rw_paths[k], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) {
            fprintf(stderr, "pi-sandbox-landlock: open %s: %s (must be an existing directory)\n",
                    rw_paths[k], strerror(errno));
            return 3;
        }
        int err;
        if (new_style >= 1) {
            struct pb_new pb = {rw_access, fd};
            err = ll_add_rule_new(ruleset, &pb);
        } else {
            struct pb_old pb = {fd, (unsigned int)rw_access};
            err = ll_add_rule_old(ruleset, &pb);
        }
        if (err < 0) {
            fprintf(stderr, "pi-sandbox-landlock: add_rule %s: %s\n", rw_paths[k], strerror(errno));
            return 3;
        }
        close(fd);
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        fprintf(stderr, "pi-sandbox-landlock: prctl(PR_SET_NO_NEW_PRIVS): %s\n", strerror(errno));
        return 3;
    }
    if (ll_restrict_self(ruleset) < 0) {
        fprintf(stderr, "pi-sandbox-landlock: landlock_restrict_self: %s\n", strerror(errno));
        return 3;
    }

    execvp(argv[i], &argv[i]);
    /* Only reached on exec failure. */
    fprintf(stderr, "pi-sandbox-landlock: exec %s: %s\n", argv[i], strerror(errno));
    return 127;
}
