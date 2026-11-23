/*
 * ex_fw.c — `fw`, the CactOS firewall tool.
 *
 * Configures the kernel packet filter and NAT ( /dev/net, CACT_NETCTL_FW_* ):
 *
 *   fw show [CHAIN]              list rules (with counters) and policies
 *   fw add CHAIN ACTION [MATCH]  append a rule
 *   fw del CHAIN INDEX           delete rule INDEX of CHAIN
 *   fw flush CHAIN               remove every rule of CHAIN
 *   fw policy CHAIN ACCEPT|DROP  set a chain's default policy
 *   fw reset                     flush every chain, reset every policy
 *   fw conn [flush]              list (or forget) tracked connections
 *   fw load [FILE]               reset, then apply FILE (default /etc/fw.conf)
 *   fw save [FILE]               write the current rules to FILE
 *
 * CHAIN is input|output|forward|prerouting|postrouting (case-insensitive).  A
 * MATCH is any of:
 *   -p|--proto PROTO        tcp|udp|icmp|icmpv6|any|<number>
 *   -s|--src ADDR[/PREFIX]  source address
 *   -d|--dst ADDR[/PREFIX]  destination address
 *      --sport MIN[-MAX]    TCP/UDP source port (or range)
 *      --dport MIN[-MAX]    TCP/UDP destination port (or range)
 *   -i|--in-iface N         interface slot number
 *      --icmp-type N        ICMP/ICMPv6 type
 *      --state LIST         new,established,related (comma-separated)
 *   --to ADDR[:PORT]        translation target address/port (SNAT/DNAT/REDIRECT)
 *
 * The config file holds one command per line, the same syntax as after `fw`
 * (e.g. `add input accept --state established,related`), with `#` comments.
 */

#include <stdint.h>
#include <stddef.h>

#include <ioctl_abi.h>
#include <nodeio.h>
#include <socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

/* ── output ─────────────────────────────────────────────────────────────── */

static void w(const char *s)  { write(STDOUT_FILENO, s, strlen(s)); }
static void we(const char *s) { write(STDERR_FILENO, s, strlen(s)); }
static void wn(int v)  { char b[16]; itoa(v, b); w(b); }
static void wne(int v) { char b[16]; itoa(v, b); we(b); }
static void wp(const char *s, int width) {
    int n = (int)strlen(s);
    w(s);
    for (; n < width; n++) w(" ");
}

static unsigned long a2u(const char *s) {
    unsigned long v = 0;
    while (*s >= '0' && *s <= '9') v = v * 10 + (unsigned long)(*s++ - '0');
    return v;
}

/* ── names <-> ids ──────────────────────────────────────────────────────── */

struct named { const char *name; int id; };

static const struct named chains[] = {
    {"input", CACT_FW_CHAIN_INPUT}, {"output", CACT_FW_CHAIN_OUTPUT},
    {"forward", CACT_FW_CHAIN_FORWARD}, {"prerouting", CACT_FW_CHAIN_PREROUTING},
    {"postrouting", CACT_FW_CHAIN_POSTROUTING}, {NULL, 0},
};
static const struct named actions[] = {
    {"accept", CACT_FW_ACTION_ACCEPT}, {"drop", CACT_FW_ACTION_DROP},
    {"snat", CACT_FW_ACTION_SNAT}, {"dnat", CACT_FW_ACTION_DNAT},
    {"masquerade", CACT_FW_ACTION_MASQUERADE}, {"redirect", CACT_FW_ACTION_REDIRECT},
    {NULL, 0},
};
static const struct named protos[] = {
    {"tcp", CACT_FW_PROTO_TCP}, {"udp", CACT_FW_PROTO_UDP},
    {"icmp", CACT_FW_PROTO_ICMP}, {"icmpv6", CACT_FW_PROTO_ICMPV6},
    {"any", CACT_FW_PROTO_ANY}, {NULL, 0},
};
struct states { const char *name; int bit; };
static const struct states statel[] = {
    {"new", CACT_FW_STATE_NEW}, {"established", CACT_FW_STATE_ESTABLISHED},
    {"related", CACT_FW_STATE_RELATED}, {NULL, 0},
};

static int ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == '\0' && *b == '\0';
}

static int id_of(const struct named *t, const char *name) {
    for (; t->name; t++)
        if (ieq(t->name, name)) return t->id;
    return -1;
}
static const char *name_of(const struct named *t, int id) {
    for (; t->name; t++)
        if (t->id == id) return t->name;
    return "?";
}

/* ── small parsers ──────────────────────────────────────────────────────── */

/* "80", "80-90" or "80:" -> port range; min==0 means "any". */
static int parse_range(const char *s, uint16_t *min, uint16_t *max) {
    *min = 0; *max = 0;
    if (!*s) return 0;
    *min = (uint16_t)a2u(s);
    while (*s >= '0' && *s <= '9') s++;
    if (*s == '-') { *max = (uint16_t)a2u(s + 1); }
    else if (*s == '\0') { *max = *min; }
    else return 0;
    return 1;
}

/* Parse an address with an optional /prefix; out is 16 bytes, *family is 4/6. */
static int parse_addr(const char *s, uint8_t out[16], int *family, int *prefix) {
    char buf[64];
    size_t n = strlen(s);
    const char *slash = strchr(s, '/');
    if (slash) n = (size_t)(slash - s);
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, s, n);
    buf[n] = '\0';
    *prefix = -1;
    if (slash) *prefix = (int)a2u(slash + 1);

    memset(out, 0, 16);
    if (strchr(buf, ':')) {
        if (inet_pton(AF_INET6, buf, out) != 1) return 0;
        *family = 6;
        if (*prefix < 0) *prefix = 128;
    } else {
        if (inet_pton(AF_INET, buf, out) != 1) return 0;
        *family = 4;
        if (*prefix < 0) *prefix = 32;
    }
    return 1;
}

/* "addr", "addr:port" (v4) or "[addr]:port" (v6) -> address + port. */
static int parse_to(const char *s, uint8_t out[16], int *family, uint16_t *port) {
    *port = 0;
    if (s[0] == '[') {
        const char *close = strchr(s, ']');
        char addr[64];
        size_t n;
        if (!close) return 0;
        n = (size_t)(close - s - 1);
        if (n >= sizeof(addr)) return 0;
        memcpy(addr, s + 1, n);
        addr[n] = '\0';
        memset(out, 0, 16);
        if (inet_pton(AF_INET6, addr, out) != 1) return 0;
        *family = 6;
        if (close[1] == ':') *port = (uint16_t)a2u(close + 2);
        return 1;
    }
    const char *colon = strchr(s, ':');
    if (colon) {   /* v4 with a port */
        char addr[64];
        size_t n = (size_t)(colon - s);
        if (n >= sizeof(addr)) return 0;
        memcpy(addr, s, n);
        addr[n] = '\0';
        memset(out, 0, 16);
        if (inet_pton(AF_INET, addr, out) != 1) return 0;
        *family = 4;
        *port = (uint16_t)a2u(colon + 1);
        return 1;
    }
    int pfx;
    return parse_addr(s, out, family, &pfx);
}

static int parse_states(const char *s, int *mask) {
    int m = 0;
    while (*s) {
        char tok[32];
        size_t n = 0;
        while (*s && *s != ',' && n + 1 < sizeof(tok)) tok[n++] = *s++;
        tok[n] = '\0';
        if (*s == ',') s++;
        if (n == 0) return 0;
        int bit = 0;
        for (const struct states *st = statel; st->name; st++)
            if (ieq(st->name, tok)) { bit = st->bit; break; }
        if (!bit) return 0;
        m |= bit;
    }
    *mask = m;
    return m != 0;
}

/* Decimal formatting for the 64-bit rule counters. */
static void u64_to_dec(uint64_t v, char *out) {
    char tmp[24];
    int n = 0, i = 0;
    if (v == 0) tmp[n++] = '0';
    while (v) { tmp[n++] = (char)('0' + (int)(v % 10)); v /= 10; }
    while (n) out[i++] = tmp[--n];
    out[i] = '\0';
}

/* ── address / conn printing ────────────────────────────────────────────── */

static void print_addr(int family, const uint8_t a[16]) {
    char b[64];
    if (family == 6) {
        if (inet_ntop(AF_INET6, a, b, sizeof(b))) w(b);
        else w("?");
    } else {
        char p[8];
        for (int i = 0; i < 4; i++) {
            itoa(a[i], p); w(p);
            if (i < 3) w(".");
        }
    }
}

static void print_addr_prefix(int family, const uint8_t a[16], int prefix) {
    print_addr(family, a);
    if ((family == 4 && prefix != 32) || (family == 6 && prefix != 128)) {
        w("/"); wn(prefix);
    }
}

/* ── device calls ───────────────────────────────────────────────────────── */

static int dev(int cmd, void *arg) {
    int rc = nio_dev_cmd("net", (unsigned long)cmd, arg);
    return rc;
}

/* ── commands ───────────────────────────────────────────────────────────── */

static const char usage[] =
    "usage: fw <command>\n"
    "  fw show [CHAIN]              list rules and policies\n"
    "  fw add CHAIN ACTION [MATCH]  append a rule\n"
    "  fw del CHAIN INDEX           delete a rule\n"
    "  fw flush CHAIN               remove every rule in CHAIN\n"
    "  fw policy CHAIN ACCEPT|DROP  set CHAIN's default policy\n"
    "  fw reset                     flush all chains, reset policies\n"
    "  fw conn [flush]              list (or forget) tracked connections\n"
    "  fw load [FILE]               reset, then apply FILE (default /etc/fw.conf)\n"
    "  fw save [FILE]               write the current rules to FILE\n"
    "CHAIN: input|output|forward|prerouting|postrouting\n"
    "MATCH: -p PROTO -s ADDR[/P] -d ADDR[/P] --sport R --dport R\n"
    "       -i IFACE --icmp-type N --state LIST --to ADDR[:PORT]\n";

static void print_rule(unsigned idx, const cact_fw_rule_t *r) {
    char b[24];
    itoa((int)idx, b);
    wp(b, 4);
    wp(name_of(actions, r->action), 11);
    if (r->proto != CACT_FW_PROTO_ANY) { w(name_of(protos, r->proto)); w(" "); }
    if (r->has_src) { w("src "); print_addr_prefix(r->family ? r->family : 4, r->src, r->src_prefix); w(" "); }
    if (r->has_dst) { w("dst "); print_addr_prefix(r->family ? r->family : 4, r->dst, r->dst_prefix); w(" "); }
    if (r->dst_port_min) {
        w("dport ");
        if (r->dst_port_min == r->dst_port_max) { wn(r->dst_port_min); }
        else { wn(r->dst_port_min); w("-"); wn(r->dst_port_max); }
        w(" ");
    }
    if (r->src_port_min) {
        w("sport ");
        if (r->src_port_min == r->src_port_max) { wn(r->src_port_min); }
        else { wn(r->src_port_min); w("-"); wn(r->src_port_max); }
        w(" ");
    }
    if (r->in_iface != CACT_FW_IFACE_ANY) { w("in "); wn(r->in_iface); w(" "); }
    if (r->icmp_type != CACT_FW_ICMP_ANY) { w("icmp-type "); wn(r->icmp_type); w(" "); }
    if (r->state_mask) {
        w("state ");
        if (r->state_mask & CACT_FW_STATE_NEW) w("NEW,");
        if (r->state_mask & CACT_FW_STATE_ESTABLISHED) w("ESTABLISHED,");
        if (r->state_mask & CACT_FW_STATE_RELATED) w("RELATED,");
    }
    if (r->nat_port) { w("to-port "); wn(r->nat_port); w(" "); }
    w("[pkts ");
    u64_to_dec(r->packets, b);
    w(b);
    w(" bytes ");
    u64_to_dec(r->bytes, b);
    w(b);
    w("]\n");
}

static int cmd_show(int argc, char **argv) {
    int only = -1;
    if (argc > 0) {
        only = id_of(chains, argv[0]);
        if (only < 0) { we("fw: unknown chain `"); we(argv[0]); we("`\n"); return 1; }
    }
    for (int ch = 0; ch < CACT_FW_CHAIN_COUNT; ch++) {
        if (only >= 0 && ch != only) continue;
        cact_fw_chain_arg_t ca;
        ca.chain = (uint32_t)ch;
        int count = dev(CACT_NETCTL_FW_RULE_COUNT, &ca);
        int policy = dev(CACT_NETCTL_FW_POLICY_GET, &ca);
        w(name_of(chains, ch));
        w("  (policy ");
        w(policy >= 0 ? name_of(actions, policy) : "?");
        w(", ");
        wn(count < 0 ? 0 : count);
        w(count == 1 ? " rule)\n" : " rules)\n");
        for (int i = 0; i < count; i++) {
            cact_fw_get_arg_t a;
            memset(&a, 0, sizeof(a));
            a.chain = (uint32_t)ch;
            a.index = (uint32_t)i;
            if (dev(CACT_NETCTL_FW_RULE_GET, &a) == 0)
                print_rule((unsigned)i, &a.rule);
        }
    }
    return 0;
}

static int cmd_conn(int argc, char **argv) {
    if (argc > 0 && ieq(argv[0], "flush")) {
        int rc = dev(CACT_NETCTL_FW_CONN_FLUSH, NULL);
        if (rc < 0) { we("fw: conn flush failed rc="); wne(rc); we(" (need root?)\n"); return 1; }
        return 0;
    }
    int count = dev(CACT_NETCTL_FW_CONN_COUNT, NULL);
    w("conntrack: ");
    wn(count < 0 ? 0 : count);
    w(" flow(s)\n");
    for (int i = 0; i < count; i++) {
        cact_fw_conn_get_arg_t a;
        memset(&a, 0, sizeof(a));
        a.index = (uint32_t)i;
        if (dev(CACT_NETCTL_FW_CONN_GET, &a) != 0) continue;
        const cact_fw_conn_t *c = &a.conn;
        w("  ");
        print_addr(c->family, c->src);
        w(":"); wn(c->sport);
        w(" -> ");
        print_addr(c->family, c->dst);
        w(":"); wn(c->dport);
        w("  ");
        w(name_of(protos, c->proto));
        if (c->state & CACT_FW_STATE_ESTABLISHED) w(" ESTABLISHED");
        else if (c->state & CACT_FW_STATE_RELATED) w(" RELATED");
        else w(" NEW");
        w("  age "); wn((int)c->age_ms); w("ms");
        if (c->xdst[0] || c->xdst[15] || c->xsrc[0] || c->xsrc[15]) {
            w("  nat ");
            print_addr(c->family, c->xsrc);
            w(":"); wn(c->xsport);
            w("->");
            print_addr(c->family, c->xdst);
            w(":"); wn(c->xdport);
        }
        w("\n");
    }
    return 0;
}

/* Parse a MATCH list into `r` (addresses, ports, proto, state, NAT target). */
static int parse_match(cact_fw_rule_t *r, int argc, char **argv) {
    for (int i = 0; i < argc; i++) {
        const char *k = argv[i];
        const char *v = (i + 1 < argc) ? argv[i + 1] : NULL;
        if (ieq(k, "-p") || ieq(k, "--proto")) {
            if (!v) return 0;
            int id = id_of(protos, v);
            r->proto = (uint8_t)(id >= 0 ? id : (int)a2u(v));
            i++;
        } else if (ieq(k, "-s") || ieq(k, "--src")) {
            int fam, pfx;
            if (!v || !parse_addr(v, r->src, &fam, &pfx)) return 0;
            r->has_src = 1; r->src_prefix = (uint8_t)pfx;
            if (r->family == 0) r->family = (uint8_t)fam;
            i++;
        } else if (ieq(k, "-d") || ieq(k, "--dst")) {
            int fam, pfx;
            if (!v || !parse_addr(v, r->dst, &fam, &pfx)) return 0;
            r->has_dst = 1; r->dst_prefix = (uint8_t)pfx;
            if (r->family == 0) r->family = (uint8_t)fam;
            i++;
        } else if (ieq(k, "--sport")) {
            if (!v || !parse_range(v, &r->src_port_min, &r->src_port_max)) return 0;
            i++;
        } else if (ieq(k, "--dport")) {
            if (!v || !parse_range(v, &r->dst_port_min, &r->dst_port_max)) return 0;
            i++;
        } else if (ieq(k, "-i") || ieq(k, "--in-iface")) {
            if (!v) return 0;
            r->in_iface = (uint8_t)a2u(v);
            i++;
        } else if (ieq(k, "--icmp-type")) {
            if (!v) return 0;
            r->icmp_type = (uint8_t)a2u(v);
            i++;
        } else if (ieq(k, "--state")) {
            int m;
            if (!v || !parse_states(v, &m)) return 0;
            r->state_mask = (uint8_t)m;
            i++;
        } else if (ieq(k, "--to")) {
            int fam; uint16_t port;
            if (!v || !parse_to(v, r->nat_addr, &fam, &port)) return 0;
            r->nat_port = port;
            i++;
        } else {
            return 0;
        }
    }
    return 1;
}

static int cmd_add(int argc, char **argv) {
    if (argc < 2) { we("fw: add needs CHAIN and ACTION\n"); return 1; }
    cact_fw_rule_t r;
    memset(&r, 0, sizeof(r));
    r.icmp_type = CACT_FW_ICMP_ANY;
    r.in_iface = CACT_FW_IFACE_ANY;
    int ch = id_of(chains, argv[0]);
    int act = id_of(actions, argv[1]);
    if (ch < 0) { we("fw: unknown chain `"); we(argv[0]); we("`\n"); return 1; }
    if (act < 0) { we("fw: unknown action `"); we(argv[1]); we("`\n"); return 1; }
    r.chain = (uint8_t)ch;
    r.action = (uint8_t)act;
    if (!parse_match(&r, argc - 2, argv + 2)) {
        we("fw: bad match in rule\n");
        return 1;
    }
    int rc = dev(CACT_NETCTL_FW_RULE_ADD, &r);
    if (rc < 0) { we("fw: add failed rc="); wne(rc); we(" (need root?)\n"); return 1; }
    return 0;
}

static int cmd_del(int argc, char **argv) {
    if (argc < 2) { we("fw: del needs CHAIN and INDEX\n"); return 1; }
    int ch = id_of(chains, argv[0]);
    if (ch < 0) { we("fw: unknown chain `"); we(argv[0]); we("`\n"); return 1; }
    cact_fw_idx_arg_t a;
    a.chain = (uint32_t)ch;
    a.index = (uint32_t)a2u(argv[1]);
    int rc = dev(CACT_NETCTL_FW_RULE_DEL, &a);
    if (rc < 0) { we("fw: del failed rc="); wne(rc); we("\n"); return 1; }
    return 0;
}

static int cmd_flush(int argc, char **argv) {
    if (argc < 1) { we("fw: flush needs CHAIN\n"); return 1; }
    int ch = id_of(chains, argv[0]);
    if (ch < 0) { we("fw: unknown chain `"); we(argv[0]); we("`\n"); return 1; }
    cact_fw_chain_arg_t a;
    a.chain = (uint32_t)ch;
    int rc = dev(CACT_NETCTL_FW_FLUSH, &a);
    if (rc < 0) { we("fw: flush failed rc="); wne(rc); we(" (need root?)\n"); return 1; }
    return 0;
}

static int cmd_policy(int argc, char **argv) {
    if (argc < 2) { we("fw: policy needs CHAIN and ACCEPT|DROP\n"); return 1; }
    int ch = id_of(chains, argv[0]);
    int pol = id_of(actions, argv[1]);
    if (ch < 0 || (pol != CACT_FW_ACTION_ACCEPT && pol != CACT_FW_ACTION_DROP)) {
        we("fw: policy takes CHAIN and ACCEPT|DROP\n");
        return 1;
    }
    cact_fw_policy_arg_t a;
    a.chain = (uint32_t)ch;
    a.policy = (uint32_t)pol;
    int rc = dev(CACT_NETCTL_FW_POLICY_SET, &a);
    if (rc < 0) { we("fw: policy failed rc="); wne(rc); we(" (need root?)\n"); return 1; }
    return 0;
}

static int cmd_reset(void) {
    int rc = dev(CACT_NETCTL_FW_RESET, NULL);
    if (rc < 0) { we("fw: reset failed rc="); wne(rc); we(" (need root?)\n"); return 1; }
    return 0;
}

/* ── config file ────────────────────────────────────────────────────────── */

#define FW_CONF_DEFAULT "/etc/fw.conf"

static const char default_config[] =
    "# fw config — one command per line, the same syntax as after `fw`.\n"
    "# Applied with `fw load`.  Examples:\n"
    "#\n"
    "#   policy input drop\n"
    "#   add input accept --state established,related\n"
    "#   add input accept -p tcp --dport 22\n"
    "#   add postrouting masquerade -i 0\n"
    "#   add prerouting dnat -p tcp --dport 8080 --to 10.0.0.5:80\n";

static int read_file(const char *path, char *buf, int cap) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    int n = (int)read(fd, buf, (size_t)(cap - 1));
    close(fd);
    if (n < 0) return -1;
    buf[n] = '\0';
    return n;
}

/* Split `line` into whitespace-separated tokens; returns the count. */
static int tokenize(char *line, char **tok, int maxtok) {
    int n = 0;
    char *p = line;
    while (*p && n < maxtok) {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
        if (!*p) break;
        tok[n++] = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
        if (*p) *p++ = '\0';
    }
    return n;
}

/* Dispatch one already-tokenized command (as after `fw`). */
static int run_command(int argc, char **argv) {
    if (argc == 0) return 0;
    if (ieq(argv[0], "add")) return cmd_add(argc - 1, argv + 1);
    if (ieq(argv[0], "del")) return cmd_del(argc - 1, argv + 1);
    if (ieq(argv[0], "flush")) return cmd_flush(argc - 1, argv + 1);
    if (ieq(argv[0], "policy")) return cmd_policy(argc - 1, argv + 1);
    if (ieq(argv[0], "reset")) return cmd_reset();
    we("fw: unknown config command `"); we(argv[0]); we("`\n");
    return 1;
}

static int cmd_load(int argc, char **argv) {
    const char *path = (argc > 0) ? argv[0] : FW_CONF_DEFAULT;
    static char buf[8192];
    int n = read_file(path, buf, (int)sizeof(buf));
    if (n < 0 && argc == 0) {
        /* First run: seed the default config, then load it (an empty rule set). */
        int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, default_config, sizeof(default_config) - 1);
            close(fd);
            n = read_file(path, buf, (int)sizeof(buf));
        }
    }
    if (n < 0) { we("fw: cannot read "); we(path); we("\n"); return 1; }
    if (cmd_reset() != 0) return 1;

    int rc = 0;
    char *p = buf;
    while (*p) {
        char *eol = p;
        while (*eol && *eol != '\n') eol++;
        char saved = *eol;
        *eol = '\0';
        /* Strip a trailing comment and whitespace-only/# lines. */
        for (char *c = p; *c; c++) if (*c == '#') { *c = '\0'; break; }
        char *tok[24];
        int nt = tokenize(p, tok, 24);
        if (nt > 0 && run_command(nt, tok) != 0) rc = 1;
        if (!saved) break;
        p = eol + 1;
    }
    return rc;
}

static int write_str(int fd, const char *s) { return (int)write(fd, s, strlen(s)); }
static void write_int(int fd, int v) { char b[16]; itoa(v, b); write_str(fd, b); }

static void save_rule(int fd, const cact_fw_rule_t *r) {
    write_str(fd, "add ");
    write_str(fd, name_of(chains, r->chain));
    write_str(fd, " ");
    write_str(fd, name_of(actions, r->action));
    if (r->proto != CACT_FW_PROTO_ANY) { write_str(fd, " -p "); write_str(fd, name_of(protos, r->proto)); }
    if (r->has_src) {
        char b[64];
        write_str(fd, " -s ");
        inet_ntop(r->family == 6 ? AF_INET6 : AF_INET, r->src, b, sizeof(b));
        write_str(fd, b);
        if ((r->family == 6 && r->src_prefix != 128) || (r->family != 6 && r->src_prefix != 32)) {
            write_str(fd, "/"); write_int(fd, r->src_prefix);
        }
    }
    if (r->has_dst) {
        char b[64];
        write_str(fd, " -d ");
        inet_ntop(r->family == 6 ? AF_INET6 : AF_INET, r->dst, b, sizeof(b));
        write_str(fd, b);
        if ((r->family == 6 && r->dst_prefix != 128) || (r->family != 6 && r->dst_prefix != 32)) {
            write_str(fd, "/"); write_int(fd, r->dst_prefix);
        }
    }
    if (r->src_port_min) { write_str(fd, " --sport "); write_int(fd, r->src_port_min);
        if (r->src_port_max != r->src_port_min) { write_str(fd, "-"); write_int(fd, r->src_port_max); } }
    if (r->dst_port_min) { write_str(fd, " --dport "); write_int(fd, r->dst_port_min);
        if (r->dst_port_max != r->dst_port_min) { write_str(fd, "-"); write_int(fd, r->dst_port_max); } }
    if (r->in_iface != CACT_FW_IFACE_ANY) { write_str(fd, " -i "); write_int(fd, r->in_iface); }
    if (r->icmp_type != CACT_FW_ICMP_ANY) { write_str(fd, " --icmp-type "); write_int(fd, r->icmp_type); }
    if (r->state_mask) {
        write_str(fd, " --state ");
        if (r->state_mask & CACT_FW_STATE_NEW) write_str(fd, "new,");
        if (r->state_mask & CACT_FW_STATE_ESTABLISHED) write_str(fd, "established,");
        if (r->state_mask & CACT_FW_STATE_RELATED) write_str(fd, "related,");
    }
    if (r->nat_port || r->nat_addr[0] || r->nat_addr[15]) {
        char b[64];
        write_str(fd, " --to ");
        inet_ntop(r->family == 6 ? AF_INET6 : AF_INET, r->nat_addr, b, sizeof(b));
        write_str(fd, b);
        if (r->nat_port) { write_str(fd, ":"); write_int(fd, r->nat_port); }
    }
    write_str(fd, "\n");
}

static int cmd_save(int argc, char **argv) {
    const char *path = (argc > 0) ? argv[0] : FW_CONF_DEFAULT;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { we("fw: cannot write "); we(path); we("\n"); return 1; }
    write_str(fd, "# fw rules — written by `fw save`.\n");
    for (int ch = 0; ch < CACT_FW_CHAIN_COUNT; ch++) {
        cact_fw_chain_arg_t ca;
        ca.chain = (uint32_t)ch;
        int policy = dev(CACT_NETCTL_FW_POLICY_GET, &ca);
        if (policy == CACT_FW_ACTION_DROP) {
            write_str(fd, "policy "); write_str(fd, name_of(chains, ch)); write_str(fd, " drop\n");
        }
        int count = dev(CACT_NETCTL_FW_RULE_COUNT, &ca);
        for (int i = 0; i < count; i++) {
            cact_fw_get_arg_t a;
            memset(&a, 0, sizeof(a));
            a.chain = (uint32_t)ch;
            a.index = (uint32_t)i;
            if (dev(CACT_NETCTL_FW_RULE_GET, &a) == 0)
                save_rule(fd, &a.rule);
        }
    }
    close(fd);
    return 0;
}

int cact_ub_fw(char **argv, int argc) {
    if (argc >= 2 && (ieq(argv[1], "--help") || ieq(argv[1], "-h"))) {
        w(usage);
        return 0;
    }
    if (argc < 2) {
        we(usage);
        return 1;
    }
    const char *cmd = argv[1];
    int sub_argc = argc - 2;
    char **sub = argv + 2;
    if (ieq(cmd, "show") || ieq(cmd, "list")) return cmd_show(sub_argc, sub);
    if (ieq(cmd, "add")) return cmd_add(sub_argc, sub);
    if (ieq(cmd, "del") || ieq(cmd, "delete")) return cmd_del(sub_argc, sub);
    if (ieq(cmd, "flush")) return cmd_flush(sub_argc, sub);
    if (ieq(cmd, "policy")) return cmd_policy(sub_argc, sub);
    if (ieq(cmd, "reset")) return cmd_reset();
    if (ieq(cmd, "conn") || ieq(cmd, "conntrack")) return cmd_conn(sub_argc, sub);
    if (ieq(cmd, "load")) return cmd_load(sub_argc, sub);
    if (ieq(cmd, "save")) return cmd_save(sub_argc, sub);
    we("fw: unknown command `"); we(cmd); we("`\n");
    we(usage);
    return 1;
}
