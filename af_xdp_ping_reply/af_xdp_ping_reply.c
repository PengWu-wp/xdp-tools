/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <locale.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/xsk.h>

#include <linux/err.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#define PROG_NAME "xdp-loader"

#define NUM_FRAMES         4096
#define FRAME_SIZE         XSK_UMEM__DEFAULT_FRAME_SIZE
#define RX_BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

/* XSK related structs */

struct xsk_umem_info {
    struct xsk_ring_prod fq; // fill ring
    struct xsk_ring_cons cq; // completion ring
    struct xsk_umem *umem;
    void *buffer; // buffer pointed to umem start address
};

struct stats_record {
    uint64_t timestamp;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct xsk_socket_info {
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_umem_info *umem;
    struct xsk_socket *xsk;

    uint64_t umem_frame_addr[NUM_FRAMES];
    uint32_t umem_frame_free;

    uint32_t outstanding_tx;

    struct stats_record stats;
    struct stats_record prev_stats;
};

static bool global_exit = false;
static int verbose = 1;

struct my_config {
    __u32 xdp_flags;
    struct iface iface;
    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
};

static const struct loadopt {
    bool help;
    struct iface iface;
    struct multistring filenames;
    char *pin_path;
    char *section_name;
    char *prog_name;
    enum xdp_attach_mode mode;
    __u16 xsk_bind_flags;
    __u32 xdp_flags;
    int xsk_if_queue;
    bool xsk_poll_mode;
    bool xsk_copy_mode;
    bool xsk_zero_copy_mode;
} defaults_load = {
        .mode = XDP_MODE_NATIVE,
        .xsk_bind_flags = XDP_COPY,
        .xdp_flags = XDP_FLAGS_SKB_MODE,
        .xsk_if_queue = 0,
        .xsk_poll_mode = false,
        .xsk_copy_mode = false,
        .xsk_zero_copy_mode = false
};
//enum xdp_attach_mode {
//    XDP_MODE_UNSPEC = 0,
//    XDP_MODE_NATIVE,
//    XDP_MODE_SKB,
//    XDP_MODE_HW
//};
struct enum_val xdp_modes[] = {
        {"native",      XDP_MODE_NATIVE},
        {"skb",         XDP_MODE_SKB},
        {"hw",          XDP_MODE_HW},
        {"unspecified", XDP_MODE_UNSPEC},
        {NULL,          0}
}; // 这是一个enum_val结构体数组

/** my functions **/

static inline __u16 compute_icmp_checksum(struct iphdr *ip, struct icmphdr *icmp) {
    __u32 csum = 0;
    __u16 *next_icmp_u16 = (__u16 *) icmp;
    icmp->checksum = 0;
    int tmp = ((ntohs(ip->tot_len) - (ip->ihl << 2)) >> 1);
    for (int i = 0; i < tmp; i++) {
        csum += *next_icmp_u16++;
    }
    return ~((csum & 0xffff) + (csum >> 16));
}


static struct xsk_umem_info *configure_xsk_umem(void *buffer, uint64_t size) {
    struct xsk_umem_info *umem;
    int ret;

    umem = calloc(1, sizeof(*umem));
    if (!umem)
        return NULL;

    ret = xsk_umem__create(&umem->umem, buffer, size, &umem->fq, &umem->cq,
                           NULL); // use NULL to use default cfg
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem->buffer = buffer;
    return umem;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
    uint64_t frame;
    if (xsk->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk->umem_frame_addr[--xsk->umem_frame_free];
    xsk->umem_frame_addr[xsk->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint64_t frame) {
    assert(xsk->umem_frame_free < NUM_FRAMES);

    xsk->umem_frame_addr[xsk->umem_frame_free++] = frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk) {
    return xsk->umem_frame_free;
}

static struct xsk_socket_info *xsk_configure_socket(struct my_config *opt,
                                                    struct xsk_umem_info *umem) {
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    uint32_t prog_id = 0;
    int i;
    int ret;

    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem = umem;
    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD; // INHIBIT load default xdp prog
    xsk_cfg.xdp_flags = opt->xdp_flags;
    xsk_cfg.bind_flags = opt->xsk_bind_flags;
    ret = xsk_socket__create(&xsk_info->xsk, opt->iface.ifname,
                             opt->xsk_if_queue, umem->umem, &xsk_info->rx,
                             &xsk_info->tx, &xsk_cfg);

    if (ret)
        goto error_exit;

    ret = bpf_xdp_query_id(opt->iface.ifindex, opt->xdp_flags, &prog_id);
    if (ret)
        goto error_exit;
    /* Initialize umem frame allocation */

    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    /* Stuff the receive path with buffers, we assume we have enough */
    ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
                                 XSK_RING_PROD__DEFAULT_NUM_DESCS,
                                 &idx);

    if (ret != XSK_RING_PROD__DEFAULT_NUM_DESCS)
        goto error_exit;

    for (i = 0; i < XSK_RING_PROD__DEFAULT_NUM_DESCS; i++)
        *xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
                xsk_alloc_umem_frame(xsk_info);

    xsk_ring_prod__submit(&xsk_info->umem->fq,
                          XSK_RING_PROD__DEFAULT_NUM_DESCS);

    return xsk_info;

    error_exit:
    errno = -ret;
    return NULL;
}


static void complete_tx(struct xsk_socket_info *xsk) {
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk->outstanding_tx)
        return;

    sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk->umem->cq,
                                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                    &idx_cq);

    if (completed > 0) {
        for (unsigned int i = 0; i < completed; i++)
            xsk_free_umem_frame(xsk,
                                *xsk_ring_cons__comp_addr(&xsk->umem->cq,
                                                          idx_cq++));

        xsk_ring_cons__release(&xsk->umem->cq, completed);
        xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
                               completed : xsk->outstanding_tx;
    }
}

static bool process_packet(struct xsk_socket_info *xsk,
                           uint64_t addr, uint32_t len) {
    uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);

    /* Lesson#3: Write an IPv6 ICMP ECHO parser to send responses
     *
     * Some assumptions to make it easier:
     * - No VLAN handling
     * - Only if nexthdr is ICMP
     * - Just return all data with MAC/IP swapped, and type set to
     *   ICMPV6_ECHO_REPLY
     * - Recalculate the icmp checksum */

    if (true) {
        int ret;
        uint32_t tx_idx = 0;
        uint8_t tmp_mac[ETH_ALEN];
        __be32 tmp_ip;
        struct ethhdr *eth = (struct ethhdr *) pkt;
        struct iphdr *ip = (struct iphdr *) (eth + 1);
        struct icmphdr *icmp = (struct icmphdr *) (ip + 1);

        memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
        memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
        memcpy(eth->h_source, tmp_mac, ETH_ALEN);

        memcpy(&tmp_ip, &ip->saddr, sizeof(tmp_ip));
        memcpy(&ip->saddr, &ip->daddr, sizeof(tmp_ip));
        memcpy(&ip->daddr, &tmp_ip, sizeof(tmp_ip));

        icmp->type = ICMP_ECHOREPLY;

        /* ip checksum not affected. ignore */
        // ip->check = compute_ip_checksum(ip);

        icmp->checksum = compute_icmp_checksum(ip, icmp);

        /* Here we sent the packet out of the receive port. Note that
         * we allocate one entry and schedule it. Your design would be
         * faster if you do batch processing/transmission */

        ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
        if (ret != 1) {
            /* No more transmit slots, drop the packet */
            return false;
        }

        xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
        xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
        xsk_ring_prod__submit(&xsk->tx, 1);
        xsk->outstanding_tx++;

        xsk->stats.tx_bytes += len;
        xsk->stats.tx_packets++;
        return true;
    }

    return false;
}

static void handle_receive_packets(struct xsk_socket_info *xsk) {
    unsigned int rcvd, stock_frames, i;
    uint32_t idx_rx = 0, idx_fq = 0;
    int ret;

    rcvd = xsk_ring_cons__peek(&xsk->rx, RX_BATCH_SIZE, &idx_rx);
    if (!rcvd)
        return;

    /* Stuff the ring with as much frames as possible */
    stock_frames = xsk_prod_nb_free(&xsk->umem->fq,
                                    xsk_umem_free_frames(xsk));

    if (stock_frames > 0) {

        ret = xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames,
                                     &idx_fq);

        /* This should not happen, but just in case */
        while ((unsigned int) ret != stock_frames)
            ret = xsk_ring_prod__reserve(&xsk->umem->fq, rcvd,
                                         &idx_fq);

        for (i = 0; i < stock_frames; i++)
            *xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
                    xsk_alloc_umem_frame(xsk);

        xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
    }

    /* Process received packets */
    for (i = 0; i < rcvd; i++) {
        uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
        uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

        if (!process_packet(xsk, addr, len))
            xsk_free_umem_frame(xsk, addr);

        xsk->stats.rx_bytes += len;
    }

    xsk_ring_cons__release(&xsk->rx, rcvd);
    xsk->stats.rx_packets += rcvd;

    /* Do we need to wake up the kernel for transmission */
    complete_tx(xsk);
}

static void rx_and_process(struct my_config *opt,
                           struct xsk_socket_info *xsk_socket) {
    struct pollfd fds[2];
    int ret, nfds = 1;

    memset(fds, 0, sizeof(fds));
    fds[0].fd = xsk_socket__fd(xsk_socket->xsk);
    fds[0].events = POLLIN;

    while (!global_exit) {
        if (opt->xsk_poll_mode) {
            ret = poll(fds, nfds, -1);
            if (ret <= 0 || ret > 1)
                continue;
        }
        handle_receive_packets(xsk_socket);
    }
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */

static uint64_t gettime(void) {
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0) {
        fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
        exit(EXIT_FAILURE);
    }
    return (uint64_t) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct stats_record *r, struct stats_record *p) {
    double period_ = 0;
    __u64 period = 0;

    period = r->timestamp - p->timestamp;
    if (period > 0)
        period_ = ((double) period / NANOSEC_PER_SEC);

    return period_;
}

static void stats_print(struct stats_record *stats_rec,
                        struct stats_record *stats_prev) {
    uint64_t packets, bytes;
    double period;
    double pps; /* packets per sec */
    double bps; /* bits per sec */

    char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
                " %'11lld Kbytes (%'6.0f Mbits/s)"
                " period:%f\n";

    period = calc_period(stats_rec, stats_prev);
    if (period == 0)
        period = 1;

    packets = stats_rec->rx_packets - stats_prev->rx_packets;
    pps = packets / period;

    bytes = stats_rec->rx_bytes - stats_prev->rx_bytes;
    bps = (bytes * 8) / period / 1000000;

    printf(fmt, "AF_XDP RX:", stats_rec->rx_packets, pps,
           stats_rec->rx_bytes / 1000, bps,
           period);

    packets = stats_rec->tx_packets - stats_prev->tx_packets;
    pps = packets / period;

    bytes = stats_rec->tx_bytes - stats_prev->tx_bytes;
    bps = (bytes * 8) / period / 1000000;

    printf(fmt, "       TX:", stats_rec->tx_packets, pps,
           stats_rec->tx_bytes / 1000, bps,
           period);

    printf("\n");
}

static void *stats_poll(void *arg) {
    unsigned int interval = 2;
    struct xsk_socket_info *xsk = arg;
    static struct stats_record previous_stats = {0};

    previous_stats.timestamp = gettime();

    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    while (!global_exit) {
        sleep(interval);
        xsk->stats.timestamp = gettime();
        stats_print(&xsk->stats, &previous_stats);
        previous_stats = xsk->stats;
    }
    return NULL;
}

static void exit_application(int signal) {
    signal = signal;
    global_exit = true;
}

/** end of my functions **/






static const struct unloadopt {
    bool all;
    __u32 prog_id;
    struct iface iface;
} defaults_unload = {};


static struct prog_option unload_options[] = {
        DEFINE_OPTION("dev", OPT_IFNAME, struct unloadopt, iface,
        .positional = true,
        .metavar = "<ifname>",
        .help = "Unload from device <ifname>"),
        DEFINE_OPTION("id", OPT_U32, struct unloadopt, prog_id,
        .metavar = "<id>",
        .short_opt = 'i',
        .help = "Unload program with id <id>"),
        DEFINE_OPTION("all", OPT_BOOL, struct unloadopt, all,
        .short_opt = 'a',
        .help = "Unload all programs from interface"),
        END_OPTIONS
};

int do_unload(const void *cfg, __unused const char *pin_root_path) {
    const struct unloadopt *opt = cfg;
    struct xdp_multiprog *mp = NULL;
    enum xdp_attach_mode mode;
    int err = EXIT_FAILURE;
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
            .pin_root_path = pin_root_path);

    if (!opt->all && !opt->prog_id) {
        pr_warn("Need prog ID or --all\n");
        goto out;
    }

    if (!opt->iface.ifindex) {
        pr_warn("Must specify ifname\n");
        goto out;
    }


    mp = xdp_multiprog__get_from_ifindex(opt->iface.ifindex);
    if (IS_ERR_OR_NULL(mp)) {
        pr_warn("No XDP program loaded on %s\n", opt->iface.ifname);
        mp = NULL;
        goto out;
    }

    if (opt->all) {
        err = xdp_multiprog__detach(mp);
        if (err) {
            pr_warn("Unable to detach XDP program: %s\n",
                    strerror(-err));
            goto out;
        }
    } else {
        struct xdp_program *prog = NULL;

        while ((prog = xdp_multiprog__next_prog(prog, mp))) {
            if (xdp_program__id(prog) == opt->prog_id) {
                mode = xdp_multiprog__attach_mode(mp);
                goto found;
            }
        }

        if (xdp_multiprog__is_legacy(mp)) {
            prog = xdp_multiprog__main_prog(mp);
            if (xdp_program__id(prog) == opt->prog_id) {
                mode = xdp_multiprog__attach_mode(mp);
                goto found;
            }
        }

        prog = xdp_multiprog__hw_prog(mp);
        if (xdp_program__id(prog) == opt->prog_id) {
            mode = XDP_MODE_HW;
            goto found;
        }

        pr_warn("Program with ID %u not loaded on %s\n",
                opt->prog_id, opt->iface.ifname);
        err = -ENOENT;
        goto out;

        found:
        pr_debug("Detaching XDP program with ID %u from %s\n",
                 xdp_program__id(prog), opt->iface.ifname);
        err = xdp_program__detach(prog, opt->iface.ifindex, mode, 0);
        if (err) {
            pr_warn("Unable to detach XDP program: %s\n",
                    strerror(-err));
            goto out;
        }
    }

    out:
    xdp_multiprog__close(mp);
    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}


static struct prog_option load_options[] = {
        DEFINE_OPTION("mode", OPT_ENUM, struct loadopt, mode,
        .short_opt = 'm',
        .typearg = xdp_modes,
        .metavar = "<mode>",
        .help = "Load XDP program in <mode>; default native"),

        DEFINE_OPTION("pin-path", OPT_STRING, struct loadopt, pin_path,
        .short_opt = 'p',
        .help = "Path to pin maps under (must be in bpffs)."),

        DEFINE_OPTION("section", OPT_STRING, struct loadopt, section_name,
        .metavar = "<section>",
        .short_opt = 's',
        .help = "ELF section name of program to load (default: first in file)."),

        DEFINE_OPTION("prog-name", OPT_STRING, struct loadopt, prog_name,
        .metavar = "<prog_name>",
        .short_opt = 'n',
        .help = "BPF program name of program to load (default: first in file)."),

        DEFINE_OPTION("dev", OPT_IFNAME, struct loadopt, iface,
        .positional = true,
        .metavar = "<ifname>",
        .required = true,
        .help = "Load on device <ifname>"),

        DEFINE_OPTION("filenames", OPT_MULTISTRING, struct loadopt, filenames,
        .positional = true,
        .metavar = "<filenames>",
        .required = true,
        .help = "Load programs from <filenames>"),

        DEFINE_OPTION("poll-mode", OPT_BOOL, struct loadopt, xsk_poll_mode,
        .short_opt = 'P',
        .required = false,
        .help = "Use the poll() API waiting for packets to arrive"),

        DEFINE_OPTION("copy", OPT_BOOL, struct loadopt, xsk_copy_mode,
        .short_opt = 'c',
        .required = false,
        .help = "Force copy mode"),

        DEFINE_OPTION("zero-copy", OPT_BOOL, struct loadopt, xsk_zero_copy_mode,
        .short_opt = 'z',
        .required = false,
        .help = "Force zero-copy mode"),

        DEFINE_OPTION("queue", OPT_U32, struct loadopt, xsk_if_queue,
        .short_opt = 'Q',
        .metavar = "<queue_id>",
        .required = false,
        .help = "Configure interface receive queue for AF_XDP, default=0"),

        END_OPTIONS
};


int do_load(const void *cfg, __unused const char *pin_root_path) {

    const struct loadopt *opt = cfg;
    struct my_config my_cfg;

    my_cfg.xsk_bind_flags = 0;
    if (opt->xsk_copy_mode && opt->xsk_zero_copy_mode) {
        pr_warn("Only one of --copy or --zero-copy can be set\n");
        return EXIT_FAILURE;
    } else if (opt->xsk_copy_mode) {
        my_cfg.xsk_bind_flags |= XDP_COPY;
    } else if (opt->xsk_zero_copy_mode) {
        if (opt->mode == XDP_MODE_SKB) {
            pr_warn("SKB mode does not support zero-copy mode\n");
            return EXIT_FAILURE;
        }
        my_cfg.xsk_bind_flags |= XDP_ZEROCOPY;
    }
    my_cfg.xsk_poll_mode = opt->xsk_poll_mode;
    my_cfg.xsk_if_queue = opt->xsk_if_queue;
    my_cfg.iface = opt->iface;
    my_cfg.xdp_flags = 0;
    switch (opt->mode) {
        case XDP_MODE_NATIVE:
            my_cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */// why we need clear it first?
            my_cfg.xdp_flags |= XDP_FLAGS_DRV_MODE;  /* Set   flag */
            break;
        case XDP_MODE_SKB:
            my_cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
            my_cfg.xdp_flags |= XDP_FLAGS_SKB_MODE;  /* Set   flag */
            break;
        case XDP_MODE_HW:
            my_cfg.xdp_flags &= ~XDP_FLAGS_MODES;    /* Clear flags */
            my_cfg.xdp_flags |= XDP_FLAGS_HW_MODE;  /* Set   flag */
            break;
        default:
            pr_warn("No XDP mode specified\n");
            return EXIT_FAILURE;
    }


    struct xdp_program **progs, *p;
    char errmsg[STRERR_BUFSIZE];
    int err = EXIT_SUCCESS;
    size_t num_progs, i;

    /** my additional variables **/
    struct xsk_umem_info *umem;
    void *packet_buffer;
    uint64_t packet_buffer_size;
    struct xsk_socket_info *xsk_socket;
    int xsks_map_fd;
    struct bpf_object *obj;
    pthread_t stats_poll_thread;
    /** end of my additional variables **/
    /* Global shutdown handler */
    signal(SIGINT, exit_application);

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
            .pin_root_path = opt->pin_path);

    if (opt->section_name && opt->prog_name) {
        pr_warn("Only one of --section or --prog-name can be set\n");
        return EXIT_FAILURE;
    }

    num_progs = opt->filenames.num_strings;
    if (!num_progs) {
        pr_warn("Need at least one filename to load\n");
        return EXIT_FAILURE;
    } else if (num_progs > 1 && opt->mode == XDP_MODE_HW) {
        pr_warn("Cannot attach multiple programs in HW mode\n");
        return EXIT_FAILURE;
    }


    /** Allocate memory for NUM_FRAMES of the default XDP frame size **/
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    if (posix_memalign(&packet_buffer,
                       getpagesize(), /* PAGE_SIZE aligned */
                       packet_buffer_size)) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /** Create UMEM **/
    umem = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (umem == NULL) {
        fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }


    /** Open and configure the AF_XDP (xsk) socket **/
    xsk_socket = xsk_configure_socket(&my_cfg, umem);
    if (xsk_socket == NULL) {
        fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }


    progs = calloc(num_progs, sizeof(*progs));
    if (!progs) {
        pr_warn("Couldn't allocate memory\n");
        return EXIT_FAILURE;
    }

    pr_debug("Loading %zu files on interface '%s'.\n",
             num_progs, opt->iface.ifname);

    /* libbpf spits out a lot of unhelpful error messages while loading.
     * Silence the logging so we can provide our own messages instead; this
     * is a noop if verbose logging is enabled.
     */
    silence_libbpf_logging();

    retry:
    for (i = 0; i < num_progs; i++) {
        DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

        p = progs[i];
        if (p)
            xdp_program__close(p);

        if (opt->prog_name) {
            xdp_opts.open_filename = opt->filenames.strings[i];
            xdp_opts.prog_name = opt->prog_name;
            xdp_opts.opts = &opts;

            p = xdp_program__create(&xdp_opts);
        } else {
            p = xdp_program__open_file(opt->filenames.strings[i],
                                       opt->section_name, &opts);
        }

        err = libxdp_get_error(p);
        if (err) {
            if (err == -EPERM && !double_rlimit())
                goto retry;

            libxdp_strerror(err, errmsg, sizeof(errmsg));
            pr_warn("Couldn't open file '%s': %s\n",
                    opt->filenames.strings[i], errmsg);
            goto out;
        }

        xdp_program__print_chain_call_actions(p, errmsg, sizeof(errmsg));
        pr_debug("XDP program %zu: Run prio: %d. Chain call actions: %s\n",
                 i, xdp_program__run_prio(p), errmsg);

        if (!opt->pin_path) {
            struct bpf_map *map;

            bpf_object__for_each_map(map, xdp_program__bpf_obj(p))
            {
                err = bpf_map__set_pin_path(map, NULL);
                if (err) {
                    pr_warn("Error clearing map pin path: %s\n",
                            strerror(-err));
                    goto out;
                }
            }
        }

        progs[i] = p;
    }







    /* Attach xdp program on interface */
    err = xdp_program__attach_multi(progs, num_progs,
                                    opt->iface.ifindex, opt->mode, 0);
    if (err) {
        if (err == -EPERM && !double_rlimit())
            goto retry;

        if (err == -EOPNOTSUPP &&
            (opt->mode == XDP_MODE_NATIVE || opt->mode == XDP_MODE_HW)) {
            pr_warn("Attaching XDP program in %s mode not supported - try %s mode.\n",
                    opt->mode == XDP_MODE_NATIVE ? "native" : "HW",
                    opt->mode == XDP_MODE_NATIVE ? "SKB" : "native or SKB");
        } else {
            libbpf_strerror(err, errmsg, sizeof(errmsg));
            pr_warn("Couldn't attach XDP program on iface '%s': %s(%d)\n",
                    opt->iface.ifname, errmsg, err);
        }
        goto out;
    }

    printf("Success: XDP program attached on iface '%s'\n", opt->iface.ifname);


    /** Update xsks_map **/

    obj = xdp_program__bpf_obj(p);
    /* We also need to load the xsks_map */
    xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (xsks_map_fd < 0) {
        fprintf(stderr, "ERROR: no xsks_map found: %s\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }
    int xsk_fd = xsk_socket__fd(xsk_socket->xsk);
    err = bpf_map_update_elem(xsks_map_fd, &opt->xsk_if_queue, &xsk_fd, BPF_ANY);
    if (err) {
        fprintf(stderr, "Error: Failed to update map: %d (%s)\n",
                xsks_map_fd, strerror(errno));
        goto out;
    } else {
        printf("Success: xsks_map updated!\n");
    }

    /* Start thread to do statistics display */
    if (verbose) {
        err = pthread_create(&stats_poll_thread, NULL, stats_poll,
                             xsk_socket);
        if (err) {
            fprintf(stderr, "ERROR: Failed creating statistics thread "
                            "\"%s\"\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    rx_and_process(&my_cfg, xsk_socket);

    /** UMEM cleanup **/
    xsk_umem__delete(umem->umem);

    const struct unloadopt unload_opt = {true, 0, opt->iface};
    do_unload(&unload_opt, NULL);


    out:
    for (i = 0; i < num_progs; i++)
        if (progs[i])
            xdp_program__close(progs[i]);
    free(progs);
    return err;
}


static const struct statusopt {
    struct iface iface;
} defaults_status = {};

static struct prog_option status_options[] = {
        DEFINE_OPTION("dev", OPT_IFNAME, struct statusopt, iface,
        .positional = true, .metavar = "[ifname]",
        .help = "Show status for device [ifname] (default all interfaces)"),
        END_OPTIONS
};

int do_status(const void *cfg, __unused const char *pin_root_path) {
    const struct statusopt *opt = cfg;

    printf("CURRENT XDP PROGRAM STATUS:\n\n");
    return iface_print_status(opt->iface.ifindex ? &opt->iface : NULL);
}


static const struct cleanopt {
    struct iface iface;
} defaults_clean = {};

static struct prog_option clean_options[] = {
        DEFINE_OPTION("dev", OPT_IFNAME, struct cleanopt, iface,
        .positional = true, .metavar = "[ifname]",
        .help = "Clean up detached program links for [ifname] (default all interfaces)"),
        END_OPTIONS
};

int do_clean(const void *cfg, __unused const char *pin_root_path) {
    const struct cleanopt *opt = cfg;

    printf("Cleaning up detached XDP program links for %s\n", opt->iface.ifindex ?
                                                              opt->iface.ifname : "all interfaces");
    return libxdp_clean_references(opt->iface.ifindex);
}

int do_help(__unused const void *cfg, __unused const char *pin_root_path) {
    fprintf(stderr,
            "Usage: xdp-loader COMMAND [options]\n"
            "\n"
            "COMMAND can be one of:\n"
            "       load        - load an XDP program on an interface\n"
            "       unload      - unload an XDP program from an interface\n"
            "       status      - show current XDP program status\n"
            "       clean       - clean up detached program links in XDP bpffs directory\n"
            "       help        - show this help message\n"
            "\n"
            "Use 'xdp-loader COMMAND --help' to see options for each command\n");
    return -1;
}

static const struct prog_command cmds[] = {
        DEFINE_COMMAND(load, "Load an XDP program on an interface"),
        DEFINE_COMMAND(unload, "Unload an XDP program from an interface"),
        DEFINE_COMMAND(clean, "Clean up detached program links in XDP bpffs directory"),
        DEFINE_COMMAND(status, "Show XDP program status"),
        {.name = "help", .func = do_help, .no_cfg = true},
        END_COMMANDS
};

union all_opts {
    struct loadopt load;
    struct unloadopt unload;
    struct statusopt status;
};

int main(int argc, char **argv) {

    if (argc > 1)
        return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
                                 sizeof(union all_opts), PROG_NAME, false);

    return do_help(NULL, NULL);
}
