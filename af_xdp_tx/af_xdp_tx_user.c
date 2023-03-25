/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <unistd.h>
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
#include <linux/if_link.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_ether.h>

#include "params.h"
#include "logging.h"
#include "util.h"

#define PROG_NAME "af_xdp_tx"

#define NUM_FRAMES      4096
#define FRAME_SIZE      XSK_UMEM__DEFAULT_FRAME_SIZE
#define BATCH_SIZE      32
//#define BATCH_SIZE      64
#define INVALID_UMEM_FRAME UINT64_MAX

static bool global_exit = false;

static char data[] = {0x00, 0x0c, 0x29, 0x3b, 0xd1, 0x44, 0x00, 0x0c, 0x29, 0x4d, 0x66, 0x3c, 0x08, 0x00, 0x45, 0xc0,
                      0x00, 0x50, 0x91, 0xc0, 0x00, 0x00, 0x40, 0x01, 0x4c, 0xd3, 0xc0, 0xa8, 0x0d, 0x01, 0xc0, 0xa8,
                      0x0d, 0x08, 0x03, 0x03, 0x98, 0x88, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};


struct xsk_umem_info { // 该结构体是linux源码samples示例中用的，值得参考
    struct xsk_ring_prod fq; // fill ring
    struct xsk_ring_cons cq; // comp ring
    struct xsk_umem *umem; // umem header
    void *buffer; // 即umem起始地址
};

struct stats_record {
    uint64_t timestamp;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t tx_packets;
    uint64_t tx_bytes;
};

struct xsk_socket_info { // 该结构体是linux源码samples示例中用的，有过修改
    struct xsk_ring_cons rx; // 与本xsk绑定的RX Ring，每个xsk一个
    struct xsk_ring_prod tx; // 与本xsk绑定的TX Ring，每个xsk一个
    struct xsk_umem_info *umem_info; // 和本xsk绑定的umem，（多个xsk可以绑定同一个umem）
    struct xsk_socket *xsk; // xsk header

    uint64_t umem_frame_addr[NUM_FRAMES]; // 每个数据帧的地址(其实是相对于UMEM起始位置的字节偏移量)
    uint32_t umem_frame_free; // 剩余能操作的数据帧数量（也就是能用的chunks数量）

    uint32_t outstanding_tx; // 这个是干啥的？成功发送的数量

    struct stats_record stats;
    struct stats_record prev_stats;
};

static const struct sendopt {
    struct iface iface;
//    __u16 xsk_bind_flags;
    int xsk_if_queue;
    bool xsk_copy_mode;
    bool xsk_zero_copy_mode;
    __u32 xdp_flags;
    bool quiet;
} defaults_send = {
//    .xsk_bind_flags = XDP_COPY,
        .xsk_if_queue = 0,
        .xsk_copy_mode = false,
        .xsk_zero_copy_mode = false,
        .xdp_flags = XDP_FLAGS_DRV_MODE,
        .quiet = false
};

struct enum_val xdp_modes[] = {
        {"native", XDP_FLAGS_DRV_MODE},
        {"skb",    XDP_FLAGS_SKB_MODE},
        {NULL,     0}
};

static struct prog_option send_options[] = {
        DEFINE_OPTION("dev", OPT_IFNAME, struct sendopt, iface,
        .positional = true,
        .metavar = "<ifname>",
        .required = true,
        .help = "Send on device <ifname>"),
        DEFINE_OPTION("queue", OPT_U32, struct sendopt, xsk_if_queue,
        .short_opt = 'Q',
        .metavar = "<queue_id>",
        .required = false,
        .help = "Configure interface queue_id for AF_XDP, default=0"),
        DEFINE_OPTION("copy", OPT_BOOL, struct sendopt, xsk_copy_mode,
        .short_opt = 'c',
        .help = "Force copy mode"),
        DEFINE_OPTION("zero-copy", OPT_BOOL, struct sendopt, xsk_zero_copy_mode,
        .short_opt = 'z',
        .help = "Force zero-copy mode"),
        DEFINE_OPTION("mode", OPT_ENUM, struct sendopt, xdp_flags,
        .short_opt = 'm',
        .typearg = xdp_modes,
        .metavar = "<mode>",
        .help = "Load XDP program in <mode>; default native (native/skb available)"),
        DEFINE_OPTION("quiet", OPT_BOOL, struct sendopt, quiet,
        .short_opt = 'q',
        .help = "Quietly send"),
        END_OPTIONS
};

/* 返回一个UMEM的地址（相对于UMEM起始地址的字节偏移量），并将xsk_info里面的frame_free减一 */
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk_info) {
    uint64_t frame;
    if (xsk_info->umem_frame_free == 0)
        return INVALID_UMEM_FRAME;

    frame = xsk_info->umem_frame_addr[--xsk_info->umem_frame_free];
    xsk_info->umem_frame_addr[xsk_info->umem_frame_free] = INVALID_UMEM_FRAME;
    return frame;
}

static struct xsk_umem_info *configure_xsk_umem(void *buffer,
                                                uint64_t size) {
    struct xsk_umem_info *umem_info;
    int ret;

    umem_info = calloc(1, sizeof(*umem_info));
    if (!umem_info)
        return NULL;

    ret = xsk_umem__create(&umem_info->umem, buffer, size, &umem_info->fq,
                           &umem_info->cq, NULL); // set NULL to use default cfg
    if (ret) {
        errno = -ret;
        return NULL;
    }

    umem_info->buffer = buffer;
    return umem_info;
}


static struct xsk_socket_info *xsk_configure_socket(const struct sendopt *opt,
                                                    struct xsk_umem_info *umem_info) {
    struct xsk_socket_config xsk_cfg;
    struct xsk_socket_info *xsk_info;
    uint32_t idx;
    int i;
    int ret;


    xsk_cfg.bind_flags = 0;
    if (opt->xsk_copy_mode && opt->xsk_zero_copy_mode) {
        pr_warn("Only one of --copy or --zero-copy can be set\n");
        exit(EXIT_FAILURE);
    } else if (opt->xsk_copy_mode) {
        xsk_cfg.bind_flags |= XDP_COPY;
    } else if (opt->xsk_zero_copy_mode) {
        if (opt->xdp_flags == XDP_FLAGS_SKB_MODE) {
            pr_warn("SKB mode does not support zero-copy mode\n");
            exit(EXIT_FAILURE);
        }
        xsk_cfg.bind_flags |= XDP_ZEROCOPY;
    }


    xsk_info = calloc(1, sizeof(*xsk_info));
    if (!xsk_info)
        return NULL;

    xsk_info->umem_info = umem_info;

    xsk_cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    xsk_cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    xsk_cfg.libbpf_flags = 0; // Use default XDP program
    xsk_cfg.xdp_flags = opt->xdp_flags;
//    xsk_cfg.bind_flags = opt->xsk_bind_flags;
    ret = xsk_socket__create(&xsk_info->xsk, opt->iface.ifname,
                             opt->xsk_if_queue, umem_info->umem, &xsk_info->rx,
                             &xsk_info->tx, &xsk_cfg);
    if (ret)
        goto error_exit;
    printf("Success: xsk socket configured\n");

    /* Initialize umem frame allocation */
    for (i = 0; i < NUM_FRAMES; i++)
        xsk_info->umem_frame_addr[i] = i * FRAME_SIZE;

    xsk_info->umem_frame_free = NUM_FRAMES;

    return xsk_info;

    error_exit:
    errno = -ret;
    return NULL;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk_info, uint64_t frame) {
    assert(xsk_info->umem_frame_free < NUM_FRAMES);

    xsk_info->umem_frame_addr[xsk_info->umem_frame_free++] = frame;
}

__attribute__((unused))
static void complete_tx(struct xsk_socket_info *xsk_info) {
    unsigned int completed;
    uint32_t idx_cq;

    if (!xsk_info->outstanding_tx)
        return;

    sendto(xsk_socket__fd(xsk_info->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);


    /* Collect/free completed TX buffers */
    completed = xsk_ring_cons__peek(&xsk_info->umem_info->cq,
                                    XSK_RING_CONS__DEFAULT_NUM_DESCS,
                                    &idx_cq);

//    printf("%d completed\n", completed);

    if (completed > 0) {
        for (unsigned int i = 0; i < completed; i++)
            xsk_free_umem_frame(xsk_info,
                                *xsk_ring_cons__comp_addr(&xsk_info->umem_info->cq,
                                                          idx_cq++));

        xsk_ring_cons__release(&xsk_info->umem_info->cq, completed);
        xsk_info->outstanding_tx -= completed < xsk_info->outstanding_tx ?
                                    completed : xsk_info->outstanding_tx;
    }
}

static void tx_process(const struct sendopt *opt,
                       struct xsk_socket_info *xsk_info) {
    unsigned int stock_frames;
    uint32_t idx_tx = 0;
    int ret;

    while (!global_exit) {
//        sleep(1);

        ret = xsk_ring_prod__reserve(&xsk_info->tx,
                                     BATCH_SIZE,
                                     &idx_tx);

        if (ret != BATCH_SIZE)
            return;

        /* Stuff all desc with static data */
        for (int i = 0; i < BATCH_SIZE; i++) {
            struct xdp_desc *desc = xsk_ring_prod__tx_desc(&xsk_info->tx, idx_tx++);
            desc->addr = xsk_alloc_umem_frame(xsk_info); // 从后往前分配地址，frame_free--
            uint8_t *pkt = xsk_umem__get_data(xsk_info->umem_info->buffer, desc->addr);
            memcpy(pkt, data, 60);
            desc->len = 60;

            xsk_info->outstanding_tx++;
            xsk_info->stats.tx_bytes += 60;
            xsk_info->stats.tx_packets++;
        }

        xsk_ring_prod__submit(&xsk_info->tx,
                              BATCH_SIZE);

        while (xsk_info->outstanding_tx)
            complete_tx(xsk_info);


    }

    printf("WP: send done\n");
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
    printf("WP: I'm out\n");
    return NULL;
}

static void exit_application(int signal) {
    signal = signal;
    global_exit = true;
    printf("WP: global_exit set true\n");
}


int do_send(const void *cfg, __unused const char *pin_root_path) {
    const struct sendopt *opt = cfg;
    int err;
    uint64_t packet_buffer_size;
    void *packet_buffer;
    struct xsk_umem_info *umem_info;
    struct xsk_socket_info *xsk_info;
    pthread_t stats_poll_thread;

    /** Allocate memory for NUM_FRAMES of the default XDP frame size **/
    packet_buffer_size = NUM_FRAMES * FRAME_SIZE;
    err = posix_memalign(&packet_buffer,
                         getpagesize(), /* PAGE_SIZE aligned */
                         packet_buffer_size);
    if (err) {
        fprintf(stderr, "ERROR: Can't allocate buffer memory \"%s\"\n",
                strerror(-err));
        exit(EXIT_FAILURE);
    }

    /** Create UMEM **/
    umem_info = configure_xsk_umem(packet_buffer, packet_buffer_size);
    if (!umem_info) {
        fprintf(stderr, "ERROR: Can't create umem \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    /** Open and configure the AF_XDP (xsk) socket **/
    xsk_info = xsk_configure_socket(opt, umem_info);
    if (!xsk_info) {
        fprintf(stderr, "ERROR: Can't setup AF_XDP socket \"%s\"\n",
                strerror(errno));
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, exit_application);

    /** Start thread to do statistics display **/
    if (!opt->quiet) {
        err = pthread_create(&stats_poll_thread, NULL, stats_poll,
                             xsk_info);
        if (err) {
            fprintf(stderr, "ERROR: Failed creating statistics thread "
                            "\"%s\"\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

    tx_process(opt, xsk_info);

    /** UMEM cleanup **/
    xsk_umem__delete(umem_info->umem);

    return 0;
}


int do_help(__unused const void *cfg, __unused const char *pin_root_path) {
    fprintf(stderr,
            "Usage: xdp-loader COMMAND [options]\n"
            "\n"
            "COMMAND can be one of:\n"
            "       send        - send packets out from an interface\n"
            "       help        - show this help message\n"
            "\n"
            "Use 'xdp-loader COMMAND --help' to see options for each command\n");
    return -1;
}

static const struct prog_command cmds[] = {
        DEFINE_COMMAND(send, "send packets out from an interface"),
        {.name = "help", .func = do_help, .no_cfg = true},
        END_COMMANDS
};

union all_opts {
    struct sendopt send;
};

int main(int argc, char **argv) {
    if (argc > 1)
        return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
                                 sizeof(union all_opts), PROG_NAME, false);

    return do_help(NULL, NULL);
}
