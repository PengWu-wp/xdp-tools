/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include "stats.h"
#include "util.h"
#include "logging.h"

#include "bpf.h"
#include "libbpf.h"

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		pr_warn("Error with gettimeofday! (%i)\n", res);
		exit(1);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

void stats_print_one(struct stats_record *stats_rec)
{
	__u64 packets, bytes;
	struct record *rec;
	int i;

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt = "  %-35s %'11lld pkts %'11lld KiB\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		packets = rec->total.rx_packets;
		bytes   = rec->total.rx_bytes;

		if (rec->enabled)
			printf(fmt, action, packets, bytes / 1024);
	}
}

void stats_print(struct stats_record *stats_rec,
		 struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	struct timespec t;
	bool first = true;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i, err;

	err = clock_gettime(CLOCK_REALTIME, &t);
	if (err < 0) {
		pr_warn("Error with gettimeofday! (%i)\n", err);
		exit(1);
	}

	/* Print for each XDP actions stats */
	for (i = 0; i < XDP_ACTION_MAX; i++)
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld KiB (%'6.0f Mbits/s)\n";
		const char *action = action2str(i);

		rec  = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		if (!rec->enabled)
			continue;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		bytes   = rec->total.rx_bytes - prev->total.rx_bytes;

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		if (first) {
			printf("Period of %fs ending at %lu.%06lu\n", period,
			       t.tv_sec, t.tv_nsec / 1000);
			first = false;
		}

		pps     = packets / period;

		bps     = (bytes * 8)/ period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1024 , bps,
		       period);
	}
	printf("\n");
}


/* BPF_MAP_TYPE_ARRAY */
static int map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	int err = 0;

	bpf_map_lookup_elem(fd, &key, value);
	if (err)
		pr_debug("bpf_map_lookup_elem failed key:0x%X\n", key);

	return err;
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
static int map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i, err;

	err = bpf_map_lookup_elem(fd, &key, values);
	if (err) {
		pr_debug("bpf_map_lookup_elem failed key:0x%X\n", key);
		return err;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
	return 0;
}

static int map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;
	int err;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		err = map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		err = map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		pr_warn("Unknown map_type: %u cannot handle\n", map_type);
		err = -EINVAL;
		break;
	}

	if (err)
		return err;

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return 0;
}

int stats_collect(int map_fd, __u32 map_type,
		  struct stats_record *stats_rec)
{
	/* Collect all XDP actions stats  */
	__u32 key;
	int err;

	for (key = 0; key < XDP_ACTION_MAX; key++) {
		if (!stats_rec->stats[key].enabled)
			continue;

		err = map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
		if (err)
			return err;
	}

	return 0;
}

int stats_poll(int map_fd, const char *pin_dir, const char *map_name, int interval)
{
	struct bpf_map_info info = {};
	struct stats_record prev, record = { 0 };
	__u32 info_len = sizeof(info);
	__u32 map_type;
	int err;

	record.stats[XDP_DROP].enabled = true;
	record.stats[XDP_PASS].enabled = true;

	if (!interval)
		return -EINVAL;

	err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
	if (err)
		return err;
	map_type = info.type;

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);

	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		usleep(interval*1000);
	}

	return 0;
}
