/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);
	__type(key, int);
	__type(value, int);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_prog(struct xdp_md *ctx)
{
	__u32 off;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(*eth);

	off = sizeof(struct ethhdr);
	if (data + off > data_end)
		return XDP_PASS;

	if (bpf_htons(eth->h_proto) == ETH_P_IP) {
		off += sizeof(struct iphdr);
		if (data + off > data_end)
			return XDP_PASS;
		/* We process IPv4 ICMP ping pkts only. */
		if (ip->protocol == IPPROTO_ICMP) {
			int idx = ctx->rx_queue_index;
			if (bpf_map_lookup_elem(&xsks_map, &idx)) {
				return bpf_redirect_map(&xsks_map, idx, 0);
			}
		}
	}
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
