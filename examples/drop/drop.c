//go:build ignore

#include "bpf_endian.h"
#include "common.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// struct bpf_map_def SEC("maps") port_map = {
// 	.type        = BPF_MAP_TYPE_HASH,
// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// 	.max_entries = 2,
// };

struct tcphdr {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
};// seems not to be defined


static volatile const int port;


SEC("xdp")

/*

 user accessible metadata for XDP packet hook
 * new fields must be added to the end of this structure
struct xdp_md {
	__u32 data;
	__u32 data_end;
	__u32 data_meta;
	/* Below access go through struct xdp_rxq_info */
	//__u32 ingress_ifindex; /* rxq->dev->ifindex */
	//__u32 rx_queue_index;  /* rxq->queue_index  */

	//__u32 egress_ifindex;  /* txq->dev->ifindex */
    //};
// */
int drop_tcp_port(struct xdp_md *ctx) {

    void *data_end = (void*)(long)ctx->data_end;
    void*data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (ip->protocol == 6) { // needed to use IPPROTO_TCP https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/in.h#L39
        // int *port_ptr = bpf_map_lookup_elem(&port_map, 1); // match 1 with mentioned in the args.
        // if(port_ptr == NULL) return XDP_ABORTED;
        // if (tcph->source == bpf_htons(*port_ptr)) { // host byte order to network byte order
        //     return XDP_DROP;
        // }
		if (tcph->source == bpf_htons(port)) { // host byte order to network byte order
            return XDP_DROP;
        }
    }
    return XDP_PASS;
}

