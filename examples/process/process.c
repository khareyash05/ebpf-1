//go:build ignore

#include "bpf_endian.h"
#include "common.h"
#define TASK_COMM_LEN 16

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") process_names = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(char[TASK_COMM_LEN]),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") port_names = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 2,
};

struct tcphdr {
	__u16	source;
	__u16	dest;
	__u32	seq;
	__u32	ack_seq;
};// seems not to be defined


SEC("xdp")
int allow_specific_port(struct xdp_md *ctx) {

    char comm[TASK_COMM_LEN]; // get name of process currently running
    bpf_get_current_comm(&comm, sizeof(comm));

    char *process_name = bpf_map_lookup_elem(&process_names, 1); // look into the map for process name passed by the user
    if (bpf_strcmp(*process_name,comm)==0) {
        // Process name not same, drop the packet
        return XDP_DROP;
    }
    int port = bpf_map_lookup_elem(&port_names, 1); // get port number mentioned by user

    void *data_end = (void*)(long)ctx->data_end;
    void*data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(struct ethhdr); // port is the allowed port
    if (ip->protocol == 6) {
        struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcph->dest == bpf_htons(port)) { // host byte order to network byte order
            return XDP_PASS;
        }
    }
    // Drop the packet if it doesn't meet the allow condition
    return XDP_DROP;
}