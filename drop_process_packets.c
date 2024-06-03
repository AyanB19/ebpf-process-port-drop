#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/sched.h>

struct bpf_map_def SEC("maps") allowed_port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u16),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") target_pid_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

SEC("prog")
int xdp_filter_packets(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct task_struct *task;
    struct pid *pid_struct;
    __u32 key = 0;
    __u32 *target_pid;
    __u16 *allowed_port;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    tcph = (void *)iph + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    // Get target process PID
    target_pid = bpf_map_lookup_elem(&target_pid_map, &key);
    if (!target_pid)
        return XDP_PASS;

    // Get the allowed port
    allowed_port = bpf_map_lookup_elem(&allowed_port_map, &key);
    if (!allowed_port)
        return XDP_PASS;

    // Check the current process ID
    task = (struct task_struct *)bpf_get_current_task();
    pid_struct = (struct pid *)task->thread_pid;
    if (pid_struct->numbers[0].nr != *target_pid)
        return XDP_PASS;

    // Allow traffic only to the specific port
    if (tcph->dest == htons(*allowed_port))
        return XDP_PASS;

    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
