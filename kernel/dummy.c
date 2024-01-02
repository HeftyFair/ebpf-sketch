

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <linux/types.h>
#include <stddef.h>


// function for comparison
SEC("xdp")
int xdp_drop(struct xdp_md *ctx) {
    return XDP_DROP;
}