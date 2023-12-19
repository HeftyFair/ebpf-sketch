

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <stdint.h>
#include <linux/types.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>



static int average_without_overflow(int a, int b) {
    return (a & b) + ((a ^ b) >> 1);
}

static int __always_inline median(int *vect, int len) {
    int temp;
    int i, j;
    // the following two loops sort the array in ascending order
    // FIXME: We might implement something more efficient here (e.g., quicksort)
    for(i = 0; i < len-1; i++) {
        for(j = i+1; j < len; j++) {
            if(vect[j] < vect[i]) {
                // swap elements
                temp = vect[i];
                vect[i] = vect[j];
                vect[j] = temp;
            }
        }
    }

    if(len % 2 == 0) {
        // if there is an even number of elements, return mean of the two elements in the middle
        // return((vect[len/2] + vect[len/2 - 1]) / 2);
        return average_without_overflow(vect[len/2], vect[len/2 - 1]);
    } else {
        // else return the element in the middle
        return vect[len/2];
    }
    ///return 
}


uint32_t trailing_zeros(unsigned int number) {
    if (number == 0) 
        return 32;

    unsigned int count = 0;
    while ((number & 1) == 0) {
        count++;
        number >>= 1;
    }
    return count;
}



// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
static __attribute__((always_inline)) inline __u64 fasthash_mix(__u64 h) {
	h ^= h >> 23;
	h *= 0x2127599bf4325c37ULL;
	h ^= h >> 47;
	return h;
}

static __attribute__((always_inline)) inline __u64 fasthash64(const void *buf, __u64 len, __u64 seed)
{
	const __u64 m = 0x880355f21e6d1965ULL;
	const __u64 *pos = (const __u64 *)buf;
	const __u64 *end = pos + (len / 8);
	const unsigned char *pos2;
	__u64 h = seed ^ (len * m);
	__u64 v;

	while (pos != end) {
		v  = *pos++;
		h ^= fasthash_mix(v);
		h *= m;
	}

	pos2 = (const unsigned char*)pos;
	v = 0;

	switch (len & 7) {
	case 7: v ^= (__u64)pos2[6] << 48;
	case 6: v ^= (__u64)pos2[5] << 40;
	case 5: v ^= (__u64)pos2[4] << 32;
	case 4: v ^= (__u64)pos2[3] << 24;
	case 3: v ^= (__u64)pos2[2] << 16;
	case 2: v ^= (__u64)pos2[1] << 8;
	case 1: v ^= (__u64)pos2[0];
		h ^= fasthash_mix(v);
		h *= m;
	}

	return fasthash_mix(h);
}

static __attribute__((always_inline)) inline __u32 fasthash32(const void *buf, __u64 len, __u32 seed)
{
	// the following trick converts the 64-bit hashcode to Fermat
	// residue, which shall retain information from both the higher
	// and lower parts of hashcode.
    __u64 h = fasthash64(buf, len, seed);
	return h - (h >> 32);
}


#define TEST_BIT(var,pos) ((var) & (1<<(pos)))



#define K_FUNC 10
#define COLUMN 256
#define LAYERS 10
#define HEAP_SIZE 5


#define SEED_UNIVMON 0x9747b28c
#define SEED_CMSKETCH 0xd6e2f2d9



struct t5 {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct topk_entry {
    int value;
    struct t5 tuple;
};

struct count_sketch {
    int _cnt[K_FUNC][COLUMN];
    struct topk_entry _topk[HEAP_SIZE];
};


static uint32_t t5_hash(struct t5 *t, uint32_t seed) {
    uint32_t hash = 0;
    hash = fasthash32(t, sizeof(struct t5), seed);
    return hash;
}

static void topk_update(struct topk_entry *topk, int value, struct t5 *t) {
    if (value < topk[0].value) {
        return;
    }
    topk[0].value = value;
    topk[0].tuple = *t;
    int i = 0;
    while (i < HEAP_SIZE) {
        int max = i;
        if (2 * i + 1 < HEAP_SIZE && topk[2 * i + 1].value > topk[max].value) {
            max = 2 * i + 1;
        }
        if (2 * i + 2 < HEAP_SIZE && topk[2 * i + 2].value > topk[max].value) {
            max = 2 * i + 2;
        }
        if (max == i) {
            break;
        }
        struct topk_entry tmp = topk[i];
        topk[i] = topk[max];
        topk[max] = tmp;
        i = max;
    }
}


static void cs_update_sketch(struct count_sketch *skt, struct t5 *t) {
    for (int i = 0; i < K_FUNC; i++) {
        uint32_t hash = t5_hash(t, SEED_CMSKETCH + i);
        uint32_t index = hash % COLUMN;
        skt->_cnt[i][index] += TEST_BIT(hash, 31) ? -1 : 1;
    }
}

static uint32_t cs_query_sketch(struct count_sketch *skt, struct t5 *t) {
    int value[K_FUNC] = {0};

    for (int i = 0; i < K_FUNC; i++) {
        uint32_t hash = t5_hash(t, SEED_CMSKETCH + i);
        uint32_t index = hash % COLUMN;
        value[i] += (TEST_BIT(hash, 31) ? -1 : 1) * skt->_cnt[i][index];
    }
    return median(value, K_FUNC);
}


struct bpf_map_def SEC("maps") univmon_sketch = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct count_sketch),
    .max_entries = LAYERS,
};

uint32_t min(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}


SEC("xdp")
int xdp_rcv(struct xdp_md *ctx) {

    //struct tcphdr *tcphdr;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 1 > data_end) {
        return XDP_PASS;
    }
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    iphdr = data + sizeof(struct ethhdr);
    if (iphdr->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    struct tcphdr *tcphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    // get 5-tuple
    uint32_t key = 0;
    struct t5 t;
    t.src_ip = iphdr->saddr;
    t.dst_ip = iphdr->daddr;
    t.src_port = tcphdr->source;
    t.dst_port = tcphdr->dest;
    t.protocol = iphdr->protocol;
    // update first sketch
    struct count_sketch *skt = bpf_map_lookup_elem(&univmon_sketch, &key);

    

    if (skt) {
        cs_update_sketch(skt, &t);
    }

    // other sketch
    uint32_t sk = fasthash32(&t, sizeof(struct t5), SEED_UNIVMON);
    sk &= ~1;
    uint32_t max_l = min(trailing_zeros(sk), LAYERS);

    for (int i = 1; i < max_l; i++) {
        key = i;
        struct count_sketch *skt = bpf_map_lookup_elem(&univmon_sketch, &key);
        if (skt) {
            cs_update_sketch(skt, &t);
            uint32_t result = 0;
            result = cs_query_sketch(skt, &t);
            topk_update(skt->_topk, result, &t);
        }
    }
    
    
    return XDP_PASS;
}
