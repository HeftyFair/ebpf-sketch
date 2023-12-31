

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
#include <stddef.h>




#include "murmurhash.h"




//char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define K_FUNC 7
#define COLUMN 512
#define LAYERS 32
#define HEAP_SIZE 35


#define SEED_UNIVMON 0x9747b28c
#define SEED_CMSKETCH 0xd6e2f2d9




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


static __attribute__((always_inline)) uint32_t min(uint32_t a, uint32_t b) {
    return a < b ? a : b;
}

static uint32_t trailing_zeros2(uint32_t V) {
	V = V-(V&(V-1));
	return( ( ( V & 0xFFFF0000 ) != 0 ? ( V &= 0xFFFF0000, 16 ) : 0 ) | ( ( V & 0xFF00FF00 ) != 0 ? ( V &= 0xFF00FF00, 8 ) : 0 ) | ( ( V & 0xF0F0F0F0 ) != 0 ? ( V &= 0xF0F0F0F0, 4 ) : 0 ) | ( ( V & 0xCCCCCCCC ) != 0 ? ( V &= 0xCCCCCCCC, 2 ) : 0 ) | ( ( V & 0xAAAAAAAA ) != 0 ) );
}


static __attribute__((always_inline)) uint32_t trailing_zeros(unsigned int number) {
    uint32_t count = 0;
    while (number & 1) {
        number >>= 1;
        count++;
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

#define TEST_BIT64(var,pos) ((var) & (1L<<(pos)))

struct global_stats {
    uint32_t total_pkts;
};



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


struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, LAYERS);
        __type(key, uint32_t);
        __type(value, struct count_sketch);
} um_sketch SEC(".maps");


struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, uint32_t);
        __type(value, struct global_stats);
} stats SEC(".maps");


/*
struct bpf_map_def SEC("maps") univmon_sketch = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(uint32_t),
    .value_size = sizeof(struct count_sketch),
    .max_entries = LAYERS,
};
*/

static inline uint32_t t5_hash(struct t5 *t, uint32_t seed) {
    uint32_t hash = 0;
    hash = fasthash32(t, sizeof(struct t5), seed);
    return hash;
}

static void __always_inline insertionSort(struct count_sketch *md) {
    int i, j;
    struct topk_entry key;

#pragma clang loop unroll(full)
    for (i = 1; i < HEAP_SIZE; i++) {
        // __builtin_memcpy(&key, &arr[i], sizeof(struct topk_entry));
        key = md->_topk[i];
        j = i - 1;
 
        while(j >= 0 && md->_topk[j].value < key.value){
            md->_topk[j+1] = md->_topk[j];		
            j = j - 1;		
        }

        // __builtin_memcpy(&arr[j + 1], &key, sizeof(struct topk_entry));
        md->_topk[j + 1] = key;
    }
}

static void __always_inline insert_into_heap(struct count_sketch *md, int median, struct t5 *pkt) {
    int index = -1;

    for (int i = 0; i < HEAP_SIZE; i++) {
        struct t5 origin_pkt = md->_topk[i].tuple;
        // bpf_probe_read_kernel(&origin, sizeof(origin), &md->topks[layer][i].tuple);
        if (origin_pkt.dst_ip == pkt->dst_ip &&
            origin_pkt.src_ip == pkt->src_ip &&
            origin_pkt.protocol == pkt->protocol &&
            origin_pkt.dst_port == pkt->dst_port &&
            origin_pkt.src_port == pkt->src_port) {
                index = i;
                break;
        }
    }

    if (index >= 0) {
        if (md->_topk[index].value < median) {
            md->_topk[index].value = median;
            md->_topk[index].tuple = *pkt;
        } else {
            return;
        }
    } else {
        // The element is not in the array, let's insert a new one.
        // What I do is to insert in the last position, and then sort the array
        if (md->_topk[HEAP_SIZE-1].value < median) {
            md->_topk[HEAP_SIZE-1].value = median;
            md->_topk[HEAP_SIZE-1].tuple = *pkt;
        } else {
            return;
        }
    }
    insertionSort(md);
}


static __attribute__((always_inline)) inline void topk_update(struct topk_entry *topk, int value, struct t5 *t) {
    if (!topk) {
        return;
    }

    if (value < topk[0].value) {
        return;
    }
    topk[0].value = value;
    topk[0].tuple = *t;
    int i = 0;
    #pragma unroll
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
    if (!skt) {
        return;
    }
    //struct t5 t_tmp;
    //bpf_probe_read_kernel(&t_tmp, sizeof(struct t5), &t);
    #pragma clang loop unroll(full)
    for (int i = 0; i < K_FUNC; i++) {
        uint32_t hash = t5_hash(t, SEED_CMSKETCH + i);
        //uint32_t hash = 1;
        uint32_t index = hash & (COLUMN - 1);
        if (TEST_BIT(hash, 31)) {
            skt->_cnt[i][index]--;
        } else {
            skt->_cnt[i][index]++;
        }
        //skt->_cnt[i][index] += (TEST_BIT(hash, 31) ? -1 : 1);
    }
}

static int cs_query_sketch(struct count_sketch *skt, struct t5 *t) {
    if (!skt) {
        return 0;
    }
    //struct t5 t_tmp;
    //bpf_probe_read_kernel(&t_tmp, sizeof(struct t5), &t);
    int value[K_FUNC] = {0};

    #pragma clang loop unroll(full)
    for (int i = 0; i < K_FUNC; i++) {
        uint32_t hash = t5_hash(t, SEED_CMSKETCH + i);
        uint32_t index = hash & (COLUMN - 1);
        if (TEST_BIT(hash, 31)) {
            value[i] = -skt->_cnt[i][index];
        } else {
            value[i] = skt->_cnt[i][index];
        }
        //value[i] += (TEST_BIT(hash, 31) ? -1 : 1) * skt->_cnt[i][index];
    }
    return median(value, K_FUNC);
}



struct ctx {
    int max_l;
    struct t5 t;
};

static inline struct count_sketch* um_sketch_get(const void *key) {
    return bpf_map_lookup_elem(&um_sketch, key);
}


static int update(__u32 index, struct ctx *ctx) {
    struct t5 t = ctx->t;
    if (!ctx) {
        return 1;
    }
    int i = index;
    if (i >= ctx->max_l) {
        return 1;
    }
    
    struct count_sketch *skt = bpf_map_lookup_elem(&um_sketch, &i);;
    if (skt) {
        cs_update_sketch(skt, &t);
        int result = cs_query_sketch(skt, &t);
        
        //topk_update(skt->_topk, result, &t);
        insert_into_heap(skt, result, &t);
    }
    return 0;
}

#define ACTION XDP_DROP

SEC("xdp")
int xdp_rcv(struct xdp_md *ctx) {

    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        //bpf_printk("packet is too small\n");
        return ACTION;
    }
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return ACTION;
    }
    iphdr = data + sizeof(struct ethhdr);

    // get 5-tuple
    uint32_t key = 0;
    struct t5 t;

    if (iphdr->protocol == IPPROTO_TCP) {
        tcphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void*)tcphdr + sizeof(struct tcphdr) > data_end) {
            return ACTION;
        }
        t.src_port = tcphdr->source;
        t.dst_port = tcphdr->dest;
    } else if (iphdr->protocol == IPPROTO_UDP) {
        udphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void*)udphdr + sizeof(struct udphdr) > data_end) {
            return ACTION;
        }
        t.src_port = udphdr->source;
        t.dst_port = udphdr->dest;
    } else {
        return ACTION;
    }


    t.src_ip = iphdr->saddr;
    t.dst_ip = iphdr->daddr;
    t.protocol = iphdr->protocol;
    

    /*
    t.src_ip = bpf_ntohl(iphdr->saddr);
    t.dst_ip = bpf_ntohl(iphdr->daddr);
    t.src_port = bpf_ntohs(tcphdr->source);
    t.dst_port = bpf_ntohs(tcphdr->dest);
    t.protocol = iphdr->protocol;
    */

    // update first sketch
    
    uint32_t sk = fasthash32(&t, sizeof(struct t5), SEED_UNIVMON);

    // print hash and t5
    //bpf_printk("hash: %x for src_ip\n", sk);
    //bpf_printk("src_port: %u\n", t.src_port);
    //bpf_printk("dst_port: %u\n", t.dst_port);

    sk &= 0xfffffffe;

    uint32_t gs_key = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&stats, &gs_key);
    if (gs) {
        __sync_fetch_and_add(&gs->total_pkts, 1);
        //gs->total_pkts++;
    }
    
    uint32_t max_l = min(trailing_zeros2(sk), LAYERS);

    struct ctx loop_ctx;
    //loop_ctx.i = 0;
    loop_ctx.max_l = max_l;
    loop_ctx.t = t;
    
    //loop_ctx.skt = &um_sketch;
    //struct count_sketch skt_tmp[LAYERS] = bpf_map_lookup_elem(&univmon_sketch, &max_l);
    bpf_loop(LAYERS, update, &loop_ctx, 0);

    /*
    for (int i = 1; i < LAYERS - 1; i++) {
        if (i >= max_l) {
            break;
        }
        //bpf_probe_read_kernel(&t, sizeof(struct t5), &t);
        struct count_sketch *skt = bpf_map_lookup_elem(&univmon_sketch, &i);
        if (skt) {
            cs_update_sketch(skt, &t);
            int result = cs_query_sketch(skt, &t);
            topk_update(skt->_topk, result, &t);
        }
    }*/

    /*
    struct count_sketch *skt = bpf_map_lookup_elem(&univmon_sketch, &max_l);

    if (skt) {
        cs_update_sketch(skt, &t);
        int result = cs_query_sketch(skt, &t);
        topk_update(skt->_topk, result, &t);
    }*/

    return XDP_DROP;
}
