

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


#include "fasthash.h"
// char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define K_FUNC 7
#define COLUMN 2048
#define LAYERS 32
#define HEAP_SIZE 35
#define RND_CNT 4096

#define SEED_UNIVMON 0x9747b28c
#define SEED_CMSKETCH 0xd6e2f2d9

#define P_INVERSE 1

#define LAMBDA 7


#define TEST_BIT(var, pos) ((var) & (1 << (pos)))


#define TEST_BIT64(var, pos) ((var) & (1L << (pos)))

struct global_stats
{
    uint32_t total_pkts;
};

struct meta
{
    uint32_t rnd[RND_CNT];
    uint32_t idx;
    uint32_t idx_rnd;
    uint32_t total_pkts;
} __attribute__((packed));

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct meta);
} meta SEC(".maps");

struct t5
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

struct topk_entry
{
    int value;
    struct t5 tuple;
};

struct count_sketch
{
    int _cnt[K_FUNC][COLUMN];
    struct topk_entry _topk[HEAP_SIZE];
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, LAYERS);
    __type(key, uint32_t);
    __type(value, struct count_sketch);
} um_sketch SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, uint32_t);
    __type(value, struct global_stats);
} stats SEC(".maps");

static inline uint32_t t5_hash(struct t5 *t, uint32_t seed)
{
    uint32_t hash = 0;
    if (!t) {
        return 0;
    }
    hash = fasthash32(t, sizeof(struct t5), seed);
    return hash;
}

static void __always_inline insertionSort(struct count_sketch *md)
{
    int i, j;
    struct topk_entry key;

#pragma clang loop unroll(full)
    for (i = 1; i < HEAP_SIZE; i++)
    {
        // __builtin_memcpy(&key, &arr[i], sizeof(struct topk_entry));
        key = md->_topk[i];
        j = i - 1;

        while (j >= 0 && md->_topk[j].value < key.value)
        {
            md->_topk[j + 1] = md->_topk[j];
            j = j - 1;
        }

        // __builtin_memcpy(&arr[j + 1], &key, sizeof(struct topk_entry));
        md->_topk[j + 1] = key;
    }
}

static void __always_inline insert_into_heap(struct count_sketch *md, int median, struct t5 *pkt)
{
    int index = -1;

    for (int i = 0; i < HEAP_SIZE; i++)
    {
        struct t5 origin_pkt = md->_topk[i].tuple;
        // bpf_probe_read_kernel(&origin, sizeof(origin), &md->topks[layer][i].tuple);
        if (origin_pkt.dst_ip == pkt->dst_ip &&
            origin_pkt.src_ip == pkt->src_ip &&
            origin_pkt.protocol == pkt->protocol &&
            origin_pkt.dst_port == pkt->dst_port &&
            origin_pkt.src_port == pkt->src_port)
        {
            index = i;
            break;
        }
    }

    if (index >= 0)
    {
        if (md->_topk[index].value < median)
        {
            md->_topk[index].value = median;
            md->_topk[index].tuple = *pkt;
        }
        else
        {
            return;
        }
    }
    else
    {
        // The element is not in the array, let's insert a new one.
        // What I do is to insert in the last position, and then sort the array
        if (md->_topk[HEAP_SIZE - 1].value < median)
        {
            md->_topk[HEAP_SIZE - 1].value = median;
            md->_topk[HEAP_SIZE - 1].tuple = *pkt;
        }
        else
        {
            return;
        }
    }
    insertionSort(md);
}

static __attribute__((always_inline)) inline void topk_update(struct topk_entry *topk, int value, struct t5 *t)
{
    if (!topk)
    {
        return;
    }

    if (value < topk[0].value)
    {
        return;
    }
    topk[0].value = value;
    topk[0].tuple = *t;
    int i = 0;
#pragma unroll
    while (i < HEAP_SIZE)
    {
        int max = i;
        if (2 * i + 1 < HEAP_SIZE && topk[2 * i + 1].value > topk[max].value)
        {
            max = 2 * i + 1;
        }
        if (2 * i + 2 < HEAP_SIZE && topk[2 * i + 2].value > topk[max].value)
        {
            max = 2 * i + 2;
        }
        if (max == i)
        {
            break;
        }
        struct topk_entry tmp = topk[i];
        topk[i] = topk[max];
        topk[max] = tmp;
        i = max;
    }
}

static __attribute__((always_inline)) inline void cs_update_sketch(struct count_sketch *skt, const struct t5 *myt5)
{
    if (!skt || !myt5)
    {
        return;
    }

    int i = 0;
    
    
    struct meta *pmeta = bpf_map_lookup_elem(&meta, &i);
    if (!pmeta) {
        return;
    }

    pmeta->total_pkts += 1;
    
    uint32_t update_idx;
    uint32_t next;
    //uint64_t rnd_value = meta->idx;

    if (bpf_probe_read_kernel(&update_idx, sizeof(update_idx), &pmeta->idx) != 0) {
        return;
    }
    //update_idx = tmp;

    for (int i = 0; i < K_FUNC; i++)
    {
        if (update_idx >= K_FUNC)
        {
            update_idx -= K_FUNC;
            break;
        } else {
            //update_idx = 0;
            
            uint32_t hash = fasthash32(myt5, sizeof(struct t5), SEED_CMSKETCH + update_idx);
            //__u8 update = TEST_BIT(hash, 31);
            uint16_t column = 0;
            column = hash & (COLUMN - 1);
            // to get the *fucking* clang compiler not optimize out validation
            uint8_t row = update_idx;

            if (TEST_BIT(hash, 31)) {
                skt->_cnt[row][column] = skt->_cnt[row][column] - P_INVERSE;
            } else {
                skt->_cnt[row][column] = skt->_cnt[row][column] - P_INVERSE;
            }
            
        }
        uint32_t idx_rnd = pmeta->idx_rnd; 
        //bpf_probe_read_kernel(&idx_rnd, sizeof(idx_rnd), &pmeta->idx_rnd);
        idx_rnd = (idx_rnd + 1) & (RND_CNT - 1);
        next = pmeta->rnd[idx_rnd]; 
        //bpf_probe_read_kernel(&next, sizeof(next), &pmeta->rnd[idx_rnd]);
        update_idx += next;
        //bpf_printk("next: %d\n", next);
        pmeta->idx_rnd = idx_rnd;
        if (update_idx >= K_FUNC)
        {
            update_idx -= K_FUNC;
            break;
        }
    }
    //bpf_printk("update_idx: %d\n", update_idx);
    pmeta->idx = update_idx;
}

static int cs_query_sketch(struct count_sketch *skt, struct t5 *t)
{
    if (!skt)
    {
        return 0;
    }
    // struct t5 t_tmp;
    // bpf_probe_read_kernel(&t_tmp, sizeof(struct t5), &t);
    int value[K_FUNC] = {0};

//#pragma clang loop unroll(full)
    for (int i = 0; i < K_FUNC; i++)
    {
        uint32_t hash = t5_hash(t, SEED_CMSKETCH + i);
        uint16_t index = hash & (COLUMN - 1);;
    

        if (TEST_BIT(hash, 31))
        {
            value[i] = -skt->_cnt[i][index];
        }
        else
        {
            value[i] = skt->_cnt[i][index];
        }
        // value[i] += (TEST_BIT(hash, 31) ? -1 : 1) * skt->_cnt[i][index];
    }
    return median(value, K_FUNC);
}

struct ctx
{
    int max_l;
    struct t5 t;
    uint64_t tot;
};

static inline struct count_sketch *um_sketch_get(const void *key)
{
    return bpf_map_lookup_elem(&um_sketch, key);
}

static int update(__u32 index, struct ctx *ctx)
{
    struct t5 t = ctx->t;
    if (!ctx)
    {
        return 1;
    }
    int i = index;

    
    if (i > ctx->max_l)
    {
        return 1;
    }

    struct count_sketch *skt = bpf_map_lookup_elem(&um_sketch, &i);
    if (skt)
    {
        cs_update_sketch(skt, &t);
        int result = cs_query_sketch(skt, &t);
        uint64_t r = result * result;
        
        uint64_t r2 = 0;
        bpf_probe_read_kernel(&r, sizeof(r), &r);
        if (r * 10 > LAMBDA * r2 * r2) {
            insert_into_heap(skt, result, &t);
        }
    }
    return 0;
}

#define ACTION XDP_DROP

SEC("xdp")
int xdp_rcv(struct xdp_md *ctx)
{
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    struct iphdr *iphdr;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return ACTION;
    }
    struct ethhdr *eth = data;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return ACTION;
    }
    iphdr = data + sizeof(struct ethhdr);

    uint32_t key = 0;
    struct t5 t;

    if (iphdr->protocol == IPPROTO_TCP)
    {
        tcphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void*)tcphdr + sizeof(struct tcphdr) > data_end)
        {
            return ACTION;
        }
        t.src_port = tcphdr->source;
        t.dst_port = tcphdr->dest;
    }
    else if (iphdr->protocol == IPPROTO_UDP)
    {
        udphdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if ((void*)udphdr + sizeof(struct udphdr) > data_end)
        {
            return ACTION;
        }
        t.src_port = udphdr->source;
        t.dst_port = udphdr->dest;
    }
    else
    {
        return ACTION;
    }

    t.src_ip = iphdr->saddr;
    t.dst_ip = iphdr->daddr;
    t.protocol = iphdr->protocol;

    struct ctx loop_ctx;

    uint32_t sk = fasthash32(&t, sizeof(struct t5), SEED_UNIVMON);
    sk &= 0xfffffffe;
    
    
    uint32_t max_l = min(trailing_zeros2(sk), LAYERS);
    loop_ctx.max_l = max_l;
    loop_ctx.t = t;
    

    uint32_t gs_key = 0;
    struct global_stats *gs = bpf_map_lookup_elem(&stats, &gs_key);
    if (gs)
    {
        __sync_fetch_and_add(&gs->total_pkts, 1);
        //loop_ctx.tot = gs->total_pkts;
    }

    

    bpf_loop(LAYERS, update, &loop_ctx, 0);

    return XDP_DROP;
}
