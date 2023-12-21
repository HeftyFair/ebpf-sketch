
#include <iostream>
#include <asm-generic/int-ll64.h>

#define SEED_UNIVMON 0x9747b28c

struct t5 {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} __attribute__((packed));

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



static uint32_t trailing_zeros2(uint32_t V) {
	V = V-(V&(V-1));
	return( ( ( V & 0xFFFF0000 ) != 0 ? ( V &= 0xFFFF0000, 16 ) : 0 ) | ( ( V & 0xFF00FF00 ) != 0 ? ( V &= 0xFF00FF00, 8 ) : 0 ) | ( ( V & 0xF0F0F0F0 ) != 0 ? ( V &= 0xF0F0F0F0, 4 ) : 0 ) | ( ( V & 0xCCCCCCCC ) != 0 ? ( V &= 0xCCCCCCCC, 2 ) : 0 ) | ( ( V & 0xAAAAAAAA ) != 0 ) );
}


int main() {
    std::cout << trailing_zeros2(0x00000001) << std::endl;

    std::cout << trailing_zeros2(0x00000002) << std::endl;
    std::cout << trailing_zeros2(0x00000004) << std::endl;

    struct t5 t {0};
    
    // test fasthash32 of t and print hash value
    // stdout hash value
    std::cout << std::hex << fasthash64(&t, sizeof(t), SEED_UNIVMON) << std::endl;
    //std::cout << fasthash32(&t, sizeof(t), 0) << std::endl;


    // print fast hash value

    // load and attach xdp program
}