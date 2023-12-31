#include <stdint.h>
#include <stdint.h>
#include <linux/types.h>
#include <stddef.h>

static int average_without_overflow(int a, int b)
{
    return (a & b) + ((a ^ b) >> 1);
}

static int __always_inline median(int *vect, int len)
{
    int temp;
    int i, j;
    // the following two loops sort the array in ascending order
    // FIXME: We might implement something more efficient here (e.g., quicksort)
    for (i = 0; i < len - 1; i++)
    {
        for (j = i + 1; j < len; j++)
        {
            if (vect[j] < vect[i])
            {
                // swap elements
                temp = vect[i];
                vect[i] = vect[j];
                vect[j] = temp;
            }
        }
    }

    if ((len & 1) == 0)
    {
        // if there is an even number of elements, return mean of the two elements in the middle
        // return((vect[len/2] + vect[len/2 - 1]) / 2);
        return average_without_overflow(vect[len / 2], vect[len / 2 - 1]);
    }
    else
    {
        // else return the element in the middle
        return vect[len / 2];
    }
    /// return
}

static __attribute__((always_inline)) uint32_t min(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}

static uint32_t trailing_zeros2(uint32_t V)
{
    V = V - (V & (V - 1));
    return (((V & 0xFFFF0000) != 0 ? (V &= 0xFFFF0000, 16) : 0) | ((V & 0xFF00FF00) != 0 ? (V &= 0xFF00FF00, 8) : 0) | ((V & 0xF0F0F0F0) != 0 ? (V &= 0xF0F0F0F0, 4) : 0) | ((V & 0xCCCCCCCC) != 0 ? (V &= 0xCCCCCCCC, 2) : 0) | ((V & 0xAAAAAAAA) != 0));
}

static __attribute__((always_inline)) uint32_t trailing_zeros(unsigned int number)
{
    uint32_t count = 0;
    while (number & 1)
    {
        number >>= 1;
        count++;
    }
    return count;
}

// Compression function for Merkle-Damgard construction.
// This function is generated using the framework provided.
static __attribute__((always_inline)) inline __u64 fasthash_mix(__u64 h)
{
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

    while (pos != end)
    {
        v = *pos++;
        h ^= fasthash_mix(v);
        h *= m;
    }

    pos2 = (const unsigned char *)pos;
    v = 0;

    switch (len & 7)
    {
    case 7:
        v ^= (__u64)pos2[6] << 48;
    case 6:
        v ^= (__u64)pos2[5] << 40;
    case 5:
        v ^= (__u64)pos2[4] << 32;
    case 4:
        v ^= (__u64)pos2[3] << 24;
    case 3:
        v ^= (__u64)pos2[2] << 16;
    case 2:
        v ^= (__u64)pos2[1] << 8;
    case 1:
        v ^= (__u64)pos2[0];
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