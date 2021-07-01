#include "sha256.h"
#include <string.h>

#define SHR(n, x) ((x) >> (n))
#define SHL(n, x) ((x) << (n))
#define ROTR(n, x) (SHR(n, x) | SHL(32 - n, x))
// FIPS 180-4, 4.1.2, SHA-224 and SHA-256 Functions
#define Ch(x, y, z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIGMA0(x) (ROTR(2, x) ^ ROTR(13, x) ^ ROTR(22, x))
#define SIGMA1(x) (ROTR(6, x) ^ ROTR(11, x) ^ ROTR(25, x))
#define sigma0(x) (ROTR(7, x) ^ ROTR(18, x) ^ SHR(3, x))
#define sigma1(x) (ROTR(17, x) ^ ROTR(19, x) ^ SHR(10, x))
// ceil integer division x/y
#define CEIL_DIV(x, y) (((x) + (y) - 1) / (y))

// FIPS 180-4, 4.2.2, SHA-224 and SHA-256 Constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// const uint32_t (*mi)[16], points to the i-th block
#define SHA256_BLOCK(mi) do {                                               \
    for (int t = 0; t <= 15; ++t) {                                         \
        W[t] = __builtin_bswap32((*(mi))[t]);                               \
    }                                                                       \
    for (int t = 16; t <= 63; ++t) {                                        \
        W[t] = sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]; \
    }                                                                       \
    a = H[0];                                                               \
    b = H[1];                                                               \
    c = H[2];                                                               \
    d = H[3];                                                               \
    e = H[4];                                                               \
    f = H[5];                                                               \
    g = H[6];                                                               \
    h = H[7];                                                               \
    for (int t = 0; t <= 63; ++t) {                                         \
        const uint32_t T1 = h + SIGMA1(e) + Ch(e, f, g) + K[t] + W[t];      \
        const uint32_t T2 = SIGMA0(a) + Maj(a, b, c);                       \
        h = g;                                                              \
        g = f;                                                              \
        f = e;                                                              \
        e = d + T1;                                                         \
        d = c;                                                              \
        c = b;                                                              \
        b = a;                                                              \
        a = T1 + T2;                                                        \
    }                                                                       \
    H[0] += a;                                                              \
    H[1] += b;                                                              \
    H[2] += c;                                                              \
    H[3] += d;                                                              \
    H[4] += e;                                                              \
    H[5] += f;                                                              \
    H[6] += g;                                                              \
    H[7] += h;                                                              \
} while (0)

void sha256(const void *M, const uint64_t l, void *digest)
{
    // hash values (FIPS 180-4, 5.3.3)
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    // message schedule
    uint32_t W[64];
    // working variables
    uint32_t a, b, c, d, e, f, g, h;

    const uint32_t (*Mi)[16] = (const uint32_t (*)[16])M;
    uint64_t lrem = l;
    while (lrem >= 512) {
        SHA256_BLOCK(Mi);
        ++Mi;
        lrem -= 512;
    }

    // process the remaining message bits (at most 511 bits) and padding
    uint32_t Mrem[16];
    memset(Mrem, 0, sizeof(Mrem));
    memcpy(Mrem, Mi, CEIL_DIV(lrem, 8));
    // point to the byte where the append bit "1" should be
    unsigned char *const Mend = (unsigned char*)Mrem + (lrem / 8);
    // append the bit "1"
    // 7 - x % 8 = ~x & 7
    *Mend |= 1U << (~lrem & 7);
    // clear the remaining bits
    *Mend &= 0xffU << (~lrem & 7);

    if (lrem >= 448) {
        SHA256_BLOCK(&Mrem);
        // then process the final block which is all 0s except for the last 64 bits
        // which holds l (length of the message in bits)
        memset(Mrem, 0, sizeof(Mrem));
    }

    // store l at the last 64 bits
    *((uint64_t*)Mrem + 7) = __builtin_bswap64(l);

    SHA256_BLOCK(&Mrem);

    // write the result to digest
    for (int i = 0; i < 8; ++i) {
        ((uint32_t*)digest)[i] = __builtin_bswap32(H[i]);
    }
}
