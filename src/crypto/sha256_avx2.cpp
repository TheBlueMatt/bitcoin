#ifdef ENABLE_AVX2

#include <stdint.h>
#if defined(_MSC_VER)
#include <immintrin.h>
#elif defined(__GNUC__)
#include <x86intrin.h>
#endif

#include "crypto/sha256.h"
#include "crypto/common.h"

namespace sha256_avx2 {
namespace {

__m256i inline K(uint32_t x) { return _mm256_set1_epi32(x); }

__m256i inline Add(__m256i x, __m256i y) { return _mm256_add_epi32(x, y); }
__m256i inline Add(__m256i x, __m256i y, __m256i z) { return Add(Add(x, y), z); }
__m256i inline Add(__m256i x, __m256i y, __m256i z, __m256i w) { return Add(Add(x, y), Add(z, w)); }
__m256i inline Add(__m256i x, __m256i y, __m256i z, __m256i w, __m256i v) { return Add(Add(x, y, z), Add(w, v)); }
__m256i inline Inc(__m256i& x, __m256i y) { x = Add(x, y); return x; }
__m256i inline Inc(__m256i& x, __m256i y, __m256i z) { x = Add(x, y, z); return x; }
__m256i inline Inc(__m256i& x, __m256i y, __m256i z, __m256i w) { x = Add(x, y, z, w); return x; }
__m256i inline Xor(__m256i x, __m256i y) { return _mm256_xor_si256(x, y); }
__m256i inline Xor(__m256i x, __m256i y, __m256i z) { return Xor(Xor(x, y), z); }
__m256i inline Or(__m256i x, __m256i y) { return _mm256_or_si256(x, y); }
__m256i inline And(__m256i x, __m256i y) { return _mm256_and_si256(x, y); }
__m256i inline ShR(__m256i x, int n) { return _mm256_srli_epi32(x, n); }
__m256i inline ShL(__m256i x, int n) { return _mm256_slli_epi32(x, n); }

__m256i inline Ch(__m256i x, __m256i y, __m256i z) { return Xor(z, And(x, Xor(y, z))); }
__m256i inline Maj(__m256i x, __m256i y, __m256i z) { return Or(And(x, y), And(z, Or(x, y))); }
__m256i inline Sigma0(__m256i x) { return Xor(Or(ShR(x, 2), ShL(x, 30)), Or(ShR(x, 13), ShL(x, 19)), Or(ShR(x, 22), ShL(x, 10))); }
__m256i inline Sigma1(__m256i x) { return Xor(Or(ShR(x, 6), ShL(x, 26)), Or(ShR(x, 11), ShL(x, 21)), Or(ShR(x, 25), ShL(x, 7))); }
__m256i inline sigma0(__m256i x) { return Xor(Or(ShR(x, 7), ShL(x, 25)), Or(ShR(x, 18), ShL(x, 14)), ShR(x, 3)); }
__m256i inline sigma1(__m256i x) { return Xor(Or(ShR(x, 17), ShL(x, 15)), Or(ShR(x, 19), ShL(x, 13)), ShR(x, 10)); }

/** One round of SHA-256. */
void inline __attribute__((always_inline)) Round(__m256i a, __m256i b, __m256i c, __m256i& d, __m256i e, __m256i f, __m256i g, __m256i& h, __m256i k)
{
    __m256i t1 = Add(h, Sigma1(e), Ch(e, f, g), k);
    __m256i t2 = Add(Sigma0(a), Maj(a, b, c));
    d = Add(d, t1);
    h = Add(t1, t2);
}

__m256i inline Read8(const unsigned char* chunk, int offset) {
    return _mm256_set_epi32(
        ReadBE32(chunk + 0 + offset),
        ReadBE32(chunk + 64 + offset),
        ReadBE32(chunk + 128 + offset),
        ReadBE32(chunk + 192 + offset),
        ReadBE32(chunk + 256 + offset),
        ReadBE32(chunk + 320 + offset),
        ReadBE32(chunk + 384 + offset),
        ReadBE32(chunk + 448 + offset)
    );
}

void inline Write8(unsigned char* out, int offset, __m256i v) {
    WriteBE32(out + 0 + offset, _mm256_extract_epi32(v, 7));
    WriteBE32(out + 32 + offset, _mm256_extract_epi32(v, 6));
    WriteBE32(out + 64 + offset, _mm256_extract_epi32(v, 5));
    WriteBE32(out + 96 + offset, _mm256_extract_epi32(v, 4));
    WriteBE32(out + 128 + offset, _mm256_extract_epi32(v, 3));
    WriteBE32(out + 160 + offset, _mm256_extract_epi32(v, 2));
    WriteBE32(out + 192 + offset, _mm256_extract_epi32(v, 1));
    WriteBE32(out + 224 + offset, _mm256_extract_epi32(v, 0));
}

}

void TransformDouble64_8way(unsigned char* out, const unsigned char* in)
{
    // Transform 1
    __m256i a = K(0x6a09e667ul);
    __m256i b = K(0xbb67ae85ul);
    __m256i c = K(0x3c6ef372ul);
    __m256i d = K(0xa54ff53aul);
    __m256i e = K(0x510e527ful);
    __m256i f = K(0x9b05688cul);
    __m256i g = K(0x1f83d9abul);
    __m256i h = K(0x5be0cd19ul);

    __m256i w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, b, c, d, e, f, g, h, Add(K(0x428a2f98ul), w0 = Read8(in, 0)));
    Round(h, a, b, c, d, e, f, g, Add(K(0x71374491ul), w1 = Read8(in, 4)));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb5c0fbcful), w2 = Read8(in, 8)));
    Round(f, g, h, a, b, c, d, e, Add(K(0xe9b5dba5ul), w3 = Read8(in, 12)));
    Round(e, f, g, h, a, b, c, d, Add(K(0x3956c25bul), w4 = Read8(in, 16)));
    Round(d, e, f, g, h, a, b, c, Add(K(0x59f111f1ul), w5 = Read8(in, 20)));
    Round(c, d, e, f, g, h, a, b, Add(K(0x923f82a4ul), w6 = Read8(in, 24)));
    Round(b, c, d, e, f, g, h, a, Add(K(0xab1c5ed5ul), w7 = Read8(in, 28)));
    Round(a, b, c, d, e, f, g, h, Add(K(0xd807aa98ul), w8 = Read8(in, 32)));
    Round(h, a, b, c, d, e, f, g, Add(K(0x12835b01ul), w9 = Read8(in, 36)));
    Round(g, h, a, b, c, d, e, f, Add(K(0x243185beul), w10 = Read8(in, 40)));
    Round(f, g, h, a, b, c, d, e, Add(K(0x550c7dc3ul), w11 = Read8(in, 44)));
    Round(e, f, g, h, a, b, c, d, Add(K(0x72be5d74ul), w12 = Read8(in, 48)));
    Round(d, e, f, g, h, a, b, c, Add(K(0x80deb1feul), w13 = Read8(in, 52)));
    Round(c, d, e, f, g, h, a, b, Add(K(0x9bdc06a7ul), w14 = Read8(in, 56)));
    Round(b, c, d, e, f, g, h, a, Add(K(0xc19bf174ul), w15 = Read8(in, 60)));
    Round(a, b, c, d, e, f, g, h, Add(K(0xe49b69c1ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xefbe4786ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x0fc19dc6ul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x240ca1ccul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x2de92c6ful), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4a7484aaul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5cb0a9dcul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x76f988daul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x983e5152ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa831c66dul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb00327c8ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0xbf597fc7ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0xc6e00bf3ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd5a79147ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x06ca6351ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x14292967ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x27b70a85ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x2e1b2138ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x4d2c6dfcul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x53380d13ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x650a7354ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x766a0abbul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x81c2c92eul), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x92722c85ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0xa2bfe8a1ul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa81a664bul), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0xc24b8b70ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0xc76c51a3ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0xd192e819ul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd6990624ul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xf40e3585ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x106aa070ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x19a4c116ul), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x1e376c08ul), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x2748774cul), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x34b0bcb5ul), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x391c0cb3ul), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4ed8aa4aul), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5b9cca4ful), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x682e6ff3ul), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x748f82eeul), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x78a5636ful), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x84c87814ul), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x8cc70208ul), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x90befffaul), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xa4506cebul), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xbef9a3f7ul), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0xc67178f2ul), Inc(w15, sigma1(w13), w8, sigma0(w0))));

    a = Add(a, K(0x6a09e667ul));
    b = Add(b, K(0xbb67ae85ul));
    c = Add(c, K(0x3c6ef372ul));
    d = Add(d, K(0xa54ff53aul));
    e = Add(e, K(0x510e527ful));
    f = Add(f, K(0x9b05688cul));
    g = Add(g, K(0x1f83d9abul));
    h = Add(h, K(0x5be0cd19ul));

    __m256i t0 = a, t1 = b, t2 = c, t3 = d, t4 = e, t5 = f, t6 = g, t7 = h;

    // Transform 2
    Round(a, b, c, d, e, f, g, h, K(0xc28a2f98));
    Round(h, a, b, c, d, e, f, g, K(0x71374491));
    Round(g, h, a, b, c, d, e, f, K(0xb5c0fbcf));
    Round(f, g, h, a, b, c, d, e, K(0xe9b5dba5));
    Round(e, f, g, h, a, b, c, d, K(0x3956c25b));
    Round(d, e, f, g, h, a, b, c, K(0x59f111f1));
    Round(c, d, e, f, g, h, a, b, K(0x923f82a4));
    Round(b, c, d, e, f, g, h, a, K(0xab1c5ed5));
    Round(a, b, c, d, e, f, g, h, K(0xd807aa98));
    Round(h, a, b, c, d, e, f, g, K(0x12835b01));
    Round(g, h, a, b, c, d, e, f, K(0x243185be));
    Round(f, g, h, a, b, c, d, e, K(0x550c7dc3));
    Round(e, f, g, h, a, b, c, d, K(0x72be5d74));
    Round(d, e, f, g, h, a, b, c, K(0x80deb1fe));
    Round(c, d, e, f, g, h, a, b, K(0x9bdc06a7));
    Round(b, c, d, e, f, g, h, a, K(0xc19bf374));
    Round(a, b, c, d, e, f, g, h, K(0x649b69c1));
    Round(h, a, b, c, d, e, f, g, K(0xf0fe4786));
    Round(g, h, a, b, c, d, e, f, K(0x0fe1edc6));
    Round(f, g, h, a, b, c, d, e, K(0x240cf254));
    Round(e, f, g, h, a, b, c, d, K(0x4fe9346f));
    Round(d, e, f, g, h, a, b, c, K(0x6cc984be));
    Round(c, d, e, f, g, h, a, b, K(0x61b9411e));
    Round(b, c, d, e, f, g, h, a, K(0x16f988fa));
    Round(a, b, c, d, e, f, g, h, K(0xf2c65152));
    Round(h, a, b, c, d, e, f, g, K(0xa88e5a6d));
    Round(g, h, a, b, c, d, e, f, K(0xb019fc65));
    Round(f, g, h, a, b, c, d, e, K(0xb9d99ec7));
    Round(e, f, g, h, a, b, c, d, K(0x9a1231c3));
    Round(d, e, f, g, h, a, b, c, K(0xe70eeaa0));
    Round(c, d, e, f, g, h, a, b, K(0xfdb1232b));
    Round(b, c, d, e, f, g, h, a, K(0xc7353eb0));
    Round(a, b, c, d, e, f, g, h, K(0x3069bad5));
    Round(h, a, b, c, d, e, f, g, K(0xcb976d5f));
    Round(g, h, a, b, c, d, e, f, K(0x5a0f118f));
    Round(f, g, h, a, b, c, d, e, K(0xdc1eeefd));
    Round(e, f, g, h, a, b, c, d, K(0x0a35b689));
    Round(d, e, f, g, h, a, b, c, K(0xde0b7a04));
    Round(c, d, e, f, g, h, a, b, K(0x58f4ca9d));
    Round(b, c, d, e, f, g, h, a, K(0xe15d5b16));
    Round(a, b, c, d, e, f, g, h, K(0x007f3e86));
    Round(h, a, b, c, d, e, f, g, K(0x37088980));
    Round(g, h, a, b, c, d, e, f, K(0xa507ea32));
    Round(f, g, h, a, b, c, d, e, K(0x6fab9537));
    Round(e, f, g, h, a, b, c, d, K(0x17406110));
    Round(d, e, f, g, h, a, b, c, K(0x0d8cd6f1));
    Round(c, d, e, f, g, h, a, b, K(0xcdaa3b6d));
    Round(b, c, d, e, f, g, h, a, K(0xc0bbbe37));
    Round(a, b, c, d, e, f, g, h, K(0x83613bda));
    Round(h, a, b, c, d, e, f, g, K(0xdb48a363));
    Round(g, h, a, b, c, d, e, f, K(0x0b02e931));
    Round(f, g, h, a, b, c, d, e, K(0x6fd15ca7));
    Round(e, f, g, h, a, b, c, d, K(0x521afaca));
    Round(d, e, f, g, h, a, b, c, K(0x31338431));
    Round(c, d, e, f, g, h, a, b, K(0x6ed41a95));
    Round(b, c, d, e, f, g, h, a, K(0x6d437890));
    Round(a, b, c, d, e, f, g, h, K(0xc39c91f2));
    Round(h, a, b, c, d, e, f, g, K(0x9eccabbd));
    Round(g, h, a, b, c, d, e, f, K(0xb5c9a0e6));
    Round(f, g, h, a, b, c, d, e, K(0x532fb63c));
    Round(e, f, g, h, a, b, c, d, K(0xd2c741c6));
    Round(d, e, f, g, h, a, b, c, K(0x07237ea3));
    Round(c, d, e, f, g, h, a, b, K(0xa4954b68));
    Round(b, c, d, e, f, g, h, a, K(0x4c191d76));

    w0 = Add(t0, a);
    w1 = Add(t1, b);
    w2 = Add(t2, c);
    w3 = Add(t3, d);
    w4 = Add(t4, e);
    w5 = Add(t5, f);
    w6 = Add(t6, g);
    w7 = Add(t7, h);

    // Transform 3
    a = K(0x6a09e667ul);
    b = K(0xbb67ae85ul);
    c = K(0x3c6ef372ul);
    d = K(0xa54ff53aul);
    e = K(0x510e527ful);
    f = K(0x9b05688cul);
    g = K(0x1f83d9abul);
    h = K(0x5be0cd19ul);

    Round(a, b, c, d, e, f, g, h, Add(K(0x428a2f98), w0));
    Round(h, a, b, c, d, e, f, g, Add(K(0x71374491), w1));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb5c0fbcf), w2));
    Round(f, g, h, a, b, c, d, e, Add(K(0xe9b5dba5), w3));
    Round(e, f, g, h, a, b, c, d, Add(K(0x3956c25b), w4));
    Round(d, e, f, g, h, a, b, c, Add(K(0x59f111f1), w5));
    Round(c, d, e, f, g, h, a, b, Add(K(0x923f82a4), w6));
    Round(b, c, d, e, f, g, h, a, Add(K(0xab1c5ed5), w7));
    Round(a, b, c, d, e, f, g, h, K(0x5807aa98));
    Round(h, a, b, c, d, e, f, g, K(0x12835b01));
    Round(g, h, a, b, c, d, e, f, K(0x243185be));
    Round(f, g, h, a, b, c, d, e, K(0x550c7dc3));
    Round(e, f, g, h, a, b, c, d, K(0x72be5d74));
    Round(d, e, f, g, h, a, b, c, K(0x80deb1fe));
    Round(c, d, e, f, g, h, a, b, K(0x9bdc06a7));
    Round(b, c, d, e, f, g, h, a, K(0xc19bf274));
    Round(a, b, c, d, e, f, g, h, Add(K(0xe49b69c1), Inc(w0, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xefbe4786), Inc(w1, K(0xa00000), sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x0fc19dc6), Inc(w2, sigma1(w0), sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x240ca1cc), Inc(w3, sigma1(w1), sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x2de92c6f), Inc(w4, sigma1(w2), sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4a7484aa), Inc(w5, sigma1(w3), sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5cb0a9dc), Inc(w6, sigma1(w4), K(0x100), sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x76f988da), Inc(w7, sigma1(w5), w0, K(0x11002000))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x983e5152), w8 = Add(K(0x80000000), sigma1(w6), w1)));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa831c66d), w9 = Add(sigma1(w7), w2)));
    Round(g, h, a, b, c, d, e, f, Add(K(0xb00327c8), w10 = Add(sigma1(w8), w3)));
    Round(f, g, h, a, b, c, d, e, Add(K(0xbf597fc7), w11 = Add(sigma1(w9), w4)));
    Round(e, f, g, h, a, b, c, d, Add(K(0xc6e00bf3), w12 = Add(sigma1(w10), w5)));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd5a79147), w13 = Add(sigma1(w11), w6)));
    Round(c, d, e, f, g, h, a, b, Add(K(0x06ca6351), w14 = Add(sigma1(w12), w7, sigma0(K(0x100)))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x14292967), w15 = Add(K(0x100), sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x27b70a85), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x2e1b2138), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x4d2c6dfc), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x53380d13), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x650a7354), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x766a0abb), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x81c2c92e), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x92722c85), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0xa2bfe8a1), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0xa81a664b), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0xc24b8b70), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0xc76c51a3), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0xd192e819), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xd6990624), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xf40e3585), Inc(w14, sigma1(w12), w7, sigma0(w15))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x106aa070), Inc(w15, sigma1(w13), w8, sigma0(w0))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x19a4c116), Inc(w0, sigma1(w14), w9, sigma0(w1))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x1e376c08), Inc(w1, sigma1(w15), w10, sigma0(w2))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x2748774c), Inc(w2, sigma1(w0), w11, sigma0(w3))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x34b0bcb5), Inc(w3, sigma1(w1), w12, sigma0(w4))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x391c0cb3), Inc(w4, sigma1(w2), w13, sigma0(w5))));
    Round(d, e, f, g, h, a, b, c, Add(K(0x4ed8aa4a), Inc(w5, sigma1(w3), w14, sigma0(w6))));
    Round(c, d, e, f, g, h, a, b, Add(K(0x5b9cca4f), Inc(w6, sigma1(w4), w15, sigma0(w7))));
    Round(b, c, d, e, f, g, h, a, Add(K(0x682e6ff3), Inc(w7, sigma1(w5), w0, sigma0(w8))));
    Round(a, b, c, d, e, f, g, h, Add(K(0x748f82ee), Inc(w8, sigma1(w6), w1, sigma0(w9))));
    Round(h, a, b, c, d, e, f, g, Add(K(0x78a5636f), Inc(w9, sigma1(w7), w2, sigma0(w10))));
    Round(g, h, a, b, c, d, e, f, Add(K(0x84c87814), Inc(w10, sigma1(w8), w3, sigma0(w11))));
    Round(f, g, h, a, b, c, d, e, Add(K(0x8cc70208), Inc(w11, sigma1(w9), w4, sigma0(w12))));
    Round(e, f, g, h, a, b, c, d, Add(K(0x90befffa), Inc(w12, sigma1(w10), w5, sigma0(w13))));
    Round(d, e, f, g, h, a, b, c, Add(K(0xa4506ceb), Inc(w13, sigma1(w11), w6, sigma0(w14))));
    Round(c, d, e, f, g, h, a, b, Add(K(0xbef9a3f7), w14, sigma1(w12), w7, sigma0(w15)));
    Round(b, c, d, e, f, g, h, a, Add(K(0xc67178f2), w15, sigma1(w13), w8, sigma0(w0)));

    // Output
    Write8(out, 0, Add(a, K(0x6a09e667ul)));
    Write8(out, 4, Add(b, K(0xbb67ae85ul)));
    Write8(out, 8, Add(c, K(0x3c6ef372ul)));
    Write8(out, 12, Add(d, K(0xa54ff53aul)));
    Write8(out, 16, Add(e, K(0x510e527ful)));
    Write8(out, 20, Add(f, K(0x9b05688cul)));
    Write8(out, 24, Add(g, K(0x1f83d9abul)));
    Write8(out, 28, Add(h, K(0x5be0cd19ul)));
}

}

#endif
