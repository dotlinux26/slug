#include "src/crypto/xchacha20poly1305.hpp"
#include <cstring>
#include <algorithm>
#include <openssl/crypto.h>

namespace slug::crypto {

namespace {

inline uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t load32_le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) |
          (static_cast<uint32_t>(p[1]) << 8) |
          (static_cast<uint32_t>(p[2]) << 16) |
          (static_cast<uint32_t>(p[3]) << 24);
}

inline void store32_le(uint8_t* p, uint32_t x) {
    p[0] = static_cast<uint8_t>(x);
    p[1] = static_cast<uint8_t>(x >> 8);
    p[2] = static_cast<uint8_t>(x >> 16);
    p[3] = static_cast<uint8_t>(x >> 24);
}

inline void store64_le(uint8_t* p, uint64_t x) {
    for (int i = 0; i < 8; ++i) {
        p[i] = static_cast<uint8_t>(x >> (i * 8));
    }
}

#define CHACHA_QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = rotl32(d, 16); \
    c += d; b ^= c; b = rotl32(b, 12); \
    a += b; d ^= a; d = rotl32(d, 8);  \
    c += d; b ^= c; b = rotl32(b, 7);

void chacha20_block(uint32_t state[16], uint8_t out[64]) {
    uint32_t x[16];
    std::memcpy(x, state, 16 * sizeof(uint32_t));

    for (int i = 0; i < 10; ++i) {
        // Column rounds
        CHACHA_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTERROUND(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        CHACHA_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; ++i) {
        x[i] += state[i];
        store32_le(out + i * 4, x[i]);
    }
}

// HChaCha20 for deriving 32-byte subkey from 32-byte key and 16-byte nonce
void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out_subkey[32]) {
    uint32_t x[16];
    // Constants: "expand 32-byte k"
    x[0] = 0x61707865;
    x[1] = 0x3320646e;
    x[2] = 0x79622d32;
    x[3] = 0x6b206574;

    for (int i = 0; i < 8; ++i) {
        x[4 + i] = load32_le(key + i * 4);
    }
    for (int i = 0; i < 4; ++i) {
        x[12 + i] = load32_le(nonce + i * 4);
    }

    for (int i = 0; i < 10; ++i) {
        CHACHA_QUARTERROUND(x[0], x[4], x[8],  x[12]);
        CHACHA_QUARTERROUND(x[1], x[5], x[9],  x[13]);
        CHACHA_QUARTERROUND(x[2], x[6], x[10], x[14]);
        CHACHA_QUARTERROUND(x[3], x[7], x[11], x[15]);
        CHACHA_QUARTERROUND(x[0], x[5], x[10], x[15]);
        CHACHA_QUARTERROUND(x[1], x[6], x[11], x[12]);
        CHACHA_QUARTERROUND(x[2], x[7], x[8],  x[13]);
        CHACHA_QUARTERROUND(x[3], x[4], x[9],  x[14]);
    }

    store32_le(out_subkey + 0,  x[0]);
    store32_le(out_subkey + 4,  x[1]);
    store32_le(out_subkey + 8,  x[2]);
    store32_le(out_subkey + 12, x[3]);
    store32_le(out_subkey + 16, x[12]);
    store32_le(out_subkey + 20, x[13]);
    store32_le(out_subkey + 24, x[14]);
    store32_le(out_subkey + 28, x[15]);
}

// Poly1305 implementation
struct Poly1305State {
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;
    uint32_t h0, h1, h2, h3, h4;
    uint8_t pad[16];
    size_t leftover;
    uint8_t buffer[16];
};

void poly1305_init(Poly1305State* st, const uint8_t key[32]) {
    uint32_t t0 = load32_le(key + 0);
    uint32_t t1 = load32_le(key + 4);
    uint32_t t2 = load32_le(key + 8);
    uint32_t t3 = load32_le(key + 12);

    st->r0 = t0 & 0x3ffffff;
    st->r1 = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
    st->r2 = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
    st->r3 = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
    st->r4 = (t3 >> 8) & 0x00fffff;

    st->s1 = st->r1 * 5;
    st->s2 = st->r2 * 5;
    st->s3 = st->r3 * 5;
    st->s4 = st->r4 * 5;

    st->h0 = st->h1 = st->h2 = st->h3 = st->h4 = 0;
    std::memcpy(st->pad, key + 16, 16);
    st->leftover = 0;
}

void poly1305_blocks(Poly1305State* st, const uint8_t* m, size_t bytes, uint32_t hibit) {
    uint32_t h0 = st->h0, h1 = st->h1, h2 = st->h2, h3 = st->h3, h4 = st->h4;
    uint32_t r0 = st->r0, r1 = st->r1, r2 = st->r2, r3 = st->r3, r4 = st->r4;
    uint32_t s1 = st->s1, s2 = st->s2, s3 = st->s3, s4 = st->s4;

    while (bytes >= 16) {
        uint32_t t0 = load32_le(m + 0);
        uint32_t t1 = load32_le(m + 4);
        uint32_t t2 = load32_le(m + 8);
        uint32_t t3 = load32_le(m + 12);

        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | (hibit << 24);

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        m += 16;
        bytes -= 16;
    }

    st->h0 = h0; st->h1 = h1; st->h2 = h2; st->h3 = h3; st->h4 = h4;
}

void poly1305_update(Poly1305State* st, const uint8_t* m, size_t bytes) {
    if (st->leftover) {
        size_t want = 16 - st->leftover;
        if (want > bytes) want = bytes;
        std::memcpy(st->buffer + st->leftover, m, want);
        bytes -= want;
        m += want;
        st->leftover += want;
        if (st->leftover < 16) return;
        poly1305_blocks(st, st->buffer, 16, 1);
        st->leftover = 0;
    }

    if (bytes >= 16) {
        size_t want = bytes & ~(size_t)15;
        poly1305_blocks(st, m, want, 1);
        m += want;
        bytes -= want;
    }

    if (bytes) {
        std::memcpy(st->buffer + st->leftover, m, bytes);
        st->leftover += bytes;
    }
}

void poly1305_finish(Poly1305State* st, uint8_t mac[16]) {
    if (st->leftover) {
        size_t i = st->leftover;
        st->buffer[i++] = 1;
        while (i < 16) st->buffer[i++] = 0;
        poly1305_blocks(st, st->buffer, 16, 0);
    }

    uint32_t h0 = st->h0, h1 = st->h1, h2 = st->h2, h3 = st->h3, h4 = st->h4;
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;

    uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff;
    uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff;
    uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    uint32_t g4 = h4 + c - (1 << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0;
    h1 = (h1 & mask) | g1;
    h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3;
    h4 = (h4 & mask) | g4;

    uint64_t f0 = ((uint64_t)h0) | ((uint64_t)h1 << 26);
    uint64_t f1 = ((uint64_t)h1 >> 6) | ((uint64_t)h2 << 20) | ((uint64_t)h3 << 46);
    uint64_t f2 = ((uint64_t)h3 >> 18) | ((uint64_t)h4 << 8);

    f0 += load32_le(st->pad + 0);
    f1 += load32_le(st->pad + 4) + (f0 >> 32);
    f2 += load32_le(st->pad + 8) + (f1 >> 32);
    uint64_t f3 = load32_le(st->pad + 12) + (f2 >> 32);

    store32_le(mac + 0, (uint32_t)f0);
    store32_le(mac + 4, (uint32_t)f1);
    store32_le(mac + 8, (uint32_t)f2);
    store32_le(mac + 12, (uint32_t)f3);
}

} // anonymous namespace

std::vector<uint8_t> XChaCha20Poly1305::encrypt(
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t, kKeySize> key,
    std::span<const uint8_t, kNonceSize> nonce,
    std::span<const uint8_t> aad) {

    uint8_t subkey[32];
    hchacha20(key.data(), nonce.data(), subkey);

    // Standard ChaCha20 state initialized with subkey and last 8 bytes of nonce (as 12-byte IV with 4 zero bytes)
    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(subkey + i * 4);
    }
    state[12] = 0; // counter = 0
    state[13] = 0; // IV prefix
    state[14] = load32_le(nonce.data() + 16);
    state[15] = load32_le(nonce.data() + 20);

    // Generate Poly1305 one-time key from counter = 0
    uint8_t block0[64];
    chacha20_block(state, block0);
    Poly1305State poly_st;
    poly1305_init(&poly_st, block0);

    // Encrypt plaintext with counter starting at 1
    std::vector<uint8_t> output(plaintext.size() + kTagSize);
    uint8_t* ct_ptr = output.data();

    state[12] = 1;
    size_t remaining = plaintext.size();
    size_t offset = 0;
    while (remaining > 0) {
        uint8_t keystream[64];
        chacha20_block(state, keystream);
        state[12]++;

        size_t chunk = std::min(remaining, (size_t)64);
        for (size_t i = 0; i < chunk; ++i) {
            ct_ptr[offset + i] = plaintext[offset + i] ^ keystream[i];
        }
        offset += chunk;
        remaining -= chunk;
    }

    // Poly1305 calculation: AAD || pad(AAD) || CT || pad(CT) || len(AAD) || len(CT)
    static const uint8_t zeros[16] = {0};
    if (!aad.empty()) {
        poly1305_update(&poly_st, aad.data(), aad.size());
        if (aad.size() % 16 != 0) {
            poly1305_update(&poly_st, zeros, 16 - (aad.size() % 16));
        }
    }
    if (!plaintext.empty()) {
        poly1305_update(&poly_st, ct_ptr, plaintext.size());
        if (plaintext.size() % 16 != 0) {
            poly1305_update(&poly_st, zeros, 16 - (plaintext.size() % 16));
        }
    }

    uint8_t lens[16];
    store64_le(lens + 0, aad.size());
    store64_le(lens + 8, plaintext.size());
    poly1305_update(&poly_st, lens, 16);

    poly1305_finish(&poly_st, output.data() + plaintext.size());
    OPENSSL_cleanse(subkey, sizeof(subkey));
    OPENSSL_cleanse(state, sizeof(state));
    OPENSSL_cleanse(block0, sizeof(block0));
    return output;
}

std::optional<std::vector<uint8_t>> XChaCha20Poly1305::decrypt(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, kKeySize> key,
    std::span<const uint8_t, kNonceSize> nonce,
    std::span<const uint8_t> aad) {

    if (ciphertext_and_tag.size() < kTagSize) return std::nullopt;

    size_t ct_len = ciphertext_and_tag.size() - kTagSize;
    const uint8_t* ct_ptr = ciphertext_and_tag.data();
    const uint8_t* tag_ptr = ciphertext_and_tag.data() + ct_len;

    uint8_t subkey[32];
    hchacha20(key.data(), nonce.data(), subkey);

    uint32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; ++i) {
        state[4 + i] = load32_le(subkey + i * 4);
    }
    state[12] = 0;
    state[13] = 0;
    state[14] = load32_le(nonce.data() + 16);
    state[15] = load32_le(nonce.data() + 20);

    uint8_t block0[64];
    chacha20_block(state, block0);
    Poly1305State poly_st;
    poly1305_init(&poly_st, block0);

    static const uint8_t zeros[16] = {0};
    if (!aad.empty()) {
        poly1305_update(&poly_st, aad.data(), aad.size());
        if (aad.size() % 16 != 0) {
            poly1305_update(&poly_st, zeros, 16 - (aad.size() % 16));
        }
    }
    if (ct_len > 0) {
        poly1305_update(&poly_st, ct_ptr, ct_len);
        if (ct_len % 16 != 0) {
            poly1305_update(&poly_st, zeros, 16 - (ct_len % 16));
        }
    }

    uint8_t lens[16];
    store64_le(lens + 0, aad.size());
    store64_le(lens + 8, ct_len);
    poly1305_update(&poly_st, lens, 16);

    uint8_t calc_tag[16];
    poly1305_finish(&poly_st, calc_tag);

    // Constant-time tag check
    uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) {
        diff |= (calc_tag[i] ^ tag_ptr[i]);
    }
    if (diff != 0) {
        OPENSSL_cleanse(subkey, sizeof(subkey));
        OPENSSL_cleanse(state, sizeof(state));
        OPENSSL_cleanse(block0, sizeof(block0));
        return std::nullopt; // Tag mismatch! Reject!
    }

    // Decrypt ciphertext with counter starting at 1
    std::vector<uint8_t> plaintext(ct_len);
    state[12] = 1;
    size_t remaining = ct_len;
    size_t offset = 0;
    while (remaining > 0) {
        uint8_t keystream[64];
        chacha20_block(state, keystream);
        state[12]++;

        size_t chunk = std::min(remaining, (size_t)64);
        for (size_t i = 0; i < chunk; ++i) {
            plaintext[offset + i] = ct_ptr[offset + i] ^ keystream[i];
        }
        offset += chunk;
        remaining -= chunk;
    }

    OPENSSL_cleanse(subkey, sizeof(subkey));
    OPENSSL_cleanse(state, sizeof(state));
    OPENSSL_cleanse(block0, sizeof(block0));
    return plaintext;
}

} // namespace slug::crypto
