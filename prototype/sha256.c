#include "sha256.h"

#include <stdint.h>
#include <memory.h>

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))



static const uint32_t K256[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};


void sha256_init(SHA256_STATE* ctx) {
    ctx->h[0] = 0x6a09e667UL;
    ctx->h[1] = 0xbb67ae85UL;
    ctx->h[2] = 0x3c6ef372UL;
    ctx->h[3] = 0xa54ff53aUL;
    ctx->h[4] = 0x510e527fUL;
    ctx->h[5] = 0x9b05688cUL;
    ctx->h[6] = 0x1f83d9abUL;
    ctx->h[7] = 0x5be0cd19UL;
    ctx->datalen = 0;
    ctx->bitlen = 0;
}

void sha256_transform(SHA256_STATE* ctx, uint8_t* data) {
    
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t w[64];
    uint32_t i, j;

    // copy 16 4byte ints from data
    for (i = 0, j = 0; i < 16; i++, j+=4)
        w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);

    for (; i < 64; i++) {
        uint32_t s0 = ROTRIGHT(w[i-15], 7) ^ ROTRIGHT(w[i-15], 18) ^ (w[i-15] >> 3);
        uint32_t s1 = ROTRIGHT(w[i-2], 17) ^ ROTRIGHT(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    
    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (uint32_t i = 0; i < 64; i++) {
        uint32_t S1 = ROTRIGHT(e, 6) ^ ROTRIGHT(e, 11) ^ ROTRIGHT(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
        uint32_t S0 = ROTRIGHT(a, 2) ^ ROTRIGHT(a, 13) ^ ROTRIGHT(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;


}

void sha256_update(SHA256_STATE* ctx, uint8_t* data, uint32_t len) {
    for (uint32_t i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}


SHA256_HASH sha256_final(SHA256_STATE *ctx)
{
	uint32_t i;
    SHA256_HASH h;

	i = ctx->datalen;

	// Pad whatever data is left in the buffer.
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (i = 0; i < 4; ++i) {
		h.hash[i]      = (ctx->h[0] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 4]  = (ctx->h[1] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 8]  = (ctx->h[2] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 12] = (ctx->h[3] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 16] = (ctx->h[4] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 20] = (ctx->h[5] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 24] = (ctx->h[6] >> (24 - i * 8)) & 0x000000ff;
		h.hash[i + 28] = (ctx->h[7] >> (24 - i * 8)) & 0x000000ff;
	}
    return h;
}

