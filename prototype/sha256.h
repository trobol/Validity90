#ifndef _SHA256_H
#define _SHA256_H

#include <stdint.h>


typedef struct SHA256_STATE SHA256_STATE;
typedef struct SHA256_HASH SHA256_HASH;

struct SHA256_STATE {
    uint32_t h[8];
    uint32_t Nl, Nh;
    uint8_t data[64];
    uint32_t datalen;
    uint64_t bitlen;
};

struct SHA256_HASH {
    uint8_t hash[32];
};


void sha256_init(SHA256_STATE* ctx);
void sha256_transform(SHA256_STATE* ctx, uint8_t* data);
void sha256_update(SHA256_STATE* ctx, uint8_t* data, uint32_t len);
SHA256_HASH sha256_final(SHA256_STATE *ctx);
#endif