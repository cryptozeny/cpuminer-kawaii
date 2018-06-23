#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include "balloon.h"

#ifdef __cplusplus
extern "C"{
#endif

static void balloon_init (struct balloon_options *opts, int64_t s_cost, int32_t t_cost) {
  opts->s_cost = s_cost;
  opts->t_cost = t_cost;
}

void balloon_hash (unsigned char *input, unsigned char *output) {
  balloon (input, output);
}

void balloon (const void* input, void* output) {
  struct balloon_options opts;
  struct hash_state s;
  balloon_init (&opts, (int64_t)128, (int32_t)4);
  hash_state_init (&s, &opts, input);
  hash_state_fill (&s, input, 80);
  hash_state_mix (&s);
  uint8_t *b = block_index (&s, 4095);
  memcpy ((char *)output, (const char *)b, 32);
  hash_state_free (&s);
}

static inline void bitstream_init (struct bitstream *b) {
  SHA256_Init(&b->c);
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  b->ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_init(b->ctx);
#else
  EVP_CIPHER_CTX_init (&b->ctx);
#endif
  b->zeros = malloc (512);
  memset (b->zeros, 0, 512);
}

static inline void bitstream_free (struct bitstream *b) {
  uint8_t out[16];
  int outl;
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_EncryptFinal (b->ctx, out, &outl);
  EVP_CIPHER_CTX_free (b->ctx);
#else
  EVP_EncryptFinal (&b->ctx, out, &outl);
  EVP_CIPHER_CTX_cleanup (&b->ctx);
#endif
  free (b->zeros);
}

static inline void bitstream_seed_add (struct bitstream *b, const void *seed, size_t seedlen) {
  SHA256_Update(&b->c, seed, seedlen);
}

static inline void bitstream_seed_finalize (struct bitstream *b) {
  uint8_t key_bytes[32];
  SHA256_Final (key_bytes, &b->c);
  uint8_t iv[16];
  memset (iv, 0, 16);
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_EncryptInit (b->ctx, EVP_aes_128_ctr (), key_bytes, iv);
#else
  EVP_EncryptInit (&b->ctx, EVP_aes_128_ctr (), key_bytes, iv);
#endif
}

void bitstream_fill_buffer (struct bitstream *b, void *out, size_t outlen) {
  int encl;
#if   OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_EncryptUpdate (b->ctx, out, &encl, b->zeros, 8);
#else
  EVP_EncryptUpdate (&b->ctx, out, &encl, b->zeros, 8);
#endif
}

static void expand (uint64_t *counter, uint8_t *buf) {
  const uint8_t *blocks[1] = { buf };
  uint8_t *cur = buf + 32;
  uint8_t hashmash[40];
  int i;
  for (i = 1; i < 4096; i++) {
    SHA256_CTX ctx;
    SHA256_Init (&ctx);
    memcpy(&hashmash[0], counter, 8);
    memcpy(&hashmash[8], blocks[0], 32);
    SHA256_Update (&ctx, hashmash, 40);
    SHA256_Final (cur, &ctx);
    *counter += 1;
    blocks[0] += 32;
    cur += 32;
  }
}

void * block_index (const struct hash_state *s, size_t i) {
  return s->buffer + (32 * i);
}

void hash_state_init (struct hash_state *s, const struct balloon_options *opts, const uint8_t salt[32]) {
  s->counter = 0;
  s->buffer = malloc(131072);
  s->opts = opts;
  bitstream_init (&s->bstream);
  bitstream_seed_add (&s->bstream, salt, 32);
  bitstream_seed_add (&s->bstream, &opts->s_cost, 8);
  bitstream_seed_add (&s->bstream, &opts->t_cost, 4);
  bitstream_seed_finalize (&s->bstream);
}

void hash_state_free (struct hash_state *s) {
  bitstream_free (&s->bstream);
  free (s->buffer);
}

void hash_state_fill (struct hash_state *s, const uint8_t *in, size_t inlen) {
  uint8_t hashmash[132];
  SHA256_CTX c;
  SHA256_Init (&c);
  memcpy(&hashmash[0],&s->counter,8);
  memcpy(&hashmash[8],in,32);
  memcpy(&hashmash[40],in,80);
  memcpy(&hashmash[120],&s->opts->s_cost, 8);
  memcpy(&hashmash[128],&s->opts->t_cost, 4);
  SHA256_Update (&c, hashmash, 132);
  SHA256_Final (s->buffer, &c);
  s->counter++;
  expand (&s->counter, s->buffer);
}

void hash_state_mix (struct hash_state *s) {
  SHA256_CTX ctx;
  uint8_t buf[8];
  uint8_t hashmash[168];
  int i; 

    // round = 0
    uint64_t neighbor;
    for (i = 0; i < 4096; i++) {
      uint8_t *cur_block = s->buffer + (32 * i);
      const uint8_t *blocks[5];
      const uint8_t *prev_block = i ? cur_block - 32 : block_index (s, 4095);
      blocks[0] = prev_block;
      blocks[1] = cur_block;
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[2] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[3] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[4] = block_index (s, neighbor % 4096);
      SHA256_Init (&ctx);
      memcpy(&hashmash[0],&s->counter, 8);
      for (int j=0; j<5; j++)
        memcpy(&hashmash[8+(j*32)], blocks[j], 32);
      SHA256_Update (&ctx, hashmash, 168);
      SHA256_Final (cur_block, &ctx);
      s->counter += 1;
    }
    // round = 1
    for (i = 0; i < 4096; i++) {
      uint8_t *cur_block = s->buffer + (32 * i);
      const uint8_t *blocks[5];
      const uint8_t *prev_block = i ? cur_block - 32 : block_index (s, 4095);
      blocks[0] = prev_block;
      blocks[1] = cur_block;
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[2] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[3] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[4] = block_index (s, neighbor % 4096);
      SHA256_Init (&ctx);
      memcpy(&hashmash[0],&s->counter, 8);
      for (int j=0; j<5; j++)
        memcpy(&hashmash[8+(j*32)], blocks[j], 32);
      SHA256_Update (&ctx, hashmash, 168);
      SHA256_Final (cur_block, &ctx);
      s->counter += 1;
    }
    // round = 2
    for (i = 0; i < 4096; i++) {
      uint8_t *cur_block = s->buffer + (32 * i);
      const uint8_t *blocks[5];
      const uint8_t *prev_block = i ? cur_block - 32 : block_index (s, 4095);
      blocks[0] = prev_block;
      blocks[1] = cur_block;
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[2] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[3] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[4] = block_index (s, neighbor % 4096);
      SHA256_Init (&ctx);
      memcpy(&hashmash[0],&s->counter, 8);
      for (int j=0; j<5; j++)
        memcpy(&hashmash[8+(j*32)], blocks[j], 32);
      SHA256_Update (&ctx, hashmash, 168);
      SHA256_Final (cur_block, &ctx);
      s->counter += 1;
    }
    // round = 3
    for (i = 0; i < 4096; i++) {
      uint8_t *cur_block = s->buffer + (32 * i);
      const uint8_t *blocks[5];
      const uint8_t *prev_block = i ? cur_block - 32 : block_index (s, 4095);
      blocks[0] = prev_block;
      blocks[1] = cur_block;
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[2] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[3] = block_index (s, neighbor % 4096);
      bitstream_fill_buffer (&s->bstream, buf, 8);
      neighbor = 0;
      neighbor |= buf[7]; neighbor <<= 8; neighbor |= buf[6]; neighbor <<= 8;
      neighbor |= buf[5]; neighbor <<= 8; neighbor |= buf[4]; neighbor <<= 8;
      neighbor |= buf[3]; neighbor <<= 8; neighbor |= buf[2]; neighbor <<= 8;
      neighbor |= buf[1]; neighbor <<= 8; neighbor |= buf[0];
      blocks[4] = block_index (s, neighbor % 4096);
      SHA256_Init (&ctx);
      memcpy(&hashmash[0],&s->counter, 8);
      for (int j=0; j<5; j++)
        memcpy(&hashmash[8+(j*32)], blocks[j], 32);
      SHA256_Update (&ctx, hashmash, 168);
      SHA256_Final (cur_block, &ctx);
      s->counter += 1;
    }
}

#ifdef __cplusplus
}
#endif
