#include "fido_crypto.h"

#include <string.h>

#include "stm32f4xx_hal.h"
#include "sha256.h"
#include "uECC.h"

#define FIDO_UID_BASE 0x1FFF7A10u

typedef struct
{
  uECC_HashContext uecc;
  SHA256_CTX sha;
  uint8_t tmp[(2u * FIDO_SHA256_SIZE) + 64u];
} fido_uECC_sha256_ctx_t;

static void fido_sha256_ctx_init(const struct uECC_HashContext *base)
{
  fido_uECC_sha256_ctx_t *ctx = (fido_uECC_sha256_ctx_t *)base;
  sha256_init(&ctx->sha);
}

static void fido_sha256_ctx_update(const struct uECC_HashContext *base,
                                   const uint8_t *message,
                                   unsigned message_size)
{
  fido_uECC_sha256_ctx_t *ctx = (fido_uECC_sha256_ctx_t *)base;
  sha256_update(&ctx->sha, message, message_size);
}

static void fido_sha256_ctx_finish(const struct uECC_HashContext *base, uint8_t *hash_result)
{
  fido_uECC_sha256_ctx_t *ctx = (fido_uECC_sha256_ctx_t *)base;
  sha256_final(&ctx->sha, hash_result);
}

static void fido_load_uid(uint8_t uid[12])
{
  const uint32_t *uid_words = (const uint32_t *)FIDO_UID_BASE;

  uid[0] = (uint8_t)(uid_words[0] >> 24);
  uid[1] = (uint8_t)(uid_words[0] >> 16);
  uid[2] = (uint8_t)(uid_words[0] >> 8);
  uid[3] = (uint8_t)(uid_words[0]);
  uid[4] = (uint8_t)(uid_words[1] >> 24);
  uid[5] = (uint8_t)(uid_words[1] >> 16);
  uid[6] = (uint8_t)(uid_words[1] >> 8);
  uid[7] = (uint8_t)(uid_words[1]);
  uid[8] = (uint8_t)(uid_words[2] >> 24);
  uid[9] = (uint8_t)(uid_words[2] >> 16);
  uid[10] = (uint8_t)(uid_words[2] >> 8);
  uid[11] = (uint8_t)(uid_words[2]);
}

static void fido_store_be32(uint8_t *dst, uint32_t value)
{
  dst[0] = (uint8_t)(value >> 24);
  dst[1] = (uint8_t)(value >> 16);
  dst[2] = (uint8_t)(value >> 8);
  dst[3] = (uint8_t)value;
}

static uint8_t fido_ecdsa_raw_to_der(const uint8_t raw_sig[64],
                                     uint8_t *der,
                                     uint16_t der_cap,
                                     uint16_t *der_len);

static uint8_t fido_crypto_sign_p256_hash_der_internal(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                                       const uint8_t message_hash[FIDO_SHA256_SIZE],
                                                       uint8_t *sig_der,
                                                       uint16_t sig_der_cap,
                                                       uint16_t *sig_der_len)
{
  uint8_t raw_sig[64];
  fido_uECC_sha256_ctx_t hash_ctx;

  if ((private_key == NULL) || (message_hash == NULL) || (sig_der == NULL) || (sig_der_len == NULL))
  {
    return 0U;
  }

  memset(&hash_ctx, 0, sizeof(hash_ctx));
  hash_ctx.uecc.init_hash = &fido_sha256_ctx_init;
  hash_ctx.uecc.update_hash = &fido_sha256_ctx_update;
  hash_ctx.uecc.finish_hash = &fido_sha256_ctx_finish;
  hash_ctx.uecc.block_size = 64U;
  hash_ctx.uecc.result_size = FIDO_SHA256_SIZE;
  hash_ctx.uecc.tmp = hash_ctx.tmp;

  if (uECC_sign_deterministic(private_key,
                              message_hash,
                              FIDO_SHA256_SIZE,
                              &hash_ctx.uecc,
                              raw_sig,
                              uECC_secp256r1()) != 1)
  {
    return 0U;
  }

  return fido_ecdsa_raw_to_der(raw_sig, sig_der, sig_der_cap, sig_der_len);
}

static uint8_t s_rng_ready;
static uint8_t s_uecc_rng_ready;
static uint8_t s_aes_tables_ready;
static uint8_t s_aes_sbox[256];
static uint8_t s_aes_rsbox[256];

static uint8_t aes_rotl8(uint8_t value, uint8_t shift)
{
  return (uint8_t)((value << shift) | (value >> (8U - shift)));
}

static uint8_t aes_gf_mul(uint8_t a, uint8_t b)
{
  uint8_t result = 0U;
  uint8_t bit;

  for (bit = 0U; bit < 8U; ++bit)
  {
    if ((b & 1U) != 0U)
    {
      result ^= a;
    }
    b >>= 1U;
    a = (uint8_t)((a << 1U) ^ (((a & 0x80U) != 0U) ? 0x1BU : 0x00U));
  }

  return result;
}

static uint8_t aes_gf_inv(uint8_t value)
{
  uint16_t candidate;

  if (value == 0U)
  {
    return 0U;
  }

  for (candidate = 1U; candidate < 256U; ++candidate)
  {
    if (aes_gf_mul(value, (uint8_t)candidate) == 1U)
    {
      return (uint8_t)candidate;
    }
  }

  return 0U;
}

static void aes_init_tables(void)
{
  uint16_t i;

  if (s_aes_tables_ready != 0U)
  {
    return;
  }

  for (i = 0U; i < 256U; ++i)
  {
    uint8_t inv = aes_gf_inv((uint8_t)i);
    uint8_t s = (uint8_t)(0x63U ^
                          inv ^
                          aes_rotl8(inv, 1U) ^
                          aes_rotl8(inv, 2U) ^
                          aes_rotl8(inv, 3U) ^
                          aes_rotl8(inv, 4U));
    s_aes_sbox[i] = s;
    s_aes_rsbox[s] = (uint8_t)i;
  }

  s_aes_tables_ready = 1U;
}

static uint8_t aes_rcon(uint8_t round)
{
  uint8_t value = 1U;

  while (round > 1U)
  {
    value = aes_gf_mul(value, 0x02U);
    round--;
  }

  return value;
}

static void aes_add_round_key(uint8_t *state, const uint8_t *round_key)
{
  uint8_t i;

  for (i = 0U; i < 16U; ++i)
  {
    state[i] ^= round_key[i];
  }
}

static void aes_sub_bytes(uint8_t *state)
{
  uint8_t i;

  for (i = 0U; i < 16U; ++i)
  {
    state[i] = s_aes_sbox[state[i]];
  }
}

static void aes_inv_sub_bytes(uint8_t *state)
{
  uint8_t i;

  for (i = 0U; i < 16U; ++i)
  {
    state[i] = s_aes_rsbox[state[i]];
  }
}

static void aes_shift_rows(uint8_t *state)
{
  uint8_t tmp;

  tmp = state[1];
  state[1] = state[5];
  state[5] = state[9];
  state[9] = state[13];
  state[13] = tmp;

  tmp = state[2];
  state[2] = state[10];
  state[10] = tmp;
  tmp = state[6];
  state[6] = state[14];
  state[14] = tmp;

  tmp = state[3];
  state[3] = state[15];
  state[15] = state[11];
  state[11] = state[7];
  state[7] = tmp;
}

static void aes_inv_shift_rows(uint8_t *state)
{
  uint8_t tmp;

  tmp = state[13];
  state[13] = state[9];
  state[9] = state[5];
  state[5] = state[1];
  state[1] = tmp;

  tmp = state[2];
  state[2] = state[10];
  state[10] = tmp;
  tmp = state[6];
  state[6] = state[14];
  state[14] = tmp;

  tmp = state[3];
  state[3] = state[7];
  state[7] = state[11];
  state[11] = state[15];
  state[15] = tmp;
}

static void aes_mix_columns(uint8_t *state)
{
  uint8_t column;

  for (column = 0U; column < 4U; ++column)
  {
    uint8_t *c = &state[column * 4U];
    uint8_t a0 = c[0];
    uint8_t a1 = c[1];
    uint8_t a2 = c[2];
    uint8_t a3 = c[3];

    c[0] = (uint8_t)(aes_gf_mul(a0, 2U) ^ aes_gf_mul(a1, 3U) ^ a2 ^ a3);
    c[1] = (uint8_t)(a0 ^ aes_gf_mul(a1, 2U) ^ aes_gf_mul(a2, 3U) ^ a3);
    c[2] = (uint8_t)(a0 ^ a1 ^ aes_gf_mul(a2, 2U) ^ aes_gf_mul(a3, 3U));
    c[3] = (uint8_t)(aes_gf_mul(a0, 3U) ^ a1 ^ a2 ^ aes_gf_mul(a3, 2U));
  }
}

static void aes_inv_mix_columns(uint8_t *state)
{
  uint8_t column;

  for (column = 0U; column < 4U; ++column)
  {
    uint8_t *c = &state[column * 4U];
    uint8_t a0 = c[0];
    uint8_t a1 = c[1];
    uint8_t a2 = c[2];
    uint8_t a3 = c[3];

    c[0] = (uint8_t)(aes_gf_mul(a0, 14U) ^ aes_gf_mul(a1, 11U) ^ aes_gf_mul(a2, 13U) ^ aes_gf_mul(a3, 9U));
    c[1] = (uint8_t)(aes_gf_mul(a0, 9U) ^ aes_gf_mul(a1, 14U) ^ aes_gf_mul(a2, 11U) ^ aes_gf_mul(a3, 13U));
    c[2] = (uint8_t)(aes_gf_mul(a0, 13U) ^ aes_gf_mul(a1, 9U) ^ aes_gf_mul(a2, 14U) ^ aes_gf_mul(a3, 11U));
    c[3] = (uint8_t)(aes_gf_mul(a0, 11U) ^ aes_gf_mul(a1, 13U) ^ aes_gf_mul(a2, 9U) ^ aes_gf_mul(a3, 14U));
  }
}

static void aes_key_expand_256(const uint8_t key[32], uint8_t round_keys[240])
{
  uint16_t generated = 32U;
  uint8_t round = 1U;
  uint8_t temp[4];
  uint8_t i;

  aes_init_tables();
  memcpy(round_keys, key, 32U);

  while (generated < 240U)
  {
    memcpy(temp, &round_keys[generated - 4U], sizeof(temp));
    if ((generated % 32U) == 0U)
    {
      uint8_t t = temp[0];
      temp[0] = s_aes_sbox[temp[1]];
      temp[1] = s_aes_sbox[temp[2]];
      temp[2] = s_aes_sbox[temp[3]];
      temp[3] = s_aes_sbox[t];
      temp[0] ^= aes_rcon(round++);
    }
    else if ((generated % 32U) == 16U)
    {
      temp[0] = s_aes_sbox[temp[0]];
      temp[1] = s_aes_sbox[temp[1]];
      temp[2] = s_aes_sbox[temp[2]];
      temp[3] = s_aes_sbox[temp[3]];
    }

    for (i = 0U; i < 4U; ++i)
    {
      round_keys[generated] = (uint8_t)(round_keys[generated - 32U] ^ temp[i]);
      generated++;
    }
  }
}

static void aes_encrypt_block(const uint8_t key[32], const uint8_t input[16], uint8_t output[16])
{
  uint8_t state[16];
  uint8_t round_keys[240];
  uint8_t round;

  memcpy(state, input, sizeof(state));
  aes_key_expand_256(key, round_keys);

  aes_add_round_key(state, &round_keys[0]);
  for (round = 1U; round < 14U; ++round)
  {
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, &round_keys[round * 16U]);
  }
  aes_sub_bytes(state);
  aes_shift_rows(state);
  aes_add_round_key(state, &round_keys[14U * 16U]);

  memcpy(output, state, sizeof(state));
}

static void aes_decrypt_block(const uint8_t key[32], const uint8_t input[16], uint8_t output[16])
{
  uint8_t state[16];
  uint8_t round_keys[240];
  int round;

  memcpy(state, input, sizeof(state));
  aes_key_expand_256(key, round_keys);

  aes_add_round_key(state, &round_keys[14U * 16U]);
  for (round = 13; round > 0; --round)
  {
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, &round_keys[(uint16_t)round * 16U]);
    aes_inv_mix_columns(state);
  }
  aes_inv_shift_rows(state);
  aes_inv_sub_bytes(state);
  aes_add_round_key(state, &round_keys[0]);

  memcpy(output, state, sizeof(state));
}

static uint8_t fido_rng_word(uint32_t *value)
{
  uint32_t start_ms = HAL_GetTick();

  if (value == NULL)
  {
    return 0U;
  }
  if (s_rng_ready == 0U)
  {
    __HAL_RCC_RNG_CLK_ENABLE();
    RNG->CR |= RNG_CR_RNGEN;
    s_rng_ready = 1U;
  }

  while ((RNG->SR & RNG_SR_DRDY) == 0U)
  {
    if ((RNG->SR & (RNG_SR_CECS | RNG_SR_SECS | RNG_SR_CEIS | RNG_SR_SEIS)) != 0U)
    {
      return 0U;
    }
    if ((uint32_t)(HAL_GetTick() - start_ms) > 50U)
    {
      return 0U;
    }
  }

  *value = RNG->DR;
  return 1U;
}

static int fido_uECC_rng(uint8_t *dest, unsigned size)
{
  return (int)fido_crypto_random(dest, size);
}

static void fido_crypto_ensure_rng(void)
{
  if (s_rng_ready == 0U)
  {
    uint32_t unused_word;

    if (fido_rng_word(&unused_word) != 0U)
    {
      s_uecc_rng_ready = 0U;
    }
  }

  if ((s_rng_ready != 0U) && (s_uecc_rng_ready == 0U))
  {
    uECC_set_rng(fido_uECC_rng);
    s_uecc_rng_ready = 1U;
  }
}

static uint8_t fido_ecdsa_raw_to_der(const uint8_t raw_sig[64],
                                     uint8_t *der,
                                     uint16_t der_cap,
                                     uint16_t *der_len)
{
  const uint8_t *r = &raw_sig[0];
  const uint8_t *s = &raw_sig[32];
  uint8_t r_pad = 0U;
  uint8_t s_pad = 0U;
  uint8_t r_skip = 0U;
  uint8_t s_skip = 0U;
  uint8_t r_len;
  uint8_t s_len;
  uint8_t seq_len;
  uint16_t off = 0U;

  while ((r_skip < 31U) && (r[r_skip] == 0U) && ((r[r_skip + 1U] & 0x80U) == 0U))
  {
    r_skip++;
  }
  while ((s_skip < 31U) && (s[s_skip] == 0U) && ((s[s_skip + 1U] & 0x80U) == 0U))
  {
    s_skip++;
  }

  r_len = (uint8_t)(32U - r_skip);
  s_len = (uint8_t)(32U - s_skip);
  if ((r[r_skip] & 0x80U) != 0U)
  {
    r_pad = 1U;
  }
  if ((s[s_skip] & 0x80U) != 0U)
  {
    s_pad = 1U;
  }

  seq_len = (uint8_t)(2U + r_pad + r_len + 2U + s_pad + s_len);
  if ((der == NULL) || (der_len == NULL) || (uint16_t)(seq_len + 2U) > der_cap)
  {
    return 0U;
  }

  der[off++] = 0x30U;
  der[off++] = seq_len;
  der[off++] = 0x02U;
  der[off++] = (uint8_t)(r_pad + r_len);
  if (r_pad != 0U)
  {
    der[off++] = 0x00U;
  }
  memcpy(&der[off], &r[r_skip], r_len);
  off = (uint16_t)(off + r_len);

  der[off++] = 0x02U;
  der[off++] = (uint8_t)(s_pad + s_len);
  if (s_pad != 0U)
  {
    der[off++] = 0x00U;
  }
  memcpy(&der[off], &s[s_skip], s_len);
  off = (uint16_t)(off + s_len);

  *der_len = off;
  return 1U;
}

void fido_crypto_sha256(const uint8_t *data, uint32_t len, uint8_t out[FIDO_SHA256_SIZE])
{
  SHA256_CTX ctx;

  sha256_init(&ctx);
  if ((data != NULL) && (len != 0U))
  {
    sha256_update(&ctx, data, len);
  }
  sha256_final(&ctx, out);
}

void fido_crypto_sha256_two(const uint8_t *a,
                            uint32_t a_len,
                            const uint8_t *b,
                            uint32_t b_len,
                            uint8_t out[FIDO_SHA256_SIZE])
{
  SHA256_CTX ctx;

  sha256_init(&ctx);
  if ((a != NULL) && (a_len != 0U))
  {
    sha256_update(&ctx, a, a_len);
  }
  if ((b != NULL) && (b_len != 0U))
  {
    sha256_update(&ctx, b, b_len);
  }
  sha256_final(&ctx, out);
}

uint8_t fido_crypto_make_credential_key(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                        const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                        uint32_t counter,
                                        uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE],
                                        uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                        uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE])
{
  static const uint8_t k_key_tag[] = "ULFIDO-KEY";
  static const uint8_t k_cred_tag[] = "ULFIDO-CRED";
  uint8_t uid[12];
  uint8_t seed[32];
  uint8_t counter_buf[4];
  uint8_t attempt;
  SHA256_CTX ctx;
  uECC_Curve curve = uECC_secp256r1();

  if ((rp_id_hash == NULL) || (client_data_hash == NULL) ||
      (credential_id == NULL) || (private_key == NULL) || (public_key == NULL))
  {
    return 0U;
  }

  fido_load_uid(uid);
  fido_store_be32(counter_buf, counter);

  for (attempt = 0U; attempt < 16U; ++attempt)
  {
    sha256_init(&ctx);
    sha256_update(&ctx, k_key_tag, sizeof(k_key_tag) - 1U);
    sha256_update(&ctx, uid, sizeof(uid));
    sha256_update(&ctx, counter_buf, sizeof(counter_buf));
    sha256_update(&ctx, rp_id_hash, FIDO_SHA256_SIZE);
    sha256_update(&ctx, client_data_hash, FIDO_SHA256_SIZE);
    sha256_update(&ctx, &attempt, 1U);
    sha256_final(&ctx, seed);
    memcpy(private_key, seed, FIDO_P256_PRIVATE_KEY_SIZE);
    if (uECC_compute_public_key(private_key, public_key, curve) == 1)
    {
      sha256_init(&ctx);
      sha256_update(&ctx, k_cred_tag, sizeof(k_cred_tag) - 1U);
      sha256_update(&ctx, uid, sizeof(uid));
      sha256_update(&ctx, counter_buf, sizeof(counter_buf));
      sha256_update(&ctx, rp_id_hash, FIDO_SHA256_SIZE);
      sha256_update(&ctx, public_key, FIDO_P256_PUBLIC_KEY_SIZE);
      sha256_final(&ctx, credential_id);
      return 1U;
    }
  }

  memset(private_key, 0, FIDO_P256_PRIVATE_KEY_SIZE);
  memset(public_key, 0, FIDO_P256_PUBLIC_KEY_SIZE);
  memset(credential_id, 0, FIDO_CREDENTIAL_ID_SIZE);
  return 0U;
}

uint8_t fido_crypto_sign_es256_der(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                   const uint8_t *auth_data,
                                   uint16_t auth_data_len,
                                   const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                   uint8_t *sig_der,
                                   uint16_t sig_der_cap,
                                   uint16_t *sig_der_len)
{
  uint8_t message_hash[FIDO_SHA256_SIZE];
  SHA256_CTX msg_ctx;

  if ((auth_data == NULL) || (client_data_hash == NULL))
  {
    return 0U;
  }

  sha256_init(&msg_ctx);
  sha256_update(&msg_ctx, auth_data, auth_data_len);
  sha256_update(&msg_ctx, client_data_hash, FIDO_SHA256_SIZE);
  sha256_final(&msg_ctx, message_hash);

  return fido_crypto_sign_p256_hash_der_internal(private_key,
                                                 message_hash,
                                                 sig_der,
                                                 sig_der_cap,
                                                 sig_der_len);
}

uint8_t fido_crypto_sign_p256_sha256_der(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                         const uint8_t *data,
                                         uint16_t data_len,
                                         uint8_t *sig_der,
                                         uint16_t sig_der_cap,
                                         uint16_t *sig_der_len)
{
  uint8_t message_hash[FIDO_SHA256_SIZE];

  if ((private_key == NULL) || ((data == NULL) && (data_len != 0U)) ||
      (sig_der == NULL) || (sig_der_len == NULL))
  {
    return 0U;
  }

  fido_crypto_sha256(data, data_len, message_hash);
  return fido_crypto_sign_p256_hash_der_internal(private_key,
                                                 message_hash,
                                                 sig_der,
                                                 sig_der_cap,
                                                 sig_der_len);
}

void fido_crypto_hmac_sha256(const uint8_t *key,
                             uint32_t key_len,
                             const uint8_t *data,
                             uint32_t data_len,
                             uint8_t out[FIDO_SHA256_SIZE])
{
  uint8_t key_block[64];
  uint8_t inner_hash[FIDO_SHA256_SIZE];
  SHA256_CTX ctx;
  uint32_t i;

  memset(key_block, 0, sizeof(key_block));
  if (key_len > sizeof(key_block))
  {
    fido_crypto_sha256(key, key_len, key_block);
  }
  else if ((key != NULL) && (key_len != 0U))
  {
    memcpy(key_block, key, key_len);
  }

  for (i = 0U; i < sizeof(key_block); ++i)
  {
    key_block[i] ^= 0x36U;
  }
  sha256_init(&ctx);
  sha256_update(&ctx, key_block, sizeof(key_block));
  if ((data != NULL) && (data_len != 0U))
  {
    sha256_update(&ctx, data, data_len);
  }
  sha256_final(&ctx, inner_hash);

  for (i = 0U; i < sizeof(key_block); ++i)
  {
    key_block[i] ^= (uint8_t)(0x36U ^ 0x5CU);
  }
  sha256_init(&ctx);
  sha256_update(&ctx, key_block, sizeof(key_block));
  sha256_update(&ctx, inner_hash, sizeof(inner_hash));
  sha256_final(&ctx, out);
}

uint8_t fido_crypto_random(uint8_t *out, uint32_t len)
{
  uint32_t offset = 0U;

  if ((out == NULL) && (len != 0U))
  {
    return 0U;
  }

  fido_crypto_ensure_rng();
  while (offset < len)
  {
    uint32_t word = 0U;
    uint32_t chunk = len - offset;

    if (fido_rng_word(&word) == 0U)
    {
      memset(out, 0, len);
      return 0U;
    }
    if (chunk > 4U)
    {
      chunk = 4U;
    }
    memcpy(&out[offset], &word, chunk);
    offset += chunk;
  }

  return 1U;
}

uint8_t fido_crypto_make_ecdh_keypair(uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                      uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE])
{
  fido_crypto_ensure_rng();
  if ((private_key == NULL) || (public_key == NULL))
  {
    return 0U;
  }

  return (uint8_t)(uECC_make_key(public_key, private_key, uECC_secp256r1()) == 1 ? 1U : 0U);
}

uint8_t fido_crypto_ecdh_shared_secret(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                       const uint8_t peer_public_key[FIDO_P256_PUBLIC_KEY_SIZE],
                                       uint8_t shared_secret[FIDO_SHA256_SIZE])
{
  uint8_t raw_secret[32];

  if ((private_key == NULL) || (peer_public_key == NULL) || (shared_secret == NULL))
  {
    return 0U;
  }
  if (uECC_shared_secret(peer_public_key, private_key, raw_secret, uECC_secp256r1()) != 1)
  {
    return 0U;
  }

  fido_crypto_sha256(raw_secret, sizeof(raw_secret), shared_secret);
  memset(raw_secret, 0, sizeof(raw_secret));
  return 1U;
}

uint8_t fido_crypto_aes256_cbc_zero_iv_encrypt(const uint8_t key[32],
                                               const uint8_t *input,
                                               uint16_t input_len,
                                               uint8_t *output,
                                               uint16_t output_cap)
{
  uint8_t prev[16];
  uint16_t offset;

  if ((key == NULL) || ((input == NULL) && (input_len != 0U)) || (output == NULL) || (output_cap < input_len))
  {
    return 0U;
  }
  if ((input_len & 0x0FU) != 0U)
  {
    return 0U;
  }

  memset(prev, 0, sizeof(prev));
  for (offset = 0U; offset < input_len; offset = (uint16_t)(offset + 16U))
  {
    uint8_t block[16];
    uint8_t i;

    memcpy(block, &input[offset], sizeof(block));
    for (i = 0U; i < 16U; ++i)
    {
      block[i] ^= prev[i];
    }
    aes_encrypt_block(key, block, &output[offset]);
    memcpy(prev, &output[offset], sizeof(prev));
  }

  return 1U;
}

uint8_t fido_crypto_aes256_cbc_zero_iv_decrypt(const uint8_t key[32],
                                               const uint8_t *input,
                                               uint16_t input_len,
                                               uint8_t *output,
                                               uint16_t output_cap)
{
  uint8_t prev[16];
  uint16_t offset;

  if ((key == NULL) || ((input == NULL) && (input_len != 0U)) || (output == NULL) || (output_cap < input_len))
  {
    return 0U;
  }
  if ((input_len & 0x0FU) != 0U)
  {
    return 0U;
  }

  memset(prev, 0, sizeof(prev));
  for (offset = 0U; offset < input_len; offset = (uint16_t)(offset + 16U))
  {
    uint8_t block[16];
    uint8_t plain[16];
    uint8_t i;

    memcpy(block, &input[offset], sizeof(block));
    aes_decrypt_block(key, block, plain);
    for (i = 0U; i < 16U; ++i)
    {
      output[offset + i] = (uint8_t)(plain[i] ^ prev[i]);
    }
    memcpy(prev, block, sizeof(prev));
  }

  return 1U;
}
