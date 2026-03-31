#include "fido_crypto.h"

#include <string.h>

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
  uint8_t raw_sig[64];
  fido_uECC_sha256_ctx_t hash_ctx;
  SHA256_CTX msg_ctx;

  if ((private_key == NULL) || (auth_data == NULL) || (client_data_hash == NULL) ||
      (sig_der == NULL) || (sig_der_len == NULL))
  {
    return 0U;
  }

  sha256_init(&msg_ctx);
  sha256_update(&msg_ctx, auth_data, auth_data_len);
  sha256_update(&msg_ctx, client_data_hash, FIDO_SHA256_SIZE);
  sha256_final(&msg_ctx, message_hash);

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
