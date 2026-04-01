#ifndef FIDO_CRYPTO_H
#define FIDO_CRYPTO_H

#include <stdint.h>

#define FIDO_SHA256_SIZE 32U
#define FIDO_P256_PRIVATE_KEY_SIZE 32U
#define FIDO_P256_PUBLIC_KEY_SIZE 64U
#define FIDO_CREDENTIAL_ID_SIZE 32U

void fido_crypto_sha256(const uint8_t *data, uint32_t len, uint8_t out[FIDO_SHA256_SIZE]);
void fido_crypto_sha256_two(const uint8_t *a,
                            uint32_t a_len,
                            const uint8_t *b,
                            uint32_t b_len,
                            uint8_t out[FIDO_SHA256_SIZE]);

uint8_t fido_crypto_make_credential_key(const uint8_t rp_id_hash[FIDO_SHA256_SIZE],
                                        const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                        uint32_t counter,
                                        uint8_t credential_id[FIDO_CREDENTIAL_ID_SIZE],
                                        uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                        uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE]);

uint8_t fido_crypto_sign_es256_der(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                   const uint8_t *auth_data,
                                   uint16_t auth_data_len,
                                   const uint8_t client_data_hash[FIDO_SHA256_SIZE],
                                   uint8_t *sig_der,
                                   uint16_t sig_der_cap,
                                   uint16_t *sig_der_len);
uint8_t fido_crypto_sign_p256_sha256_der(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                         const uint8_t *data,
                                         uint16_t data_len,
                                         uint8_t *sig_der,
                                         uint16_t sig_der_cap,
                                         uint16_t *sig_der_len);
void fido_crypto_hmac_sha256(const uint8_t *key,
                             uint32_t key_len,
                             const uint8_t *data,
                             uint32_t data_len,
                             uint8_t out[FIDO_SHA256_SIZE]);
uint8_t fido_crypto_random(uint8_t *out, uint32_t len);
uint8_t fido_crypto_make_ecdh_keypair(uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                      uint8_t public_key[FIDO_P256_PUBLIC_KEY_SIZE]);
uint8_t fido_crypto_ecdh_shared_secret(const uint8_t private_key[FIDO_P256_PRIVATE_KEY_SIZE],
                                       const uint8_t peer_public_key[FIDO_P256_PUBLIC_KEY_SIZE],
                                       uint8_t shared_secret[FIDO_SHA256_SIZE]);
uint8_t fido_crypto_aes256_cbc_zero_iv_encrypt(const uint8_t key[32],
                                               const uint8_t *input,
                                               uint16_t input_len,
                                               uint8_t *output,
                                               uint16_t output_cap);
uint8_t fido_crypto_aes256_cbc_zero_iv_decrypt(const uint8_t key[32],
                                               const uint8_t *input,
                                               uint16_t input_len,
                                               uint8_t *output,
                                               uint16_t output_cap);

#endif
