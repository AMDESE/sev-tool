/**************************************************************************
 * Copyright 2018 Advanced Micro Devices, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **************************************************************************/

#ifndef CRYPTO_H
#define CRYPTO_H

#include "sevapi.h"
#include "utilities.h"

#include <cstring>                  // memset
#include <stdio.h>
#include <stdexcept>
#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

/**
 * NIST_KDF
 */
#define NIST_KDF_H_BYTES 32
#define NIST_KDF_H       (NIST_KDF_H_BYTES*BITS_PER_BYTE)   // 32*8=256
#define NIST_KDF_R       sizeof(uint32_t)*BITS_PER_BYTE     // 32

#define SEV_MASTER_SECRET_LABEL "sev-master-secret"
#define SEV_KEK_LABEL           "sev-kek"
#define SEV_KIK_LABEL           "sev-kik"
#define SEV_CEK_LABEL           "sev-chip-endorsement-key"
#define SEV_VCEK_LABEL          "sev-versioned-chip-endorsement-key"

/**
 * DIGEST
 */
#define DIGEST_SHA256_SIZE_BYTES    (256/8) // 32
#define DIGEST_SHA384_SIZE_BYTES    (384/8) // 48
#define DIGEST_SHA512_SIZE_BYTES    (512/8) // 64
typedef uint8_t DIGESTSHA256[DIGEST_SHA256_SIZE_BYTES];
// typedef uint8_t DIGESTSHA384[DIGEST_SHA384_SIZE_BYTES];
typedef uint8_t DIGESTSHA512[DIGEST_SHA512_SIZE_BYTES];


/**
 * ECC
 */
#define ECC_CURVE_SECP256R1_SIZE_BITS   256
#define ECC_CURVE_SECP256R1_SIZE_BYTES  (ECC_CURVE_SECP256R1_SIZE_BITS/8)   // 32
#define ECC_CURVE_SECP384R1_SIZE_BITS   384
#define ECC_CURVE_SECP384R1_SIZE_BYTES  (ECC_CURVE_SECP384R1_SIZE_BITS/8)   // 48

// SEV supported ECC curve size
#define SEV_ECC_CURVE_SIZE_BYTES        ECC_CURVE_SECP384R1_SIZE_BYTES

/**
 * For ECC keys generated from extra bits, FIPS 180-4 requires that the
 * input contain an additional 64 bits (8 bytes) of random data.
 */
#define ECC_KEYGEN_EXTRA_BITS   (64)
#define ECC_KEYGEN_EXTRA_BYTES  (ECC_KEYGEN_EXTRA_BITS/8)


typedef enum __attribute__((mode(QI))) SHA_TYPE
{
    SHA_TYPE_256 = 0,
    SHA_TYPE_384 = 1,
} SHA_TYPE;

// NIST Compliant KDF
bool kdf(uint8_t *key_out,       size_t key_out_length,
         const uint8_t *key_in,  size_t key_in_length,
         const uint8_t *label,   size_t label_length,
         const uint8_t *context, size_t context_length);

uint8_t *calculate_shared_secret(EVP_PKEY *priv_key,
                                 EVP_PKEY *peer_key,
                                 size_t& shared_key_len_out);

bool derive_master_secret(aes_128_key master_secret,
                          EVP_PKEY *godh_priv_key,
                          const sev_cert *pdh_public,
                          const uint8_t nonce[sizeof(nonce_128)]);

bool derive_kek(aes_128_key kek, const aes_128_key master_secret);
bool derive_kik(hmac_key_128 kik, const aes_128_key master_secret);
bool gen_hmac(hmac_sha_256 *out, hmac_key_128 key, uint8_t *msg, size_t msg_len);

// AES128 encrypt a buffer
bool encrypt(uint8_t *out, const uint8_t *in, size_t length,
             const aes_128_key key, const uint8_t iv[128/8]);

bool generate_ecdh_key_pair(EVP_PKEY **evp_key_pair, SEV_EC curve = SEV_EC_P384);
bool generate_rsa_keypair(EVP_PKEY **evp_key_pair);

bool digest_sha(const void *msg, size_t msg_len, uint8_t *digest,
                size_t digest_len, SHA_TYPE sha_type);

bool ecdsa_verify(sev_sig *sig, EVP_PKEY **pub_evp_key, uint8_t *digest, size_t length);

bool sign_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg,
                  size_t length, const SEV_SIG_ALGO algo);
bool verify_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg,
                    size_t length, const SEV_SIG_ALGO algo);

SEV_ERROR_CODE aes_256_gcm_authenticated_encrypt(const uint8_t *p_key, size_t key_size,
                                                 const uint8_t *p_aad, size_t aad_size,
                                                 const uint8_t *p_msg, size_t msg_size,
                                                 uint8_t *p_out, const uint8_t *p_iv, size_t iv_size,
                                                 uint8_t *p_tag); // [out, 16 bytes]
SEV_ERROR_CODE aes_256_gcm_authenticated_decrypt(const uint8_t *p_key, size_t key_size,
                                                 const uint8_t *p_aad, size_t aad_size,
                                                 const uint8_t *p_msg, size_t msg_size,
                                                 uint8_t *p_out, const uint8_t *p_iv, size_t iv_size,
                                                 const uint8_t *p_tag); // [in, 16 bytes]

#endif /* CRYPTO_H */
