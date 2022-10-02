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

#include "crypto.h"
#include "sevcert.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ts.h>
#include <openssl/ecdh.h>
#include <array>

/**
 * Description:   Generates a new P-384 key pair
 * Typical Usage: Used to create a new Guest Owner DH
 *                (Elliptic Curve Diffie Hellman (ECDH)) P-384 key pair
 * Parameters:    [evp_key_pair] the output EVP_PKEY to which the keypair gets
 *                  set
 *                [curve] P-384 (default) or P-256 (only for negative testing)
 * Note:          This key must be initialized (with EVP_PKEY_new())
 *                before passing in
 */
bool generate_ecdh_key_pair(EVP_PKEY **evp_key_pair, SEV_EC curve)
{
    if (!evp_key_pair)
        return false;

    bool ret = false;
    int nid = 0;
    EC_KEY *ec_key_pair = nullptr;

    do {
        // New up the Guest Owner's private EVP_PKEY
        if (!(*evp_key_pair = EVP_PKEY_new()))
            break;

        // New up the EC_KEY with the EC_GROUP
        if (curve == SEV_EC_P256)
            nid = EC_curve_nist2nid("P-256");   // NID_secp256r1
        else
            nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
        ec_key_pair = EC_KEY_new_by_curve_name(nid);

        // Create the new public/private EC key pair. EC_key must have a group
        // associated with it before calling this function
        if (EC_KEY_generate_key(ec_key_pair) != 1)
            break;

        /*
         * Convert EC key to EVP_PKEY
         * This function links evp_key_pair to ec_key_pair, so when evp_key_pair is
         *  freed, ec_key_pair is freed. We don't want the user to have to manage 2
         *  keys, so just return EVP_PKEY and make sure user free's it
         */
        if (EVP_PKEY_assign_EC_KEY(*evp_key_pair, ec_key_pair) != 1)
            break;

        if (!evp_key_pair)
            break;

        ret = true;
    } while (false);

    return ret;
}

/**
 * Calculate the complete SHA256/SHA384 digest of the input message.
 * Use for RSA and ECDSA, not ECDH
 * Formerly called CalcHashDigest
 *
 * msg       : message buffer to hash.
 * msg_len   : length of the input message.
 *             - For SEV_CERTs, use PubKeyOffset (number of bytes to be hashed,
 *               from the top of the sev_cert until the first signature.
 *               Version through and including pub_key)
 * digest    : output buffer for the final digest.
 * digest_len: length of the output buffer.
 */
bool digest_sha(const void *msg, size_t msg_len, uint8_t *digest,
                size_t digest_len, SHA_TYPE sha_type)
{
    bool ret = false;

    do {    //TODO 384 vs 512 is all a mess
        if ((sha_type == SHA_TYPE_256 && digest_len != SHA256_DIGEST_LENGTH)/* ||
            (sha_type == SHA_TYPE_384 && digest_len != SHA384_DIGEST_LENGTH)*/)
                break;

        if (sha_type == SHA_TYPE_256) {
            SHA256_CTX context;

            if (SHA256_Init(&context) != 1)
                break;
            if (SHA256_Update(&context, msg, msg_len) != 1)
                break;
            if (SHA256_Final(digest, &context) != 1)
                break;
        }
        else if (sha_type == SHA_TYPE_384) {
            SHA512_CTX context;

            if (SHA384_Init(&context) != 1)
                break;
            if (SHA384_Update(&context, msg, msg_len) != 1)
                break;
            if (SHA384_Final(digest, &context) != 1)
                break;
        }

        ret = true;
    } while (false);

    return ret;
}

static bool rsa_sign(sev_sig *sig, EVP_PKEY **priv_evp_key, const uint8_t *digest,
                     size_t length, SHA_TYPE sha_type, bool pss)
{
    bool is_valid = false;
    RSA *priv_rsa_key = nullptr;
    uint32_t sig_len = 0;

    do {
        // Pull the RSA key from the EVP_PKEY
        priv_rsa_key = EVP_PKEY_get1_RSA(*priv_evp_key);
        if (!priv_rsa_key)
            break;

        if ((size_t)RSA_size(priv_rsa_key) > sizeof(sev_sig::rsa)) {
            printf("rsa_sign buffer too small\n");
            break;
        }

        if (pss) {
            std::array<uint8_t, 4096/BITS_PER_BYTE> encrypted{};
            std::array<uint8_t, 4096/BITS_PER_BYTE> signature{};

            // Compute the pss padded data
            if (RSA_padding_add_PKCS1_PSS(priv_rsa_key, encrypted.data(), digest,
                                         (sha_type == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384(),
                                         -2) != 1) // maximum salt length
            {
                break;
            }

            // Perform digital signature
            if (RSA_private_encrypt(sizeof(encrypted), encrypted.data(), signature.data(), priv_rsa_key, RSA_NO_PADDING) == -1)
                break;

            // Swap the bytes of the signature
            if (!sev::reverse_bytes(signature.data(), signature.size()))
                break;
            memcpy(sig->rsa.s, signature.data(), signature.size());
        }
        else {
            if (RSA_sign((sha_type == SHA_TYPE_256) ? NID_sha256 : NID_sha384, digest,
                        (uint32_t)length, reinterpret_cast<uint8_t *>(&sig->rsa), &sig_len, priv_rsa_key) != 1)
                break;
        }

        if (sig_len > sizeof(sev_sig::rsa)) {
            printf("rsa_sign buffer too small\n");
            break;
        }

        is_valid = true;
    } while (false);

    // Free memory
    // RSA_free(priv_rsa_key);

    return is_valid;
}

/**
 * rsa_pss_verify
 */
static bool rsa_verify(sev_sig *sig, EVP_PKEY **evp_pub_key, const uint8_t *sha_digest,
                       size_t sha_length, SHA_TYPE sha_type, bool pss)
{
    bool is_valid = false;
    RSA *rsa_pub_key = nullptr;
    uint32_t sig_len = 0;

    do {
        // Pull the RSA key from the EVP_PKEY
        rsa_pub_key = EVP_PKEY_get1_RSA(*evp_pub_key);
        if (!rsa_pub_key)
            break;

        sig_len = RSA_size(rsa_pub_key);

        if (pss) {
            std::array<uint8_t, 4096/BITS_PER_BYTE> decrypted{}; // TODO wrong length
            std::array<uint8_t, 4096/BITS_PER_BYTE> signature{};

            // Swap the bytes of the signature
            memcpy(signature.data(), sig->rsa.s, signature.size());
            if (!sev::reverse_bytes(signature.data(), signature.size()))
                break;

            // Now we will verify the signature. Start by a RAW decrypt of the signature
            if (RSA_public_decrypt(sig_len, signature.data(), decrypted.data(), rsa_pub_key, RSA_NO_PADDING) == -1)
                break;

            // Verify the data
            // SLen of -2 means salt length is recovered from the signature
            if (RSA_verify_PKCS1_PSS(rsa_pub_key, sha_digest,
                                     (sha_type == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384(),
                                     decrypted.data(), -2) != 1)
            {
                printf("Error: rsa_verify with pss Failed\n");
                break;
            }
        }
        else {
            // Verify the data
            if (RSA_verify((sha_type == SHA_TYPE_256) ? NID_sha256 : NID_sha384,
                            sha_digest, (uint32_t)sha_length, sig->rsa.s, sig_len, rsa_pub_key) != 1)
            {
                printf("Error: rsa_verify without pss Failed\n");
                break;
            }
        }

        is_valid = true;
    } while (false);

    // Free the keys and contexts
    // if (rsa_pub_key)
    //     RSA_free(rsa_pub_key);

    // if (md_ctx)
    //     EVP_MD_CTX_free(md_ctx);

    return is_valid;
}

/**
 * Call sign_verify_message and it will call this
 */
static bool ecdsa_sign(sev_sig *sig, EVP_PKEY **priv_evp_key,
                       const uint8_t *digest, size_t length)
{
    bool is_valid = false;
    EC_KEY *priv_ec_key = nullptr;
    const BIGNUM *r = nullptr;
    const BIGNUM *s = nullptr;
    ECDSA_SIG *ecdsa_sig = nullptr;

    do {
        priv_ec_key = EVP_PKEY_get1_EC_KEY(*priv_evp_key);
        if (!priv_ec_key)
            break;

        ecdsa_sig = ECDSA_do_sign(digest, (uint32_t)length, priv_ec_key); // Contains 2 bignums
        if (!ecdsa_sig)
            break;

        // Extract the bignums from ecdsa_sig and store the signature in sig
        ECDSA_SIG_get0(ecdsa_sig, &r, &s);
        BN_bn2lebinpad(r, sig->ecdsa.r, sizeof(sev_ecdsa_sig::r));    // LE to BE
        BN_bn2lebinpad(s, sig->ecdsa.s, sizeof(sev_ecdsa_sig::s));

        ECDSA_SIG_free(ecdsa_sig);

        is_valid = true;
    } while (false);

    // Free memory
    EC_KEY_free(priv_ec_key);

    return is_valid;
}

/**
 * It would be easier if we could just pass in the populated ECDSA_SIG from
 *  ecdsa_sign instead of using sev_sig to BigNums as the intermediary, but we
 *  do need to ecdsa_verify to verify something signed by firmware, so we
 *  wouldn't have the ECDSA_SIG
 */
bool ecdsa_verify(sev_sig *sig, EVP_PKEY **pub_evp_key, uint8_t *digest, size_t length)
{
    bool is_valid = false;
    EC_KEY *pub_ec_key = nullptr;
    BIGNUM *r = nullptr;
    BIGNUM *s = nullptr;
    ECDSA_SIG *ecdsa_sig = nullptr;

    do {
        pub_ec_key = EVP_PKEY_get1_EC_KEY(*pub_evp_key);
        if (!pub_ec_key)
            break;

        // Store the x and y components as separate BIGNUM objects. The values in the
        // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
        r = BN_lebin2bn(sig->ecdsa.r, sizeof(sig->ecdsa.r), nullptr);  // New's up BigNum
        s = BN_lebin2bn(sig->ecdsa.s, sizeof(sig->ecdsa.s), nullptr);

        // Create a ecdsa_sig from the bignums and store in sig
        ecdsa_sig = ECDSA_SIG_new();
        ECDSA_SIG_set0(ecdsa_sig, r, s);

        // Validation will also be done by the FW
        if (ECDSA_do_verify(digest, (uint32_t)length, ecdsa_sig, pub_ec_key) != 1) {
            ECDSA_SIG_free(ecdsa_sig);
            break;
        }
        ECDSA_SIG_free(ecdsa_sig);

        is_valid = true;
    } while (false);

    // Free memory
    EC_KEY_free(pub_ec_key);

    return is_valid;
}

/**
 * A generic sign function that takes a byte array (not specifically an sev_cert)
 *  and signs it using an sev_sig
 *
 * Note that verify always happens, even after a sign operation, just to make
 *  sure the sign worked correctly
 */
static bool sign_verify_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg,
                                size_t length, const SEV_SIG_ALGO algo, bool sign)
{
    bool is_valid = false;
    hmac_sha_256 sha_digest_256;   // Hash on the cert from Version to PubKey
    hmac_sha_512 sha_digest_384;   // Hash on the cert from Version to PubKey
    SHA_TYPE sha_type;
    uint8_t *sha_digest = nullptr;
    size_t sha_length;
    const bool pss = true;

    do {
        // Determine if SHA_TYPE is 256 bit or 384 bit
        if (algo == SEV_SIG_ALGO_RSA_SHA256 || algo == SEV_SIG_ALGO_ECDSA_SHA256 ||
            algo == SEV_SIG_ALGO_ECDH_SHA256)
        {
            sha_type = SHA_TYPE_256;
            sha_digest = sha_digest_256;
            sha_length = sizeof(hmac_sha_256);
        }
        else if (algo == SEV_SIG_ALGO_RSA_SHA384 || algo == SEV_SIG_ALGO_ECDSA_SHA384 ||
                 algo == SEV_SIG_ALGO_ECDH_SHA384)
        {
            sha_type = SHA_TYPE_384;
            sha_digest = sha_digest_384;
            sha_length = sizeof(hmac_sha_512);
        }
        else
        {
            break;
        }
        memset(sha_digest, 0, sha_length);

        // Calculate the hash digest
        if (!digest_sha(msg, length, sha_digest, sha_length, sha_type))
            break;

        if ((algo == SEV_SIG_ALGO_RSA_SHA256) || (algo == SEV_SIG_ALGO_RSA_SHA384)) {
            if (sign && !rsa_sign(sig, evp_key_pair, sha_digest, sha_length, sha_type, pss))
                break;
            if (!rsa_verify(sig, evp_key_pair, sha_digest, sha_length, sha_type, pss))
                break;
        }
        else if ((algo == SEV_SIG_ALGO_ECDSA_SHA256) || (algo == SEV_SIG_ALGO_ECDSA_SHA384)) {
            if (sign && !ecdsa_sign(sig, evp_key_pair, sha_digest, sha_length))
                break;
            if (!ecdsa_verify(sig, evp_key_pair, sha_digest, sha_length))
                break;
        }
        else if ((algo == SEV_SIG_ALGO_ECDH_SHA256) || (algo == SEV_SIG_ALGO_ECDH_SHA384)) {
            printf("Error: ECDH signing unsupported");
            break;                       // Error unsupported
        }
        else {
            printf("Error: invalid signing algo. Can't sign");
            break;                          // Invalid params
        }

        is_valid = true;
    } while (false);

    return is_valid;
}

bool sign_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg,
                 size_t length, const SEV_SIG_ALGO algo)
{
    return sign_verify_message(sig, evp_key_pair, msg, length, algo, true);
}

bool verify_message(sev_sig *sig, EVP_PKEY **evp_key_pair, const uint8_t *msg,
                    size_t length, const SEV_SIG_ALGO algo)
{
    return sign_verify_message(sig, evp_key_pair, msg, length, algo, false);
}
