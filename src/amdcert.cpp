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

#include "amdcert.h"
#include "crypto.h"
#include "utilities.h"  // reverse_bytes
#include <cstring>      // memset
#include <openssl/ts.h> // SHA256_CTX
#include <array>
#include <memory>
#include <string>
#include <string_view>

/**
 * If out_str is passed in, fill up the string, else prints to std::out
 */
void print_amd_cert_readable(const amd_cert *cert, std::string &out_str)
{
    std::array<char, sizeof(amd_cert)*3+500> out{};   // 2 chars per byte + 1 space + ~500 extra chars for text
    size_t offset{};

    offset += sprintf(out.data(), "%-15s%08x\n", "Version:", cert->version);                               // uint32_t
    offset += sprintf(out.data()+offset, "%-15s%016lx\n", "key_id_0:", cert->key_id_0);               // uint64_t
    offset += sprintf(out.data()+offset, "%-15s%016lx\n", "key_id_1:", cert->key_id_1);               // uint64_t
    offset += sprintf(out.data()+offset, "%-15s%016lx\n", "certifying_id_0:", cert->certifying_id_0); // uint64_t
    offset += sprintf(out.data()+offset, "%-15s%016lx\n", "certifying_id_1:", cert->certifying_id_1); // uint64_t
    offset += sprintf(out.data()+offset, "%-15s%08x\n", "key_usage:", cert->key_usage);               // uint32_t
    offset += sprintf(out.data()+offset, "%-15s%016lx\n", "reserved_0:", cert->reserved_0);           // uint64_t
    offset += sprintf(out.data()+offset, "%-15s%016lx\n", "reserved_1:", cert->reserved_1);           // uint64_t
    offset += sprintf(out.data()+offset, "%-15s%08x\n", "pub_exp_size:", cert->pub_exp_size);         // uint32_t
    offset += sprintf(out.data()+offset, "%-15s%08x\n", "modulus_size:", cert->modulus_size);         // uint32_t
    offset += sprintf(out.data()+offset, "\nPubExp:\n");
    for (size_t i = 0; i < (size_t)(cert->pub_exp_size/8); i++) {    // bytes to uint8
        offset += sprintf(out.data()+offset, "%02X ", (reinterpret_cast<uint8_t const *>(&cert->pub_exp))[i] );
    }
    offset += sprintf(out.data()+offset, "\nModulus:\n");
    for (size_t i = 0; i < (size_t)(cert->modulus_size/8); i++) {    // bytes to uint8
        offset += sprintf(out.data()+offset, "%02X ", (reinterpret_cast<uint8_t const *>(&cert->modulus))[i] );
    }
    offset += sprintf(out.data()+offset, "\nSig:\n");
    for (size_t i = 0; i < (size_t)(cert->modulus_size/8); i++) {    // bytes to uint8
        offset += sprintf(out.data()+offset, "%02X ", (reinterpret_cast<uint8_t const *>(&cert->sig))[i] );
    }
    offset += sprintf(out.data()+offset, "\n");

    if (out_str == "NULL") {
        printf("%s\n", out.data());
    }
    else {
        out_str += std::string_view{out.data(), offset};
    }
}

/**
 * AMD Certs are unions because key sizes can be different. So, you can't just
 * print out the memory, you need to print each parameter based off its correct
 * size
 * Note: there are no spaces in this printout because this function is also used
 *       to write to a .cert file, not just printing to the screen
 */
void print_amd_cert_hex(const amd_cert *cert, std::string &out_str)
{
    std::array<char, sizeof(amd_cert)*2> out{};   // 2 chars per byte
    size_t fixed_offset = offsetof(amd_cert, pub_exp);      // 64 bytes

    size_t offset{};

    // Print fixed parameters
    for (size_t i = 0; i < fixed_offset; i++) {
        offset += sprintf(out.data()+offset, "%02X", (reinterpret_cast<uint8_t const *>(&cert->version))[i] );
    }
    // Print pub_exp
    for (size_t i = 0; i < (size_t)(cert->pub_exp_size/8); i++) {    // bytes to uint8
        offset += sprintf(out.data()+offset, "%02X", (reinterpret_cast<uint8_t const *>(&cert->pub_exp))[i] );
    }
    // Print nModulus
    for (size_t i = 0; i < (size_t)(cert->modulus_size/8); i++) {    // bytes to uint8
        offset += sprintf(out.data()+offset, "%02X", (reinterpret_cast<uint8_t const *>(&cert->modulus))[i] );
    }
    // Print Sig
    for (size_t i = 0; i < (size_t)(cert->modulus_size/8); i++) {    // bytes to uint8
        offset += sprintf(out.data()+offset, "%02X", (reinterpret_cast<uint8_t const *>(&cert->sig)[i]) );
    }

    if (out_str == "NULL") {
        printf("%s\n\n\n", out.data());
    }
    else {
        out_str += std::string_view{out.data(), offset};
    }
}

// Obtain information on device type from provided Root certificate.
ePSP_DEVICE_TYPE AMDCert::get_device_type(const amd_cert *ark)
{
    ePSP_DEVICE_TYPE ret = PSP_DEVICE_TYPE_INVALID;
    if(ark == nullptr)
        return ret;
    if(memcmp(&ark->key_id_0, amd_root_key_id_rome, sizeof(ark->key_id_0 + ark->key_id_1)) == 0) {
        return PSP_DEVICE_TYPE_ROME;
    }
    if(memcmp(&ark->key_id_0, amd_root_key_id_naples, sizeof(ark->key_id_0 + ark->key_id_1)) == 0) {
        return PSP_DEVICE_TYPE_NAPLES;
    }
    if(memcmp(&ark->key_id_0, amd_root_key_id_milan, sizeof(ark->key_id_0 + ark->key_id_1)) == 0) {
        return PSP_DEVICE_TYPE_MILAN;
    }
    return ret;
}

/**
 * This function takes Bits, NOT Bytes
 */
bool AMDCert::key_size_is_valid(size_t size)
{
    return (size == AMD_CERT_KEY_BITS_2K) || (size == AMD_CERT_KEY_BITS_4K);
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_sig(const amd_cert *cert,
                                              const amd_cert *parent,
                                              ePSP_DEVICE_TYPE device_type)
{
    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    hmac_sha_256 sha_digest_256;
    hmac_sha_512 sha_digest_384;
    SHA_TYPE algo = SHA_TYPE_256;
    uint8_t *sha_digest = nullptr;
    size_t sha_length = 0;

    std::unique_ptr<RSA, decltype(&RSA_free)> rsa_pub_key{nullptr, &RSA_free};
    BIGNUM *modulus = nullptr;
    BIGNUM *pub_exp = nullptr;
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> md_ctx{nullptr, &EVP_MD_CTX_free};
    uint32_t sig_len = cert->modulus_size/8;

    uint32_t digest_len = 0;
    std::array<uint8_t, AMD_CERT_KEY_BYTES_4K> decrypted{}; // TODO wrong length
    std::array<uint8_t, AMD_CERT_KEY_BYTES_4K> signature{};
    uint32_t fixed_offset = offsetof(amd_cert, pub_exp);    // 64 bytes

    do {
        if ((cert == nullptr) || (parent == nullptr)) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        // Set SHA_TYPE to 256 bit or 384 bit depending on device_type
        if (device_type == PSP_DEVICE_TYPE_NAPLES) {
            algo = SHA_TYPE_256;
            sha_digest = sha_digest_256;
            sha_length = sizeof(hmac_sha_256);
        }
        else /*if (ROME/MILAN)*/ {
            algo = SHA_TYPE_384;
            sha_digest = sha_digest_384;
            sha_length = sizeof(hmac_sha_512);
        }

        // Memzero all the buffers
        memset(sha_digest, 0, sha_length);

        // New up the RSA key
        rsa_pub_key.reset(RSA_new());

        // Convert the parent to an RSA key to pass into RSA_verify
        modulus = BN_lebin2bn(reinterpret_cast<uint8_t const *>(&parent->modulus), parent->modulus_size/8, nullptr);  // n    // New's up BigNum
        pub_exp = BN_lebin2bn(reinterpret_cast<uint8_t const *>(&parent->pub_exp), parent->pub_exp_size/8, nullptr);   // e
        if (RSA_set0_key(rsa_pub_key.get(), modulus, pub_exp, nullptr) != 1)
            break;

        md_ctx.reset(EVP_MD_CTX_create());
        if (EVP_DigestInit(md_ctx.get(), (algo == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384()) <= 0)
            break;
        if (EVP_DigestUpdate(md_ctx.get(), cert, fixed_offset) <= 0)     // Calls SHA256_UPDATE
            break;
        if (EVP_DigestUpdate(md_ctx.get(), &cert->pub_exp, cert->pub_exp_size/8) <= 0)
            break;
        if (EVP_DigestUpdate(md_ctx.get(), &cert->modulus, cert->modulus_size/8) <= 0)
            break;
        EVP_DigestFinal(md_ctx.get(), sha_digest, &digest_len);

        // Swap the bytes of the signature
        memcpy(signature.data(), &cert->sig, parent->modulus_size/8);
        if (!sev::reverse_bytes(signature.data(), parent->modulus_size/8))
            break;

        // Now we will verify the signature. Start by a RAW decrypt of the signature
        if (RSA_public_decrypt(sig_len, signature.data(), decrypted.data(), rsa_pub_key.get(), RSA_NO_PADDING) == -1)
            break;

        // Verify the data
        // SLen of -2 means salt length is recovered from the signature
        if (RSA_verify_PKCS1_PSS(rsa_pub_key.get(), sha_digest,
                                (algo == SHA_TYPE_256) ? EVP_sha256() : EVP_sha384(),
                                decrypted.data(), -2) != 1)
        {
            break;
        }

        cmd_ret = STATUS_SUCCESS;
    } while (false);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_common(const amd_cert *cert)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

    do {
        if (cert == nullptr) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        if (cert->version != AMD_CERT_VERSION      ||
            !key_size_is_valid(cert->modulus_size) ||   // bits
            !key_size_is_valid(cert->pub_exp_size))     // bits
        {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
        }
    } while (false);

    return cmd_ret;
}

bool AMDCert::usage_is_valid(AMD_SIG_USAGE usage)
{
    return (usage == AMD_USAGE_ARK) || (usage == AMD_USAGE_ASK);    // ARK, ASK
}

SEV_ERROR_CODE AMDCert::amd_cert_validate(const amd_cert *cert,
                                          const amd_cert *parent,
                                          AMD_SIG_USAGE expected_usage,
                                          ePSP_DEVICE_TYPE device_type)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
    const uint8_t *key_id = nullptr;

    do {
        if ((cert == nullptr) || !usage_is_valid(expected_usage)) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        // Validate the signature before using any certificate fields
        if (parent != nullptr) {
            cmd_ret = amd_cert_validate_sig(cert, parent, device_type);
            if (cmd_ret != STATUS_SUCCESS)
                break;
        }

        // Validate the fixed data
        cmd_ret = amd_cert_validate_common(cert);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // If there is no parent, then the certificate must be self-certified
        key_id = (parent != nullptr) ? reinterpret_cast<uint8_t const *>(&parent->key_id_0) : reinterpret_cast<uint8_t const *>(&cert->key_id_0);

        if (cert->key_usage != expected_usage ||
            memcmp(&cert->certifying_id_0, key_id, sizeof(cert->certifying_id_0 + cert->certifying_id_1)) != 0)
        {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
        }
    } while (false);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_public_key_hash(const amd_cert *cert,
                                                 hmac_sha_256 *hash)
{
    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    hmac_sha_256 tmp_hash;
    // size_t hash_size = sizeof(tmp_hash);
    SHA256_CTX ctx;
    uint32_t fixed_offset = offsetof(amd_cert, pub_exp);    // 64 bytes

    do {
        if ((cert == nullptr) || (hash == nullptr)) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(&tmp_hash, 0, sizeof(tmp_hash));

        // Calculate the hash of the public key
        if (SHA256_Init(&ctx) != 1)
            break;

        if (SHA256_Update(&ctx, cert, fixed_offset) != 1)
            break;

        if (SHA256_Update(&ctx, &cert->pub_exp, cert->pub_exp_size/8) != 1)
            break;

        if (SHA256_Update(&ctx, &cert->modulus, cert->modulus_size/8) != 1)
            break;

        if (SHA256_Final(reinterpret_cast<uint8_t *>(&tmp_hash), &ctx) != 1)
            break;

        // Copy the hash to the output
        memcpy(hash, &tmp_hash, sizeof(hmac_sha_256));

        cmd_ret = STATUS_SUCCESS;
    } while (false);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_ark(const amd_cert *ark)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
    hmac_sha_256 hash;
    hmac_sha_256 fused_hash;
    const uint8_t *amd_root_key_id = nullptr;
    ePSP_DEVICE_TYPE device_type = get_device_type(ark);

    do {
        if (ark == nullptr) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(&hash, 0, sizeof(hash));
        memset(&fused_hash, 0, sizeof(fused_hash));

        // Validate the certificate. Check for self-signed ARK
        cmd_ret = amd_cert_validate(ark, ark, AMD_USAGE_ARK, device_type);       // Rome
        if (cmd_ret != STATUS_SUCCESS) {
            // Not a self-signed ARK. Check the ARK without a signature
            cmd_ret = amd_cert_validate(ark, nullptr, AMD_USAGE_ARK, device_type);  // Naples
            if (cmd_ret != STATUS_SUCCESS)
                break;
        }

        if (device_type == PSP_DEVICE_TYPE_NAPLES)
            amd_root_key_id = amd_root_key_id_naples;
        else if (device_type == PSP_DEVICE_TYPE_ROME)
            amd_root_key_id = amd_root_key_id_rome;
        else //if (device_type == PSP_DEVICE_TYPE_MILAN)
            amd_root_key_id = amd_root_key_id_milan;

        if (memcmp(&ark->key_id_0, amd_root_key_id, sizeof(ark->key_id_0 + ark->key_id_1)) != 0) {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        // We have to trust the ARK from the website, as there is no way to
        // validate it further, here. It is trustable due to being transmitted
        // over https
    } while (false);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_ask(const amd_cert *ask, const amd_cert *ark)
{
    ePSP_DEVICE_TYPE device_type = get_device_type(ark);
    return amd_cert_validate(ask, ark, AMD_USAGE_ASK, device_type);      // ASK
}

/**
 * Bytes, NOT bits
 */
size_t AMDCert::amd_cert_get_size(const amd_cert *cert)
{
    size_t size = 0;
    uint32_t fixed_offset = offsetof(amd_cert, pub_exp);    // 64 bytes

    if (cert != nullptr) {
        size = fixed_offset + (cert->pub_exp_size + 2*cert->modulus_size)/8;
    }
    return size;
}

/**
 * The verify_sev_cert function takes in a parent of an sev_cert not
 *   an amd_cert, so need to pull the pubkey out of the amd_cert and
 *   place it into a tmp sev_cert to help validate the cek
 */
SEV_ERROR_CODE AMDCert::amd_cert_export_pub_key(const amd_cert *cert,
                                                sev_cert *pub_key_cert)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

    do {
        if ((cert == nullptr) || (pub_key_cert == nullptr)) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(pub_key_cert, 0, sizeof(*pub_key_cert));

        // Todo. This has the potential for issues if we keep the key size
        //       4k and change the SHA type on the next gen
        if (cert->modulus_size == AMD_CERT_KEY_BITS_2K) {        // Naples
            pub_key_cert->pub_key_algo = SEV_SIG_ALGO_RSA_SHA256;
        }
        else if (cert->modulus_size == AMD_CERT_KEY_BITS_4K) {   // Rome
            pub_key_cert->pub_key_algo = SEV_SIG_ALGO_RSA_SHA384;
        }

        pub_key_cert->pub_key_usage = cert->key_usage;
        pub_key_cert->pub_key.rsa.modulus_size = cert->modulus_size;
        memcpy(pub_key_cert->pub_key.rsa.pub_exp, &cert->pub_exp, cert->pub_exp_size/8);
        memcpy(pub_key_cert->pub_key.rsa.modulus, &cert->modulus, cert->modulus_size/8);
    } while (false);

    return cmd_ret;
}

/**
 * Initialize an amd_cert object from a (.cert file) buffer
 *
 * Parameters:
 *     cert     [out] AMD certificate object,
 *     buffer   [in]  buffer containing the raw AMD certificate
 */
SEV_ERROR_CODE AMDCert::amd_cert_init(amd_cert *cert, const uint8_t *buffer)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
    amd_cert tmp;
    uint32_t fixed_offset = offsetof(amd_cert, pub_exp);    // 64 bytes
    uint32_t pub_exp_offset = fixed_offset;                 // 64 bytes
    uint32_t modulus_offset = 0;                            // 2k or 4k bits
    uint32_t sig_offset = 0;                                // 2k or 4k bits

    do {
        if ((cert == nullptr) || (buffer == nullptr)) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(&tmp, 0, sizeof(tmp));

        // Copy the fixed body data from the temporary buffer
        memcpy(&tmp, buffer, fixed_offset);

        modulus_offset = pub_exp_offset + (tmp.pub_exp_size/8);
        sig_offset = modulus_offset + (tmp.modulus_size/8);     // Mod size as def in spec

        // Initialize the remainder of the certificate
        memcpy(&tmp.pub_exp, (void *)(buffer + pub_exp_offset), tmp.pub_exp_size/8);
        memcpy(&tmp.modulus, (void *)(buffer + modulus_offset), tmp.modulus_size/8);
        memcpy(&tmp.sig, (void *)(buffer + sig_offset), tmp.modulus_size/8);

        memcpy(cert, &tmp, sizeof(*cert));
    } while (false);

    return cmd_ret;
}
