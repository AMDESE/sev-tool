/* ************************************************************************
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
 * ************************************************************************/

#include "amdcert.h"
#include "utilities.h"
#include <cstring>                  // memset
#include <stdio.h>
#include <stdexcept>
#include <fstream>
#include <stdio.h>

#define AMD_CERT_KEY_BYTES_4K   (AMD_CERT_KEY_BITS_4K/8)

static const uint8_t amd_root_key_id[AMD_CERT_ID_SIZE_BYTES] = {
        0x1b, 0xb9, 0x87, 0xc3, 0x59, 0x49, 0x46, 0x06,
        0xb1, 0x74, 0x94, 0x56, 0x01, 0xc9, 0xea, 0x5b,
};

/**
 * If out_str is passed in, fill up the string, else prints to std::out
 */
void print_amd_cert_readable(const AMD_CERT *cert, std::string& out_str)
{
    char out[sizeof(AMD_CERT)*3+500];   // 2 chars per byte + 1 spaces + ~500 extra chars for text

    sprintf(out, "%-15s%08x\n", "Version:", cert->Version);                          // uint32_t
    sprintf(out+strlen(out), "%-15s%016lx\n", "KeyID0:", cert->KeyID0);               // uint64_t
    sprintf(out+strlen(out), "%-15s%016lx\n", "KeyID1:", cert->KeyID1);               // uint64_t
    sprintf(out+strlen(out), "%-15s%016lx\n", "CertifyingID0:", cert->CertifyingID0); // uint64_t
    sprintf(out+strlen(out), "%-15s%016lx\n", "CertifyingID1:", cert->CertifyingID1); // uint64_t
    sprintf(out+strlen(out), "%-15s%08x\n", "KeyUsage:", cert->KeyUsage);            // uint32_t
    sprintf(out+strlen(out), "%-15s%016lx\n", "Reserved0:", cert->Reserved0);         // uint64_t
    sprintf(out+strlen(out), "%-15s%016lx\n", "Reserved1:", cert->Reserved1);         // uint64_t
    sprintf(out+strlen(out), "%-15s%08x\n", "PubExpSize:", cert->PubExpSize);        // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "ModulusSize:", cert->ModulusSize);      // uint32_t
    sprintf(out+strlen(out), "\nPubExp:\n");
    for(size_t i = 0; i < (size_t)(cert->PubExpSize/8); i++) {  // bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->PubExp)[i] );
    }
    sprintf(out+strlen(out), "\nModulus:\n");
    for(size_t i = 0; i < (size_t)(cert->ModulusSize/8); i++) { // bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Modulus)[i] );
    }
    sprintf(out+strlen(out), "\nSig:\n");
    for(size_t i = 0; i < (size_t)(cert->ModulusSize/8); i++) { // bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Sig)[i] );
    }
    sprintf(out+strlen(out), "\n");

    if(out_str == "NULL") {
        printf("%s\n", out);
    }
    else {
        out_str += out;
    }
}

/**
 * AMD Certs are unions because key sizes can be different. So, you can't just
 * print out the memory, you need to print each parameter based off its correct
 * size
 * Note: there are no spaces in this printout because this function is also used
 *       to write to a .cert file, not just printing to the screen
 */
void print_amd_cert_hex(const AMD_CERT *cert, std::string& out_str)
{
    char out[sizeof(AMD_CERT)*2];   // 2 chars per byte
    size_t fixed_offset = offsetof(AMD_CERT, PubExp);     // 64 bytes

    out[0] = '\0';       // Gotta get the sprintf started

    // Print fixed parameters
    for(size_t i = 0; i < fixed_offset; i++) {
        sprintf(out+strlen(out), "%02X", ((uint8_t *)&cert->Version)[i] );
    }
    // Print PubExp
    for(size_t i = 0; i < (size_t)(cert->PubExpSize/8); i++) {  // bytes to uint8
        sprintf(out+strlen(out), "%02X", ((uint8_t *)&cert->PubExp)[i] );
    }
    // Print nModulus
    for(size_t i = 0; i < (size_t)(cert->ModulusSize/8); i++) { // bytes to uint8
        sprintf(out+strlen(out), "%02X", ((uint8_t *)&cert->Modulus)[i] );
    }
    // Print Sig
    for(size_t i = 0; i < (size_t)(cert->ModulusSize/8); i++) { // bytes to uint8
        sprintf(out+strlen(out), "%02X", ((uint8_t *)&cert->Sig)[i] );
    }

    if(out_str == "NULL") {
        printf("%s\n\n\n", out);
    }
    else {
        out_str += out;
    }
}

/**
 * This function takes Bits, NOT Bytes
 */
bool AMDCert::key_size_is_valid(size_t size)
{
    return (size == AMD_CERT_KEY_BITS_2K) || (size == AMD_CERT_KEY_BITS_4K);
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_sig(const AMD_CERT *cert)
{
    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    SHA256_CTX ctx;
    HMACSHA256 msg_digest;
    // size_t digest_len = 0;       //TODO
    uint8_t signature[AMD_CERT_KEY_BYTES_4K] = {0};
    uint32_t fixed_offset = offsetof(AMD_CERT, PubExp);     // 64 bytes

    do {
        if (!cert) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        // Validate the key sizes before using them
        if (!key_size_is_valid(cert->PubExpSize) || // bits
            !key_size_is_valid(cert->ModulusSize))  // bits
        {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        memset(&ctx, 0, sizeof(ctx));
        memset(&msg_digest, 0, sizeof(msg_digest));

        /*
         * Calculate the digest of the certificate body. This includes the
         * fixed body data, the public exponent, and the modulus.
         */
        if(SHA256_Init(&ctx) != 1)
            break;

        if(SHA256_Update(&ctx, cert, fixed_offset) != 1)
            break;

        if(SHA256_Update(&ctx, &cert->PubExp, cert->PubExpSize/8) != 1)
            break;

        if(SHA256_Update(&ctx, &cert->Modulus, cert->ModulusSize/8) != 1)
            break;

        if(SHA256_Final((uint8_t *)&msg_digest, &ctx) != 1)
            break;

        // Swap the bytes of the signature
        memcpy(signature, &cert->Sig, cert->ModulusSize/8);

        if(!ReverseBytes(signature, cert->ModulusSize/8))
            break;

        // Verify the signature
        // cmd_ret = rsa_pss_verify(msg_digest, digest_len,
        //                         cert->Modulus, cert->ModulusSize/8,
        //                         cert->PubExp, cert->PubExpSize/8,
        //                         signature); // TODO
        cmd_ret = STATUS_SUCCESS;   //TODO
    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_common(const AMD_CERT *cert)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

    do {
        if (!cert) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        if (cert->Version != AMD_CERT_VERSION     ||
            !key_size_is_valid(cert->ModulusSize) ||    // bits
            !key_size_is_valid(cert->PubExpSize))       // bits
        {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
        }
    } while (0);

    return cmd_ret;
}

bool AMDCert::usage_is_valid(uint32_t usage)
{
    return (usage == AMDUsageARK) || (usage == AMDUsageASK);    // ARK, ASK
}

SEV_ERROR_CODE AMDCert::amd_cert_validate(const AMD_CERT *cert,
                                          const AMD_CERT *parent,
                                          uint32_t expected_usage)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
    const uint8_t *key_id = NULL;

    do {
        if (!cert || !usage_is_valid(expected_usage)) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        // Validate the signature before using any certificate fields
        if (parent) {
            cmd_ret = amd_cert_validate_sig(parent);
            if (cmd_ret != STATUS_SUCCESS)
                break;
        }

        // Validate the fixed data
        cmd_ret = amd_cert_validate_common(cert);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // If there is no parent, then the certificate must be self-certified
        key_id = parent ? (uint8_t *)&parent->KeyID0 : (uint8_t *)&cert->KeyID0;

        if (cert->KeyUsage != expected_usage ||
            memcmp(&cert->CertifyingID0, key_id, sizeof(cert->CertifyingID0 + cert->CertifyingID1)) != 0)
        {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
        }
    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_public_key_hash(const AMD_CERT *cert,
                                                 HMACSHA256 *hash)
{
    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    HMACSHA256 tmp_hash;
    // size_t hash_size = sizeof(tmp_hash);
    SHA256_CTX ctx;
    uint32_t fixed_offset = offsetof(AMD_CERT, PubExp);     // 64 bytes

    do {
        if (!cert || !hash) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(&tmp_hash, 0, sizeof(tmp_hash));

        // Calculate the hash of the public key
        if(SHA256_Init(&ctx) != 1)
            break;

        if(SHA256_Update(&ctx, cert, fixed_offset) != 1)
            break;

        if(SHA256_Update(&ctx, &cert->PubExp, cert->PubExpSize/8) != 1)
            break;

        if(SHA256_Update(&ctx, &cert->Modulus, cert->ModulusSize/8) != 1)
            break;

        if(SHA256_Final((uint8_t *)&tmp_hash, &ctx) != 1)
            break;

        // Copy the hash to the output
        memcpy(hash, &tmp_hash, sizeof(HMACSHA256));

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_ark(const AMD_CERT *ark)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
    HMACSHA256 hash;
    HMACSHA256 fused_hash;

    do {
        if (!ark) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(&hash, 0, sizeof(hash));
        memset(&fused_hash, 0, sizeof(fused_hash));

        // Validate the certificate
        cmd_ret = amd_cert_validate(ark, NULL, AMDUsageARK);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        if (memcmp(&ark->KeyID0, amd_root_key_id, sizeof(ark->KeyID0 + ark->KeyID1)) != 0)
        {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        // We have to trust the ARK from the website, as there is no way to
        // validate it further, here. It is trustable due to being transmitted
        // over https
    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE AMDCert::amd_cert_validate_ask(const AMD_CERT *ask, const AMD_CERT *ark)
{
    return amd_cert_validate(ask, ark, AMDUsageASK);    // ASK
}

/**
 * Bytes, NOT bits
 */
size_t AMDCert::amd_cert_get_size(const AMD_CERT *cert)
{
    size_t size = 0;
    uint32_t fixed_offset = offsetof(AMD_CERT, PubExp);     // 64 bytes

    if (cert) {
        size = fixed_offset + (cert->PubExpSize + 2*cert->ModulusSize)/8;
    }
    return size;
}

/**
 * The verify_sev_cert function takes in a parent of an SEV_CERT not
 *   an AMD_CERT, so need to pull the pubkey out of the AMD_CERT and
 *   place it into a tmp SEV_CERT to help validate the cek
 */
SEV_ERROR_CODE AMDCert::amd_cert_export_pubkey(const AMD_CERT *cert,
                                               SEV_CERT *pubkey_cert)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;

    do {
        if (!cert || !pubkey_cert) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(pubkey_cert, 0, sizeof(*pubkey_cert));

        // Todo. This has the potential for issues if we keep the key size
        //       4k and change the SHA type on the next gen
        if(cert->ModulusSize == AMD_CERT_KEY_BITS_2K) {      // Naples
            pubkey_cert->PubkeyAlgo = SEVSigAlgoRSASHA256;
        }
        else if(cert->ModulusSize == AMD_CERT_KEY_BITS_4K) { // Rome
            pubkey_cert->PubkeyAlgo = SEVSigAlgoRSASHA384;
        }

        pubkey_cert->PubkeyUsage = cert->KeyUsage;
        pubkey_cert->Pubkey.RSA.ModulusSize = cert->ModulusSize;
        memcpy(pubkey_cert->Pubkey.RSA.PubExp, &cert->PubExp, cert->PubExpSize/8);
        memcpy(pubkey_cert->Pubkey.RSA.Modulus, &cert->Modulus, cert->ModulusSize/8);
    } while (0);

    return cmd_ret;
}

/**
 * Initialize an AMD_CERT object from a (.cert file) buffer
 *
 * Parameters:
 *     cert     [out] AMD certificate object,
 *     buffer   [in]  buffer containing the raw AMD certificate
 */
SEV_ERROR_CODE AMDCert::amd_cert_init(AMD_CERT *cert, const uint8_t *buffer)
{
    SEV_ERROR_CODE cmd_ret = STATUS_SUCCESS;
    AMD_CERT tmp;
    uint32_t fixed_offset = offsetof(AMD_CERT, PubExp);     // 64 bytes
    uint32_t pub_exp_offset = fixed_offset;                 // 64 bytes
    uint32_t modulus_offset = 0;                            // 2k or 4k bits
    uint32_t sig_offset = 0;                                // 2k or 4k bits

    do {
        if (!cert || !buffer) {
            cmd_ret = ERROR_INVALID_PARAM;
            break;
        }

        memset(&tmp, 0, sizeof(tmp));

        // Copy the fixed body data from the temporary buffer
        memcpy(&tmp, buffer, fixed_offset);

        modulus_offset = pub_exp_offset + (tmp.PubExpSize/8);
        sig_offset = modulus_offset + (tmp.ModulusSize/8);     // Mod size as def in spec

        // Initialize the remainder of the certificate
        memcpy(&tmp.PubExp, (void *)(buffer + pub_exp_offset), tmp.PubExpSize/8);
        memcpy(&tmp.Modulus, (void *)(buffer + modulus_offset), tmp.ModulusSize/8);
        memcpy(&tmp.Sig, (void *)(buffer + sig_offset), tmp.ModulusSize/8);

        memcpy(cert, &tmp, sizeof(*cert));
    } while (0);

    return cmd_ret;
}
