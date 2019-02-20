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

#ifndef amdcert_h
#define amdcert_h

#include "sevapi.h"
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ts.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define AMD_CERT_VERSION        0x01
#define AMD_CERT_ID_SIZE_BYTES    16      // sizeof(AMD_CERT:KeyID0 + AMD_CERT:KeyID1)

enum amd_cert_key_bits
{
    AMD_CERT_KEY_BITS_2K = 2048,
    AMD_CERT_KEY_BITS_4K = 4096,
};

// Public global functions
static std::string amd_empty = "NULL";
void print_amd_cert_readable(AMD_CERT *cert, std::string& out_str = amd_empty);

class AMDCert {
private:
    SEV_ERROR_CODE amd_cert_validate_sig(const AMD_CERT *cert);
    SEV_ERROR_CODE amd_cert_validate_common(const AMD_CERT *cert);
    bool usage_is_valid(uint32_t usage);
    SEV_ERROR_CODE amd_cert_validate(const AMD_CERT *cert,
                                     const AMD_CERT *parent,
                                     uint32_t expected_usage);
    SEV_ERROR_CODE amd_cert_public_key_hash(const AMD_CERT *cert, HMACSHA256 *hash);

public:
    AMDCert() {}
    ~AMDCert() {};

    bool key_size_is_valid(size_t size);
    SEV_ERROR_CODE amd_cert_validate_ark(const AMD_CERT *ark);
    SEV_ERROR_CODE amd_cert_validate_ask(const AMD_CERT *ask, const AMD_CERT *ark);
    size_t amd_cert_get_size(const AMD_CERT *cert);
    SEV_ERROR_CODE amd_cert_export_pubkey(const AMD_CERT *cert, SEV_CERT *pubkey_cert);
    SEV_ERROR_CODE amd_cert_init(AMD_CERT *cert, const uint8_t *buffer);
};

#endif /* amdcert_h */
