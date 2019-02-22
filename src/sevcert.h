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

#ifndef sevcert_h
#define sevcert_h

#include "sevapi.h"
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ts.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// Public global functions
static std::string sev_empty = "NULL";
void print_sev_cert_readable(const SEV_CERT *cert, std::string& outStr = sev_empty);
void print_sev_cert_hex(const SEV_CERT *cert);
void print_cert_chain_buf_readable(const SEV_CERT_CHAIN_BUF *p, std::string& outStr = sev_empty);
void print_cert_chain_buf_hex(const SEV_CERT_CHAIN_BUF *p);

class SEVCert {
private:
    SEV_CERT m_child_cert;
    bool calc_hash_digest(const SEV_CERT *cert, uint32_t pubkey_algo, uint32_t pub_key_offset,
                             HMACSHA256 *sha_digest_256, HMACSHA512 *sha_digest_384);
    SEV_ERROR_CODE validate_usage(uint32_t Usage);
    SEV_ERROR_CODE validate_rsa_pubkey(const SEV_CERT *cert, const EVP_PKEY *PublicKey);
    SEV_ERROR_CODE validate_public_key(const SEV_CERT *cert, const EVP_PKEY *PublicKey);
    SEV_ERROR_CODE validate_signature(const SEV_CERT *child_cert, const SEV_CERT *parent_cert,
                                     EVP_PKEY *parent_signing_key);
    SEV_ERROR_CODE validate_body(const SEV_CERT *cert);

public:
    SEVCert( SEV_CERT& cert ) { m_child_cert = cert; }
    ~SEVCert() {};

    const SEV_CERT *data() { return &m_child_cert; }

    bool sign_with_key( uint32_t Version, uint32_t pub_key_usage, uint32_t pub_key_algorithm,
                      const std::string& oca_priv_key_file, uint32_t sig1_usage, uint32_t sig1_algo );
    SEV_ERROR_CODE compile_public_key_from_certificate(const SEV_CERT *cert, EVP_PKEY *evp_pub_key);
    SEV_ERROR_CODE verify_sev_cert(const SEV_CERT *parent_cert1, const SEV_CERT *parent_cert2 = NULL);
};

#endif /* sevcert_h */
