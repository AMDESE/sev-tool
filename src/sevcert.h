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
#include "x509cert.h"
#include <string>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ts.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

// Public global functions
void PrintCert(SEV_CERT* cert);
void PrintCertHex(void* cert);
void PrintCertChainBufHex(void* p);

class SEVCert {
private:
    SEV_CERT mChildCert;
    bool CalcHashDigest(const SEV_CERT *Cert, uint32_t PubkeyAlgo, uint32_t PubKeyOffset,
                             HMACSHA256* shaDigest256, HMACSHA512* shaDigest384);
    SEV_ERROR_CODE ValidateUsage(uint32_t Usage);
    SEV_ERROR_CODE ValidateRSAPubkey(const SEV_CERT *Cert, const EVP_PKEY *PublicKey);
    SEV_ERROR_CODE ValidatePublicKey(const SEV_CERT *Cert, const EVP_PKEY *PublicKey);
    SEV_ERROR_CODE ValidateSignature(const SEV_CERT *ChildCert, const SEV_CERT *ParentCert,
                                     EVP_PKEY *ParentSigningKey);
    SEV_ERROR_CODE ValidateBody(const SEV_CERT *Cert);

public:
    SEVCert( SEV_CERT& cert ) { mChildCert = cert; }
    ~SEVCert() {};

    const SEV_CERT *Data() { return &mChildCert; }

    void SEVCertToX509Cert(const X509_CERT *X509Cert, SEV_CERT *SEVCert);
    void X509CertToSEVCert(const SEV_CERT *SEVCert, X509_CERT *X509Cert);

    bool SignWithKey( uint32_t Version, uint32_t PubKeyUsage, uint32_t PubKeyAlgorithm,
                      const std::string& OCAPrivKeyFile, uint32_t Sig1Usage, uint32_t Sig1Algo );
    SEV_ERROR_CODE CompilePublicKeyFromCertificate(const SEV_CERT* Cert, EVP_PKEY* EVP_pubKey);
    SEV_ERROR_CODE VerifySEVCert(const SEV_CERT *ParentCert1, const SEV_CERT *ParentCert2 = NULL);
};

#endif /* sevcert_h */
