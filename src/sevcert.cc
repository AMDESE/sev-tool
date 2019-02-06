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

#include "sevcert.h"
#include "crypto/rsa/rsa_locl.h"    // Needed to access internals of struct rsa_st. RSA_pubKey->n
#include "crypto/ec/ec_lcl.h"       // Needed to access internals of struct ECDSA_SIG_st
#include <cstring>                  // memset
#include <stdio.h>
#include <stdexcept>
#include <fstream>
#include <stdio.h>

// Converts X509_CERTs to SEV_CERTs
void SEVCert::SEVCertToX509Cert(const X509_CERT *X509Cert, SEV_CERT *SEVCert)
{

}

// Converts SEV_CERTs to X509_CERTs
void SEVCert::X509CertToSEVCert(const SEV_CERT *SEVCert, X509_CERT *X509Cert)
{

}

// If outStr is passed in, fill up the string, else prints to std::out
void PrintCertReadable(SEV_CERT *cert, std::string& outStr)
{
    char out[sizeof(SEV_CERT)*3+500];   // 2 chars per byte + 1 spaces + ~500 extra chars for text

    sprintf(out, "%-15s%04x\n", "Version:", cert->Version);           // uint32_t
    sprintf(out+strlen(out), "%-15s%04x\n", "ApiMajor:", cert->ApiMajor);         // uint8_t
    sprintf(out+strlen(out), "%-15s%04x\n", "ApiMinor:", cert->ApiMinor);         // uint8_t
    sprintf(out+strlen(out), "%-15s%04x\n", "PubkeyUsage:", cert->PubkeyUsage);   // uint32_t
    sprintf(out+strlen(out), "%-15s%04x\n", "PubkeyAlgo:", cert->PubkeyAlgo);     // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Pubkey:");                               // SEV_PUBKEY
    for(size_t i = 0; i < (size_t)(sizeof(SEV_PUBKEY)); i++) {  //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Pubkey)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%04x\n", "Sig1Usage:", cert->Sig1Usage);       // uint32_t
    sprintf(out+strlen(out), "%-15s%04x\n", "Sig1Algo:", cert->Sig1Algo);         // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Sig1:");                                 // SEV_SIG
    for(size_t i = 0; i < (size_t)(sizeof(SEV_SIG)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Sig1)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%04x\n", "Sig2Usage:", cert->Sig2Usage);       // uint32_t
    sprintf(out+strlen(out), "%-15s%04x\n", "Sig2Algo:", cert->Sig2Algo);         // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Sig2:");                                 // SEV_SIG
    for(size_t i = 0; i < (size_t)(sizeof(SEV_SIG)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Sig2)[i] );
    }
    sprintf(out+strlen(out), "\n");

    if(outStr == "NULL") {
        printf("%s\n", out);
    }
    else {
        outStr += out;
    }
}

// To print this to a file, just use WriteFile directly
void PrintCertHex(void *cert)
{
    printf("Printing Cert...\n");
    for(size_t i = 0; i < (size_t)(sizeof(SEV_CERT)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)cert)[i] );
    }
    printf("\n");
}

// Prints out the PDK, OCA, and CEK
// If outStr is passed in, fill up the string, else prints to std::out
void PrintCertChainBufReadable(void *p, std::string& outStr)
{
    char outPEK[50];    // Just big enough for string below
    char outOCA[50];
    char outCEK[50];

    std::string outStr_local = "";

    sprintf(outPEK, "PEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    outStr_local += outPEK;
    PrintCertReadable(((SEV_CERT*)PEKinCertChain(p)), outStr_local);

    sprintf(outOCA, "\nOCA Memory: %ld bytes\n", sizeof(SEV_CERT));
    outStr_local += outOCA;
    PrintCertReadable(((SEV_CERT*)OCAinCertChain(p)), outStr_local);

    sprintf(outCEK, "\nCEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    outStr_local += outCEK;
    PrintCertReadable(((SEV_CERT*)CEKinCertChain(p)), outStr_local);

    if(outStr == "NULL") {
        printf("%s\n", outStr_local.c_str());
    }
    else {
        outStr = outStr_local;
    }
}

// Prints out the PDK, OCA, and CEK
// To print this to a file, just use WriteFile directly
void PrintCertChainBufHex(void *p)
{
    printf("PEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    for(size_t i = 0; i < (size_t)(sizeof(SEV_CERT)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)PEKinCertChain(p))[i] );
    }
    printf("\nOCA Memory: %ld bytes\n", sizeof(SEV_CERT));
    for(size_t i = 0; i < (size_t)(sizeof(SEV_CERT)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)OCAinCertChain(p))[i] );
    }
    printf("\nCEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    for(size_t i = 0; i < (size_t)(sizeof(SEV_CERT)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)CEKinCertChain(p))[i] );
    }
    printf("\n");
}

bool SEVCert::CalcHashDigest(const SEV_CERT *Cert, uint32_t PubkeyAlgo, uint32_t PubKeyOffset,
                             HMACSHA256 *shaDigest256, HMACSHA512 *shaDigest384)
{
    bool ret = false;
    SHA256_CTX ctx256;
    SHA512_CTX ctx384;              // size is the same for 384 and 512

    // SHA256/SHA384 hash the Cert from Version through Pubkey parameters
    // Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
    do {
        if( (PubkeyAlgo == SEVSigAlgoRSASHA256) ||
            (PubkeyAlgo == SEVSigAlgoECDSASHA256)) {
            if (SHA256_Init(&ctx256) != 1)
                break;
            if (SHA256_Update(&ctx256, Cert, PubKeyOffset) != 1)
                break;
            if (SHA256_Final((uint8_t *)shaDigest256, &ctx256) != 1)  // size = 32
                break;
        }
        else if( (PubkeyAlgo == SEVSigAlgoRSASHA384) ||
                 (PubkeyAlgo == SEVSigAlgoECDSASHA384)) {
            if (SHA384_Init(&ctx384) != 1)
                break;
            if (SHA384_Update(&ctx384, Cert, PubKeyOffset) != 1)
                break;
            if (SHA384_Final((uint8_t *)shaDigest384, &ctx384) != 1)  // size = 32
                break;
        }
        // Don't calculate for ECDH
        ret = true;
    } while (0);
    return ret;
}

// sev_cert.c -> sev_cert_create() (kinda)
// Signs the PEK's sig1 with the OCA (private key)
// The firmware signs sig2 with the CEK during PEK_CERT_IMPORT
// Inputs: Version, PubKeyUsage, PubKeyAlgorithm are for the child cert (PEK)
//         OCAPrivKeyFile, Sig1Usage, Sig1Algo are for the parent (OCA)
/* To optimize this function, can make the PEM read code RSA, EC, or general EVP.
The issue is that if it reads it into a common-format EVP_PKEY, how to we get that
private key into the EC_KEY or RSA_KEY that we are doing the signing on.
Also, to make the EC_KEY validate, I only figured out how to create the EC_KEY with
a GROUP as the input parm, not new up the EC_KEY then assign it a GROUP and all other
params later (don't know what other params it needed to validate correctly) */
bool SEVCert::SignWithKey( uint32_t Version, uint32_t PubKeyUsage, uint32_t PubKeyAlgorithm,
                           const std::string& OCAPrivKeyFile, uint32_t Sig1Usage, uint32_t Sig1Algo )
{
    bool isValid = false;
    HMACSHA256 shaDigest256;           // Hash on the cert from Version to PubKey
    HMACSHA512 shaDigest384;           // Hash on the cert from Version to PubKey
    EC_KEY *privECKey = NULL;
    RSA *privRSAKey = NULL;

    do {
        // Sign the certificate    sev_cert.c -> sev_cert_sign()
        // The constructor defaults all member vars, and the user can change them
        memset(&mChildCert.Sig1, 0, sizeof(SEV_CERT::Sig1));
        mChildCert.Version = Version;
        mChildCert.PubkeyUsage = PubKeyUsage;
        mChildCert.PubkeyAlgo = PubKeyAlgorithm;

        mChildCert.Sig1Usage = Sig1Usage;       // Parent cert's sig
        mChildCert.Sig1Algo = Sig1Algo;

        // SHA256/SHA384 hash the Cert from the [Version:Pubkey] params
        uint32_t PubKeyOffset = offsetof(SEV_CERT, Sig1Usage);  // 16 + sizeof(SEV_PUBKEY)
        if(!CalcHashDigest(&mChildCert, Sig1Algo, PubKeyOffset, &shaDigest256, &shaDigest384))
            break;

        if( (Sig1Algo == SEVSigAlgoRSASHA256) ||
            (Sig1Algo == SEVSigAlgoRSASHA384)) {
            printf("Error: RSA signing untested!");
            // This code probably does not work!

            if (!(privRSAKey = RSA_new()))
                break;

            // Read in the private key file into EVP_PKEY
            // You cannot call a sub-function here because the privRSAKey doesn't get set correctly
            FILE *pFile = fopen(OCAPrivKeyFile.c_str(), "r");
            if(!pFile) {
                printf("OCA private key file not found\n");
                break;
            }
            privRSAKey = PEM_read_RSAPrivateKey(pFile, NULL, NULL, NULL);
            fclose (pFile);
            if(!privRSAKey)
                break;

            uint32_t sigLen = sizeof(mChildCert.Sig1.RSA);
            if(Sig1Algo == SEVSigAlgoRSASHA256) {
                if(RSA_sign(NID_sha256, shaDigest256, sizeof(shaDigest256), (uint8_t *)&mChildCert.Sig1.RSA, &sigLen, privRSAKey) != 1)
                    break;
                if(RSA_verify(NID_sha256, shaDigest256, sizeof(shaDigest256), (uint8_t *)&mChildCert.Sig1.RSA, sigLen, privRSAKey) != 1)
                    break;
            }
            else if(Sig1Algo == SEVSigAlgoRSASHA384) {
                if(RSA_sign(NID_sha384, shaDigest384, sizeof(shaDigest384), (uint8_t *)&mChildCert.Sig1.RSA, &sigLen, privRSAKey) != 1)
                    break;
                if(RSA_verify(NID_sha384, shaDigest384, sizeof(shaDigest384), (uint8_t *)&mChildCert.Sig1.RSA, sigLen, privRSAKey) != 1)
                    break;
            }
        }
        else if( (Sig1Algo == SEVSigAlgoECDSASHA256) ||
                 (Sig1Algo ==  SEVSigAlgoECDSASHA384)) {
            // New up the EC_KEY with the EC_GROUP
            int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
            privECKey = EC_KEY_new_by_curve_name(nid);

            // Read in the private key file into EVP_PKEY
            // You cannot call a sub-function here because the privECKey doesn't get set correctly
            FILE *pFile = fopen(OCAPrivKeyFile.c_str(), "r");
            if(!pFile) {
                printf("OCA private key file not found\n");
                break;
            }
            privECKey = PEM_read_ECPrivateKey(pFile, NULL, NULL, NULL);
            fclose(pFile);
            if(!privECKey)
                break;

            if(Sig1Algo == SEVSigAlgoECDSASHA256) {
                ECDSA_SIG *sig = ECDSA_do_sign(shaDigest256, sizeof(shaDigest256), privECKey); // Contains 2 bignums
                if(!sig)
                    break;
                BN_bn2lebinpad(sig->r, mChildCert.Sig1.ECDSA.R, sizeof(SEV_ECDSA_SIG::R));    // LE to BE
                BN_bn2lebinpad(sig->s, mChildCert.Sig1.ECDSA.S, sizeof(SEV_ECDSA_SIG::S));

                // Validation will also be done by the FW
                if(ECDSA_do_verify(shaDigest256, sizeof(shaDigest256), sig, privECKey) != 1) {
                    ECDSA_SIG_free(sig);
                    break;
                }
                ECDSA_SIG_free(sig);
            }
            else if(Sig1Algo == SEVSigAlgoECDSASHA384) {
                ECDSA_SIG *sig = ECDSA_do_sign(shaDigest384, sizeof(shaDigest384), privECKey); // Contains 2 bignums
                if(!sig)
                    break;
                BN_bn2lebinpad(sig->r, mChildCert.Sig1.ECDSA.R, sizeof(SEV_ECDSA_SIG::R));    // LE to BE
                BN_bn2lebinpad(sig->s, mChildCert.Sig1.ECDSA.S, sizeof(SEV_ECDSA_SIG::S));

                // Validation will also be done by the FW
                if(ECDSA_do_verify(shaDigest384, sizeof(shaDigest384), sig, privECKey) != 1) {
                    ECDSA_SIG_free(sig);
                    break;
                }
                ECDSA_SIG_free(sig);
            }
        }
        else if( (Sig1Algo == SEVSigAlgoECDHSHA256) ||
                 (Sig1Algo == SEVSigAlgoECDHSHA384)) {
            printf("Error: ECDH signing unsupported");
            break;                       // Error unsupported
        }
        else {
            printf("Error: invalid signing algo. Can't sign");
            break;                          // Invalid params
        }

        isValid = true;
    } while (0);

    // Free memory
    EC_KEY_free(privECKey);
    RSA_free(privRSAKey);

    return isValid;
}

//sev_cert.c  -> usage_is_valid()
SEV_ERROR_CODE SEVCert::ValidateUsage(uint32_t Usage)
{
    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;

    switch (Usage)
    {
    case SEVUsageARK:
    case SEVUsageASK:
    case SEVUsageOCA:
    case SEVUsagePEK:
    case SEVUsagePDH:
    case SEVUsageCEK:
        CmdRet = STATUS_SUCCESS;
        break;
    default:
        CmdRet = ERROR_INVALID_CERTIFICATE;
    }

    return CmdRet;
}

// rsa.c -> rsa_pubkey_is_valid()
// This function is untested because we don't have any RSA certs to test
SEV_ERROR_CODE SEVCert::ValidateRSAPubkey(const SEV_CERT *Cert, const EVP_PKEY *PublicKey)
{
    if (!Cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;

    if (Cert->Pubkey.RSA.ModulusSize <= (SEV_RSA_PUBKEY_MAX_BITS/8))    //TODO, bits or bytes
		CmdRet = STATUS_SUCCESS;

    return CmdRet;
}

// rsa.c -> pubkey_is_valid()
// Inputs: Cert is the child cert
//         PublicKey is the parent's public key
SEV_ERROR_CODE SEVCert::ValidatePublicKey(const SEV_CERT *Cert, const EVP_PKEY *PublicKey)
{
    if (!Cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;

    do {
        if(ValidateUsage(Cert->PubkeyUsage) != STATUS_SUCCESS)
            break;

        if( (Cert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
            (Cert->PubkeyAlgo == SEVSigAlgoRSASHA384) ) {
            if(ValidateRSAPubkey(Cert, PublicKey) != STATUS_SUCCESS)
                break;
        }
        else if( (Cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                 (Cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                 (Cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                 (Cert->PubkeyAlgo == SEVSigAlgoECDHSHA384) )
            ;       // Are no invalid values for these cert types
        else
            break;

        CmdRet = STATUS_SUCCESS;
    } while (0);

    return CmdRet;
}

// sev_cert.c -> sev_cert_validate_sig()
// This function gets called from a loop, and this function has
// to see which of the signatures this currentSig matches to
// Inputs Ex) ChildCert = PEK. ParentCert = OCA. ParentSigningKey = OCA PubKey.
SEV_ERROR_CODE SEVCert::ValidateSignature(const SEV_CERT *ChildCert,
                                          const SEV_CERT *ParentCert,
                                          EVP_PKEY *ParentSigningKey)    // Probably PubKey
{
    if (!ChildCert || !ParentCert || !ParentSigningKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;
    SEV_SIG CertSig[SEV_CERT_MAX_SIGNATURES] = {ChildCert->Sig1, ChildCert->Sig2};
    HMACSHA256 shaDigest256;        // Hash on the cert from Version to PubKey
    HMACSHA512 shaDigest384;        // Hash on the cert from Version to PubKey

    do{
        // 1. SHA256 hash the Cert from Version through Pubkey parameters
        // Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
        uint32_t PubKeyOffset = offsetof(SEV_CERT, Sig1Usage);  // 16 + sizeof(SEV_PUBKEY)
        if(!CalcHashDigest(ChildCert, ParentCert->PubkeyAlgo, PubKeyOffset, &shaDigest256, &shaDigest384)) {
            break;
        }

        // 2. Use the Pubkey in sig[i] arg to decrypt the sig in ChildCert arg
        // Try both sigs in ChildCert, to see if either of them match. In PEK, CEK and OCA can be in any order
        bool foundMatch = false;
        for (int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++)
        {
            if( (ParentCert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
                (ParentCert->PubkeyAlgo == SEVSigAlgoRSASHA384)) {
                // TODO: THIS CODE IS UNTESTED!!!!!!!!!!!!!!!!!!!!!!!!!!!
                printf("WARNING: You are using untested code in"
                    "ValidateSignature for RSA cert type!\n");
                // if( RSA_verify(NID_sha256, shaDigest, sizeof(shaDigest), (uint8_t *)&ParentCert->Sig1.RSA,
                //                sizeof(SEV_RSA_SIG), EVP_PKEY_get1_RSA(SigningKey[i])) != 1 ) {
                // }
                continue;
            }
            else if( (ParentCert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                     (ParentCert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                     (ParentCert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                     (ParentCert->PubkeyAlgo == SEVSigAlgoECDHSHA384)) {      // ecdsa.c -> sign_verify_msg
                ECDSA_SIG *tmp_ecdsa_sig = ECDSA_SIG_new();
                BIGNUM *rBigNum = BN_new();
                BIGNUM *sBigNum = BN_new();

                // Store the x and y components as separate BIGNUM objects. The values in the
                // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
                rBigNum = BN_lebin2bn(CertSig[i].ECDSA.R, sizeof(SEV_ECDSA_SIG::R), rBigNum);    // LE to BE
                sBigNum = BN_lebin2bn(CertSig[i].ECDSA.S, sizeof(SEV_ECDSA_SIG::S), sBigNum);

                // Calling ECDSA_SIG_set0() transfers the memory management of the values to
                // the ECDSA_SIG object, and therefore the values that have been passed
                // in should not be freed directly after this function has been called
                if(ECDSA_SIG_set0(tmp_ecdsa_sig, rBigNum, sBigNum) != 1) {
                    BN_free(sBigNum);
                    BN_free(rBigNum);
                    continue;
                }
                if( (ParentCert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                    (ParentCert->PubkeyAlgo == SEVSigAlgoECDHSHA256)) {
                    if(ECDSA_do_verify(shaDigest256, sizeof(shaDigest256), tmp_ecdsa_sig,
                                    EVP_PKEY_get1_EC_KEY(ParentSigningKey)) == 1)
                        foundMatch = true;
                }
                else if( (ParentCert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                         (ParentCert->PubkeyAlgo == SEVSigAlgoECDHSHA384)) {
                    if(ECDSA_do_verify(shaDigest384, sizeof(shaDigest384), tmp_ecdsa_sig,
                                EVP_PKEY_get1_EC_KEY(ParentSigningKey)) == 1)
                        foundMatch = true;
                }
                ECDSA_SIG_free(tmp_ecdsa_sig);      // Frees BIGNUMs too
                continue;
            }
            else {       // Bad/unsupported signing key algorithm
                printf("Unexpected algorithm! %x\n", ParentCert->PubkeyAlgo);
                break;
            }
        }
        if(!foundMatch)
            break;

        // 3. Compare

        CmdRet = STATUS_SUCCESS;
    } while (0);

    return CmdRet;
}

// sev_cert.c -> sev_cert_validate_body()
SEV_ERROR_CODE SEVCert::ValidateBody(const SEV_CERT *Cert)
{
    if (!Cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;

    do {
        if ( (Cert->Version == 0) || (Cert->Version > SEV_CERT_MAX_VERSION) )
            break;

        CmdRet = STATUS_SUCCESS;
    } while (0);

    return CmdRet;
}

// Note that this function NEWs/allocates memory for a EC_KEY
//  that must be freed in the calling function using EC_KEY_free()
// Inputs: Cert is the parent Cert
//         pubKey is the parent's public key
SEV_ERROR_CODE SEVCert::CompilePublicKeyFromCertificate(const SEV_CERT* Cert, EVP_PKEY* EVP_pubKey)
{
    if(!Cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;
    struct rsa_st *RSA_pubKey = NULL;
    EC_KEY *EC_pubKey = NULL;
    BIGNUM *xBigNum = NULL;
    BIGNUM *yBigNum = NULL;
    BIGNUM *Modulus = NULL;
    BIGNUM *PubExp = NULL;

    do {
        if( (Cert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
            (Cert->PubkeyAlgo == SEVSigAlgoRSASHA384) ) {
            // TODO: THIS CODE IS UNTESTED!!!!!!!!!!!!!!!!!!!!!!!!!!!
            printf("WARNING: You are using untested code in"
                   "CompilePublicKeyFromCertificate for RSA cert type!\n");
            RSA_pubKey = RSA_new();

            Modulus = BN_lebin2bn(Cert->Pubkey.RSA.Modulus, sizeof(Cert->Pubkey.RSA.Modulus), NULL);  // New's up BigNum
            PubExp  = BN_lebin2bn(Cert->Pubkey.RSA.PubExp,  sizeof(Cert->Pubkey.RSA.PubExp), NULL);
            RSA_pubKey->n = Modulus;
            RSA_pubKey->e = PubExp;

            // Make sure the key is good. TODO: Will this step work?
            if (RSA_check_key(RSA_pubKey) != 1)
                break;

            // Create a public EVP_PKEY from the public RSA_KEY
            // This function links EVP_pubKey to RSA_pubKey, so when EVP_pubKey is freed, RSA_pubKey is freed
            // We don't want the user to have to manage 2 keys, so just return EVP_PKEY and make sure user free's it
            EVP_PKEY_assign_RSA(EVP_pubKey, RSA_pubKey);
        }
        else if( (Cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                 (Cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                 (Cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                 (Cert->PubkeyAlgo == SEVSigAlgoECDHSHA384) ) {      // ecdsa.c -> sign_verify_msg

            // Store the x and y components as separate BIGNUM objects. The values in the
            // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
            xBigNum = BN_lebin2bn(Cert->Pubkey.ECDH.QX, sizeof(Cert->Pubkey.ECDH.QX), NULL);  // New's up BigNum
            yBigNum = BN_lebin2bn(Cert->Pubkey.ECDH.QY, sizeof(Cert->Pubkey.ECDH.QY), NULL);

            int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1

            // Create/allocate memory for an EC_KEY object using the NID above
            if (!(EC_pubKey = EC_KEY_new_by_curve_name(nid)))
                break;
            // Store the x and y coordinates of the public key
            if (EC_KEY_set_public_key_affine_coordinates(EC_pubKey, xBigNum, yBigNum) != 1)
                break;
            // Make sure the key is good
            if (EC_KEY_check_key(EC_pubKey) != 1)
                break;

            // Create a public EVP_PKEY from the public EC_KEY
            // This function links EVP_pubKey to EC_pubKey, so when EVP_pubKey is freed, EC_pubKey is freed
            // We don't want the user to have to manage 2 keys, so just return EVP_PKEY and make sure user free's it
            EVP_PKEY_assign_EC_KEY(EVP_pubKey, EC_pubKey);
        }

        if (!EVP_pubKey)
            break;

        CmdRet = STATUS_SUCCESS;
    } while (0);

    // Free memory if it was allocated
    BN_free(yBigNum);       // If NULL, does nothing
    BN_free(xBigNum);
    BN_free(Modulus);
    BN_free(PubExp);

    return CmdRet;
}

// Takes in a signed certificate and validates the signature(s)
// against the public keys in other certificates.
// This test assumes ParentCert1 is always valid, and ParentCert2 may be valid
// sev_cert.c -> sev_cert_validate()
SEV_ERROR_CODE SEVCert::VerifySEVCert(const SEV_CERT *ParentCert1, const SEV_CERT *ParentCert2)
{
    if(!ParentCert1)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE CmdRet = ERROR_INVALID_CERTIFICATE;
    EVP_PKEY *ParentPubKey[SEV_CERT_MAX_SIGNATURES] = {NULL};
    const SEV_CERT *ParentCert[SEV_CERT_MAX_SIGNATURES] = {ParentCert1, ParentCert2};   // A cert has max of x parents/sigs

    do {
        // Get the public key from parent certs
        int numSigs = (ParentCert1 && ParentCert2) ? 2 : 1;   // Run the loop for 1 or 2 signatures
        int i = 0;
        for (i = 0; i < numSigs; i++)
        {
            // New up the EVP_PKEY
            if (!(ParentPubKey[i] = EVP_PKEY_new()))
                break;

            // This function allocates memory and attaches an EC_Key
            //  to your EVP_PKEY so, to prevent mem leaks, make sure
            //  the EVP_PKEY is freed at the end of this function
            if(CompilePublicKeyFromCertificate(ParentCert[i], ParentPubKey[i]) != STATUS_SUCCESS)
                break;

            // Now, we have Parent's PublicKey(s), validate them
            if (ValidatePublicKey(&mChildCert, ParentPubKey[i]) != STATUS_SUCCESS)
                break;

            // Validate the signature before we do any other checking
            // Sub-function will need a separate loop to find which of the 2 signatures this one matches to
            if(ValidateSignature(&mChildCert, ParentCert[i], ParentPubKey[i]) != STATUS_SUCCESS)
                break;
        }
        if(i != numSigs)
            break;

        // Validate the certificate body
        if(ValidateBody(&mChildCert) != STATUS_SUCCESS)
            break;


        // Although the signature was valid, ensure that the certificate
        // was signed with the proper key(s) in the correct order
        if(mChildCert.PubkeyUsage == SEVUsagePDH) {
            // The PDH certificate must be signed by the PEK
            if(ParentCert1->PubkeyUsage != SEVUsagePEK) {
                break;
            }
        }
        else if(mChildCert.PubkeyUsage == SEVUsagePEK) {
            // The PEK certificate must be signed by the CEK and the OCA
            if( ((ParentCert1->PubkeyUsage != SEVUsageOCA) && (ParentCert2->PubkeyUsage != SEVUsageCEK)) &&
                ((ParentCert2->PubkeyUsage != SEVUsageOCA) && (ParentCert1->PubkeyUsage != SEVUsageCEK)) ) {
                break;
            }
        }
        else if(mChildCert.PubkeyUsage == SEVUsageOCA) {
            // The OCA certificate must be self-signed
            if(ParentCert1->PubkeyUsage != SEVUsageOCA) {
                break;
            }
        }
        else if(mChildCert.PubkeyUsage == SEVUsageCEK) {
            // The CEK must be signed by the ASK
            if(ParentCert1->PubkeyUsage != SEVUsageASK) {
                break;
            }
        }
        else
            break;

        CmdRet = STATUS_SUCCESS;
    } while (0);

    // Free memory
    for(int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
        EVP_PKEY_free(ParentPubKey[i]);
    }

    return CmdRet;
}
