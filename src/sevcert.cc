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
#include "utilities.h"
#include "crypto/rsa/rsa_locl.h"    // Needed to access internals of struct rsa_st. rsa_pub_key->n
#include "crypto/ec/ec_lcl.h"       // Needed to access internals of struct ECDSA_SIG_st
#include <cstring>                  // memset
#include <stdio.h>
#include <stdexcept>
#include <fstream>
#include <stdio.h>

/**
 * Converts X509_CERTs to SEV_CERTs
 */
// void SEVCert::sev_cert_to_x509_cert(const X509_CERT *x509_cert, SEV_CERT *sev_cert)
// {

// }

/**
 * Converts SEV_CERTs to X509_CERTs
 */
// void SEVCert::x509_cert_to_sev_cert(const SEV_CERT *sev_cert, X509_CERT *x509_cert)
// {

// }

/**
 * If outStr is passed in, fill up the string, else prints to std::out
 */
void print_cert_readable(const SEV_CERT *cert, std::string& outStr)
{
    char out[sizeof(SEV_CERT)*3+500];   // 2 chars per byte + 1 spaces + ~500 extra chars for text

    sprintf(out, "%-15s%08x\n", "Version:", cert->Version);                         // uint32_t
    sprintf(out+strlen(out), "%-15s%02x\n", "ApiMajor:", cert->ApiMajor);           // uint8_t
    sprintf(out+strlen(out), "%-15s%02x\n", "ApiMinor:", cert->ApiMinor);           // uint8_t
    sprintf(out+strlen(out), "%-15s%08x\n", "pub_key_usage:", cert->PubkeyUsage); // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "pubkey_algo:", cert->PubkeyAlgo);     // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Pubkey:");                                 // SEV_PUBKEY
    for(size_t i = 0; i < (size_t)(sizeof(SEV_PUBKEY)); i++) {  //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Pubkey)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%08x\n", "sig1_usage:", cert->Sig1Usage);       // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "sig1_algo:", cert->Sig1Algo);         // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Sig1:");                                   // SEV_SIG
    for(size_t i = 0; i < (size_t)(sizeof(SEV_SIG)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Sig1)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%08x\n", "Sig2Usage:", cert->Sig2Usage);       // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "Sig2Algo:", cert->Sig2Algo);         // uint32_t
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

/**
 * To print this to a file, just use WriteFile directly
 */
void print_cert_hex(void *cert)
{
    printf("Printing cert...\n");
    for(size_t i = 0; i < (size_t)(sizeof(SEV_CERT)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)cert)[i] );
    }
    printf("\n");
}

/**
 * Prints out the PDK, OCA, and CEK
 * If outStr is passed in, fill up the string, else prints to std::out
 */
void print_cert_chain_buf_readable(void *p, std::string& outStr)
{
    char out_pek[50];    // Just big enough for string below
    char out_oca[50];
    char out_cek[50];

    std::string out_str_local = "";

    sprintf(out_pek, "PEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    out_str_local += out_pek;
    print_cert_readable(((SEV_CERT*)PEKinCertChain(p)), out_str_local);

    sprintf(out_oca, "\nOCA Memory: %ld bytes\n", sizeof(SEV_CERT));
    out_str_local += out_oca;
    print_cert_readable(((SEV_CERT*)OCAinCertChain(p)), out_str_local);

    sprintf(out_cek, "\nCEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    out_str_local += out_cek;
    print_cert_readable(((SEV_CERT*)CEKinCertChain(p)), out_str_local);

    if(outStr == "NULL") {
        printf("%s\n", out_str_local.c_str());
    }
    else {
        outStr = out_str_local;
    }
}

/*
 * Prints out the PDK, OCA, and CEK
 * To print this to a file, just use WriteFile directly
 */
void print_cert_chain_buf_hex(void *p)
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

bool SEVCert::calc_hash_digest(const SEV_CERT *cert, uint32_t pubkey_algo, uint32_t pub_key_offset,
                             HMACSHA256 *sha_digest_256, HMACSHA512 *sha_digest_384)
{
    bool ret = false;
    SHA256_CTX ctx_256;
    SHA512_CTX ctx_384;              // size is the same for 384 and 512

    // SHA256/SHA384 hash the cert from Version through Pubkey parameters
    // Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
    do {
        if( (pubkey_algo == SEVSigAlgoRSASHA256) ||
            (pubkey_algo == SEVSigAlgoECDSASHA256)) {
            if (SHA256_Init(&ctx_256) != 1)
                break;
            if (SHA256_Update(&ctx_256, cert, pub_key_offset) != 1)
                break;
            if (SHA256_Final((uint8_t *)sha_digest_256, &ctx_256) != 1)  // size = 32
                break;
        }
        else if( (pubkey_algo == SEVSigAlgoRSASHA384) ||
                 (pubkey_algo == SEVSigAlgoECDSASHA384)) {
            if (SHA384_Init(&ctx_384) != 1)
                break;
            if (SHA384_Update(&ctx_384, cert, pub_key_offset) != 1)
                break;
            if (SHA384_Final((uint8_t *)sha_digest_384, &ctx_384) != 1)  // size = 32
                break;
        }
        // Don't calculate for ECDH
        ret = true;
    } while (0);
    return ret;
}

/**
 * sev_cert.c -> sev_cert_create() (kinda)
 * Signs the PEK's sig1 with the OCA (private key)
 * The firmware signs sig2 with the CEK during PEK_CERT_IMPORT
 * Inputs: Version, pub_key_usage, pub_key_algorithm are for the child cert (PEK)
 *         oca_priv_key_file, sig1_usage, sig1_algo are for the parent (OCA)
 *
 * To optimize this function, can make the PEM read code RSA, EC, or general EVP.
 * The issue is that if it reads it into a common-format EVP_PKEY, how to we get that
 * private key into the EC_KEY or RSA_KEY that we are doing the signing on.
 * Also, to make the EC_KEY validate, I only figured out how to create the EC_KEY with
 * a GROUP as the input parm, not new up the EC_KEY then assign it a GROUP and all other
 * params later (don't know what other params it needed to validate correctly)
 */
bool SEVCert::sign_with_key( uint32_t Version, uint32_t pub_key_usage, uint32_t pub_key_algorithm,
                           const std::string& oca_priv_key_file, uint32_t sig1_usage, uint32_t sig1_algo )
{
    bool isValid = false;
    HMACSHA256 sha_digest_256;           // Hash on the cert from Version to PubKey
    HMACSHA512 sha_digest_384;           // Hash on the cert from Version to PubKey
    EC_KEY *priv_ec_key = NULL;
    RSA *priv_rsa_key = NULL;

    do {
        // Sign the certificate    sev_cert.c -> sev_cert_sign()
        // The constructor defaults all member vars, and the user can change them
        memset(&m_child_cert.Sig1, 0, sizeof(SEV_CERT::Sig1));
        m_child_cert.Version = Version;
        m_child_cert.PubkeyUsage = pub_key_usage;
        m_child_cert.PubkeyAlgo = pub_key_algorithm;

        m_child_cert.Sig1Usage = sig1_usage;       // Parent cert's sig
        m_child_cert.Sig1Algo = sig1_algo;

        // SHA256/SHA384 hash the cert from the [Version:Pubkey] params
        uint32_t pub_key_offset = offsetof(SEV_CERT, Sig1Usage);  // 16 + sizeof(SEV_PUBKEY)
        if(!calc_hash_digest(&m_child_cert, sig1_algo, pub_key_offset, &sha_digest_256, &sha_digest_384))
            break;

        if( (sig1_algo == SEVSigAlgoRSASHA256) ||
            (sig1_algo == SEVSigAlgoRSASHA384)) {
            printf("Error: RSA signing untested!");
            // This code probably does not work!

            if (!(priv_rsa_key = RSA_new()))
                break;

            // Read in the private key file into EVP_PKEY
            // You cannot call a sub-function here because the priv_rsa_key doesn't get set correctly
            FILE *pFile = fopen(oca_priv_key_file.c_str(), "r");
            if(!pFile) {
                printf("OCA private key file not found\n");
                break;
            }
            priv_rsa_key = PEM_read_RSAPrivateKey(pFile, NULL, NULL, NULL);
            fclose (pFile);
            if(!priv_rsa_key)
                break;

            uint32_t sigLen = sizeof(m_child_cert.Sig1.RSA);
            if(sig1_algo == SEVSigAlgoRSASHA256) {
                if(RSA_sign(NID_sha256, sha_digest_256, sizeof(sha_digest_256), (uint8_t *)&m_child_cert.Sig1.RSA, &sigLen, priv_rsa_key) != 1)
                    break;
                if(RSA_verify(NID_sha256, sha_digest_256, sizeof(sha_digest_256), (uint8_t *)&m_child_cert.Sig1.RSA, sigLen, priv_rsa_key) != 1)
                    break;
            }
            else if(sig1_algo == SEVSigAlgoRSASHA384) {
                if(RSA_sign(NID_sha384, sha_digest_384, sizeof(sha_digest_384), (uint8_t *)&m_child_cert.Sig1.RSA, &sigLen, priv_rsa_key) != 1)
                    break;
                if(RSA_verify(NID_sha384, sha_digest_384, sizeof(sha_digest_384), (uint8_t *)&m_child_cert.Sig1.RSA, sigLen, priv_rsa_key) != 1)
                    break;
            }
        }
        else if( (sig1_algo == SEVSigAlgoECDSASHA256) ||
                 (sig1_algo ==  SEVSigAlgoECDSASHA384)) {
            // New up the EC_KEY with the EC_GROUP
            int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
            priv_ec_key = EC_KEY_new_by_curve_name(nid);

            // Read in the private key file into EVP_PKEY
            // You cannot call a sub-function here because the priv_ec_key doesn't get set correctly
            FILE *pFile = fopen(oca_priv_key_file.c_str(), "r");
            if(!pFile) {
                printf("OCA private key file not found\n");
                break;
            }
            priv_ec_key = PEM_read_ECPrivateKey(pFile, NULL, NULL, NULL);
            fclose(pFile);
            if(!priv_ec_key)
                break;

            if(sig1_algo == SEVSigAlgoECDSASHA256) {
                ECDSA_SIG *sig = ECDSA_do_sign(sha_digest_256, sizeof(sha_digest_256), priv_ec_key); // Contains 2 bignums
                if(!sig)
                    break;
                BN_bn2lebinpad(sig->r, m_child_cert.Sig1.ECDSA.R, sizeof(SEV_ECDSA_SIG::R));    // LE to BE
                BN_bn2lebinpad(sig->s, m_child_cert.Sig1.ECDSA.S, sizeof(SEV_ECDSA_SIG::S));

                // Validation will also be done by the FW
                if(ECDSA_do_verify(sha_digest_256, sizeof(sha_digest_256), sig, priv_ec_key) != 1) {
                    ECDSA_SIG_free(sig);
                    break;
                }
                ECDSA_SIG_free(sig);
            }
            else if(sig1_algo == SEVSigAlgoECDSASHA384) {
                ECDSA_SIG *sig = ECDSA_do_sign(sha_digest_384, sizeof(sha_digest_384), priv_ec_key); // Contains 2 bignums
                if(!sig)
                    break;
                BN_bn2lebinpad(sig->r, m_child_cert.Sig1.ECDSA.R, sizeof(SEV_ECDSA_SIG::R));    // LE to BE
                BN_bn2lebinpad(sig->s, m_child_cert.Sig1.ECDSA.S, sizeof(SEV_ECDSA_SIG::S));

                // Validation will also be done by the FW
                if(ECDSA_do_verify(sha_digest_384, sizeof(sha_digest_384), sig, priv_ec_key) != 1) {
                    ECDSA_SIG_free(sig);
                    break;
                }
                ECDSA_SIG_free(sig);
            }
        }
        else if( (sig1_algo == SEVSigAlgoECDHSHA256) ||
                 (sig1_algo == SEVSigAlgoECDHSHA384)) {
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
    EC_KEY_free(priv_ec_key);
    RSA_free(priv_rsa_key);

    return isValid;
}

/**
 * sev_cert.c  -> usage_is_valid()
 */
SEV_ERROR_CODE SEVCert::validate_usage(uint32_t Usage)
{
    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    switch (Usage)
    {
    case SEVUsageARK:
    case SEVUsageASK:
    case SEVUsageOCA:
    case SEVUsagePEK:
    case SEVUsagePDH:
    case SEVUsageCEK:
        cmd_ret = STATUS_SUCCESS;
        break;
    default:
        cmd_ret = ERROR_INVALID_CERTIFICATE;
    }

    return cmd_ret;
}

/**
 * rsa.c -> rsa_pubkey_is_valid()
 * This function is untested because we don't have any RSA certs to test
 */
SEV_ERROR_CODE SEVCert::validate_rsa_pubkey(const SEV_CERT *cert, const EVP_PKEY *PublicKey)
{
    if (!cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    if (cert->Pubkey.RSA.ModulusSize <= SEV_RSA_PUBKEY_MAX_BITS)
        cmd_ret = STATUS_SUCCESS;

    return cmd_ret;
}

/**
 * rsa.c -> pubkey_is_valid()
 * Inputs: cert is the child cert
 *         PublicKey is the parent's public key
 */
SEV_ERROR_CODE SEVCert::validate_public_key(const SEV_CERT *cert, const EVP_PKEY *PublicKey)
{
    if (!cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    do {
        if(validate_usage(cert->PubkeyUsage) != STATUS_SUCCESS)
            break;

        if( (cert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
            (cert->PubkeyAlgo == SEVSigAlgoRSASHA384) ) {
            if(validate_rsa_pubkey(cert, PublicKey) != STATUS_SUCCESS)
                break;
        }
        else if( (cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDHSHA384) )
            ;       // Are no invalid values for these cert types
        else
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

/**
 * sev_cert.c -> sev_cert_validate_sig()
 * This function gets called from a loop, and this function has
 * to see which of the signatures this currentSig matches to
 * Inputs Ex) child_cert = PEK. parent_cert = OCA. parent_signing_key = OCA PubKey.
 */
SEV_ERROR_CODE SEVCert::validate_signature(const SEV_CERT *child_cert,
                                          const SEV_CERT *parent_cert,
                                          EVP_PKEY *parent_signing_key)    // Probably PubKey
{
    if (!child_cert || !parent_cert || !parent_signing_key)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    SEV_SIG cert_sig[SEV_CERT_MAX_SIGNATURES] = {child_cert->Sig1, child_cert->Sig2};
    HMACSHA256 sha_digest_256;        // Hash on the cert from Version to PubKey
    HMACSHA512 sha_digest_384;        // Hash on the cert from Version to PubKey

    do{
        // 1. SHA256 hash the cert from Version through Pubkey parameters
        // Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
        uint32_t pub_key_offset = offsetof(SEV_CERT, Sig1Usage);  // 16 + sizeof(SEV_PUBKEY)
        if(!calc_hash_digest(child_cert, parent_cert->PubkeyAlgo, pub_key_offset, &sha_digest_256, &sha_digest_384)) {
            break;
        }

        // 2. Use the Pubkey in sig[i] arg to decrypt the sig in child_cert arg
        // Try both sigs in child_cert, to see if either of them match. In PEK, CEK and OCA can be in any order
        bool found_match = false;
        for (int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++)
        {
            if( (parent_cert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
                (parent_cert->PubkeyAlgo == SEVSigAlgoRSASHA384)) {

                // TODO: THIS CODE IS UNTESTED!!!!!!!!!!!!!!!!!!!!!!!!!!!
                printf("TODO validate_signature segfaults on RSA_verify\n");

                // RSA *rsa = EVP_PKEY_get1_RSA(parent_signing_key);     // Signer's (parent's) public key
                // if (!rsa)
                //     printf("Error parent signing key is bad\n");

                // if(parent_cert->PubkeyAlgo == SEVSigAlgoRSASHA256) {
                //     if( RSA_verify(NID_sha256, sha_digest_256, sizeof(sha_digest_256),
                //                     (uint8_t *)&parent_cert->Sig1.RSA, sizeof(SEV_RSA_SIG), rsa) != 1 )
                //         found_match = true;
                // }
                // else if(parent_cert->PubkeyAlgo == SEVSigAlgoRSASHA384) {
                //         if( RSA_verify(NID_sha384, sha_digest_384, sizeof(sha_digest_384),
                //                     (uint8_t *)&parent_cert->Sig1.RSA, sizeof(SEV_RSA_SIG), rsa) != 1 )
                        found_match = true;
                // }
                // RSA_free(rsa);
                continue;
            }
            else if( (parent_cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                     (parent_cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                     (parent_cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                     (parent_cert->PubkeyAlgo == SEVSigAlgoECDHSHA384)) {      // ecdsa.c -> sign_verify_msg
                ECDSA_SIG *tmp_ecdsa_sig = ECDSA_SIG_new();
                BIGNUM *r_big_num = BN_new();
                BIGNUM *s_big_num = BN_new();

                // Store the x and y components as separate BIGNUM objects. The values in the
                // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
                r_big_num = BN_lebin2bn(cert_sig[i].ECDSA.R, sizeof(SEV_ECDSA_SIG::R), r_big_num);    // LE to BE
                s_big_num = BN_lebin2bn(cert_sig[i].ECDSA.S, sizeof(SEV_ECDSA_SIG::S), s_big_num);

                // Calling ECDSA_SIG_set0() transfers the memory management of the values to
                // the ECDSA_SIG object, and therefore the values that have been passed
                // in should not be freed directly after this function has been called
                if(ECDSA_SIG_set0(tmp_ecdsa_sig, r_big_num, s_big_num) != 1) {
                    BN_free(s_big_num);
                    BN_free(r_big_num);
                    continue;
                }
                if( (parent_cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                    (parent_cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)) {
                    if(ECDSA_do_verify(sha_digest_256, sizeof(sha_digest_256), tmp_ecdsa_sig,
                                    EVP_PKEY_get1_EC_KEY(parent_signing_key)) == 1)
                        found_match = true;
                }
                else if( (parent_cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                         (parent_cert->PubkeyAlgo == SEVSigAlgoECDHSHA384)) {
                    if(ECDSA_do_verify(sha_digest_384, sizeof(sha_digest_384), tmp_ecdsa_sig,
                                EVP_PKEY_get1_EC_KEY(parent_signing_key)) == 1)
                        found_match = true;
                }
                ECDSA_SIG_free(tmp_ecdsa_sig);      // Frees BIGNUMs too
                continue;
            }
            else {       // Bad/unsupported signing key algorithm
                printf("Unexpected algorithm! %x\n", parent_cert->PubkeyAlgo);
                break;
            }
        }
        if(!found_match)
            break;

        // 3. Compare

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

/**
 * sev_cert.c -> sev_cert_validate_body()
 */
SEV_ERROR_CODE SEVCert::validate_body(const SEV_CERT *cert)
{
    if (!cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    do {
        if ( (cert->Version == 0) || (cert->Version > SEV_CERT_MAX_VERSION) )
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

/** Note that this function NEWs/allocates memory for a EC_KEY
 *  that must be freed in the calling function using EC_KEY_free()
 * Inputs: cert is the parent cert
 *         pubKey is the parent's public key
 */
SEV_ERROR_CODE SEVCert::compile_public_key_from_certificate(const SEV_CERT* cert, EVP_PKEY* evp_pub_key)
{
    if(!cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    struct rsa_st *rsa_pub_key = NULL;
    EC_KEY *ec_pub_key = NULL;
    BIGNUM *x_big_num = NULL;
    BIGNUM *y_big_num = NULL;
    BIGNUM *modulus = NULL;
    BIGNUM *pub_exp = NULL;

    do {
        if( (cert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
            (cert->PubkeyAlgo == SEVSigAlgoRSASHA384) ) {
            // TODO: THIS CODE IS UNTESTED!!!!!!!!!!!!!!!!!!!!!!!!!!!
            printf("WARNING: You are using untested code in"
                   "compile_public_key_from_certificate for RSA cert type!\n");
            rsa_pub_key = RSA_new();

            modulus = BN_lebin2bn(cert->Pubkey.RSA.Modulus, sizeof(cert->Pubkey.RSA.Modulus), NULL);  // New's up BigNum
            pub_exp = BN_lebin2bn(cert->Pubkey.RSA.PubExp,  cert->Pubkey.RSA.ModulusSize/8, NULL);
            rsa_pub_key->n = modulus;
            rsa_pub_key->e = pub_exp;

            // Make sure the key is good.
            // TODO: This step fails because, from the openssl doc:
            //       It does not work on RSA public keys that have only
            //       the modulus and public exponent elements populated
            // if (RSA_check_key(rsa_pub_key) != 1)
            //     break;

            // Create a public EVP_PKEY from the public RSA_KEY
            // This function links evp_pub_key to rsa_pub_key, so when evp_pub_key is freed, rsa_pub_key is freed
            // We don't want the user to have to manage 2 keys, so just return EVP_PKEY and make sure user free's it
            // if(EVP_PKEY_assign_RSA(evp_pub_key, rsa_pub_key) != 1)
            //     break;
        }
        else if( (cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDHSHA384) ) {      // ecdsa.c -> sign_verify_msg

            // Store the x and y components as separate BIGNUM objects. The values in the
            // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
            x_big_num = BN_lebin2bn(cert->Pubkey.ECDH.QX, sizeof(cert->Pubkey.ECDH.QX), NULL);  // New's up BigNum
            y_big_num = BN_lebin2bn(cert->Pubkey.ECDH.QY, sizeof(cert->Pubkey.ECDH.QY), NULL);

            int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1

            // Create/allocate memory for an EC_KEY object using the NID above
            if (!(ec_pub_key = EC_KEY_new_by_curve_name(nid)))
                break;
            // Store the x and y coordinates of the public key
            if (EC_KEY_set_public_key_affine_coordinates(ec_pub_key, x_big_num, y_big_num) != 1)
                break;
            // Make sure the key is good
            if (EC_KEY_check_key(ec_pub_key) != 1)
                break;

            // Create a public EVP_PKEY from the public EC_KEY
            // This function links evp_pub_key to ec_pub_key, so when evp_pub_key is freed, ec_pub_key is freed
            // We don't want the user to have to manage 2 keys, so just return EVP_PKEY and make sure user free's it
            if(EVP_PKEY_assign_EC_KEY(evp_pub_key, ec_pub_key) != 1)
                break;
        }

        if (!evp_pub_key)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory if it was allocated
    BN_free(y_big_num);       // If NULL, does nothing
    BN_free(x_big_num);
    BN_free(modulus);
    BN_free(pub_exp);

    return cmd_ret;
}

/**
 * Takes in a signed certificate and validates the signature(s)
 * against the public keys in other certificates.
 * This test assumes parent_cert1 is always valid, and parent_cert2 may be valid
 * sev_cert.c -> sev_cert_validate()
 */
SEV_ERROR_CODE SEVCert::verify_sev_cert(const SEV_CERT *parent_cert1, const SEV_CERT *parent_cert2)
{
    if(!parent_cert1)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    EVP_PKEY *parent_pub_key[SEV_CERT_MAX_SIGNATURES] = {NULL};
    const SEV_CERT *parent_cert[SEV_CERT_MAX_SIGNATURES] = {parent_cert1, parent_cert2};   // A cert has max of x parents/sigs

    do {
        // Get the public key from parent certs
        int numSigs = (parent_cert1 && parent_cert2) ? 2 : 1;   // Run the loop for 1 or 2 signatures
        int i = 0;
        for (i = 0; i < numSigs; i++)
        {
            // New up the EVP_PKEY
            if (!(parent_pub_key[i] = EVP_PKEY_new()))
                break;

            // This function allocates memory and attaches an EC_Key
            //  to your EVP_PKEY so, to prevent mem leaks, make sure
            //  the EVP_PKEY is freed at the end of this function
            if(compile_public_key_from_certificate(parent_cert[i], parent_pub_key[i]) != STATUS_SUCCESS)
                break;

            // Now, we have Parent's PublicKey(s), validate them
            if (validate_public_key(&m_child_cert, parent_pub_key[i]) != STATUS_SUCCESS)
                break;

            // Validate the signature before we do any other checking
            // Sub-function will need a separate loop to find which of the 2 signatures this one matches to
            if(validate_signature(&m_child_cert, parent_cert[i], parent_pub_key[i]) != STATUS_SUCCESS)
                break;
        }
        if(i != numSigs)
            break;

        // Validate the certificate body
        if(validate_body(&m_child_cert) != STATUS_SUCCESS)
            break;

        // Although the signature was valid, ensure that the certificate
        // was signed with the proper key(s) in the correct order
        if(m_child_cert.PubkeyUsage == SEVUsagePDH) {
            // The PDH certificate must be signed by the PEK
            if(parent_cert1->PubkeyUsage != SEVUsagePEK) {
                break;
            }
        }
        else if(m_child_cert.PubkeyUsage == SEVUsagePEK) {
            // The PEK certificate must be signed by the CEK and the OCA
            if( ((parent_cert1->PubkeyUsage != SEVUsageOCA) && (parent_cert2->PubkeyUsage != SEVUsageCEK)) &&
                ((parent_cert2->PubkeyUsage != SEVUsageOCA) && (parent_cert1->PubkeyUsage != SEVUsageCEK)) ) {
                break;
            }
        }
        else if(m_child_cert.PubkeyUsage == SEVUsageOCA) {
            // The OCA certificate must be self-signed
            if(parent_cert1->PubkeyUsage != SEVUsageOCA) {
                break;
            }
        }
        else if(m_child_cert.PubkeyUsage == SEVUsageCEK) {
            // The CEK must be signed by the ASK
            if(parent_cert1->PubkeyUsage != SEVUsageASK) {
                break;
            }
        }
        else
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory
    for(int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
        EVP_PKEY_free(parent_pub_key[i]);
    }

    return cmd_ret;
}
