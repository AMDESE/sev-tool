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
#include <openssl/hmac.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <cstring>                  // memset
#include <fstream>
#include <stdio.h>
#include <stdexcept>

/**
 * Description: This function prints out an SEV_CERT in readable ASCII format
 * Parameters:  [cert] is the source cert which to be printed
 *              [OutStr][optional] if passed in, will be filled up with the
 *               text output, instead of the output being printed to the screen
 *               using std::out
 */
void print_sev_cert_readable(const SEV_CERT *cert, std::string& out_str)
{
    char out[sizeof(SEV_CERT)*3+500];   // 2 chars per byte + 1 spaces + ~500 extra chars for text

    sprintf(out, "%-15s%08x\n", "Version:", cert->Version);                         // uint32_t
    sprintf(out+strlen(out), "%-15s%02x\n", "api_major:", cert->ApiMajor);          // uint8_t
    sprintf(out+strlen(out), "%-15s%02x\n", "api_minor:", cert->ApiMinor);          // uint8_t
    sprintf(out+strlen(out), "%-15s%08x\n", "pub_key_usage:", cert->PubkeyUsage);   // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "pub_key_algo:", cert->PubkeyAlgo);     // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Pubkey:");                                 // SEV_PUBKEY
    for(size_t i = 0; i < (size_t)(sizeof(SEV_PUBKEY)); i++) {  //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Pubkey)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%08x\n", "sig1_usage:", cert->Sig1Usage);        // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "sig1_algo:", cert->Sig1Algo);          // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Sig1:");                                   // SEV_SIG
    for(size_t i = 0; i < (size_t)(sizeof(SEV_SIG)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Sig1)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%08x\n", "Sig2Usage:", cert->Sig2Usage);         // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "Sig2Algo:", cert->Sig2Algo);           // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Sig2:");                                   // SEV_SIG
    for(size_t i = 0; i < (size_t)(sizeof(SEV_SIG)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->Sig2)[i] );
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
 * Description: Prints the contents of an SEV_CERT as hex bytes to the screen
 * Notes:       To print this to a file, just use write_file() directly
 * Parameters:  [cert] is the source cert which to be printed
 */
void print_sev_cert_hex(const SEV_CERT *cert)
{
    printf("Printing cert as hex...\n");
    for(size_t i = 0; i < (size_t)(sizeof(SEV_CERT)); i++) { // bytes to uint8
        printf( "%02X ", ((uint8_t *)cert)[i] );
    }
    printf("\n");
}

/**
 * Description: Prints out the cert chain (PDK, OCA, and CEK) in a readable format
 * Parameters:  [p] is the source cert chain buf to be printed
 *              [OutStr][optional] if passed in, will be filled up with the
 *               text output, instead of the output being printed to the screen
 *               using std::out
 */
void print_cert_chain_buf_readable(const SEV_CERT_CHAIN_BUF *p, std::string& out_str)
{
    char out_pek[50];    // Just big enough for string below
    char out_oca[50];
    char out_cek[50];

    std::string out_str_local = "";

    sprintf(out_pek, "PEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    out_str_local += out_pek;
    print_sev_cert_readable(((SEV_CERT *)PEKinCertChain(p)), out_str_local);

    sprintf(out_oca, "\nOCA Memory: %ld bytes\n", sizeof(SEV_CERT));
    out_str_local += out_oca;
    print_sev_cert_readable(((SEV_CERT *)OCAinCertChain(p)), out_str_local);

    sprintf(out_cek, "\nCEK Memory: %ld bytes\n", sizeof(SEV_CERT));
    out_str_local += out_cek;
    print_sev_cert_readable(((SEV_CERT *)CEKinCertChain(p)), out_str_local);

    if(out_str == "NULL") {
        printf("%s\n", out_str_local.c_str());
    }
    else {
        out_str = out_str_local;
    }
}

/**
 * Description: Prints out the cert chain (PDK, OCA, and CEK) to the screen as
 *              hex bytes
 * Notes:       Put the following line at the end of test PEKGen01 to see the chain
 *              CertChainMem1.PrintCertChainBufHex();
 * Parameters:  [p] is the source cert chain buf to be printed
 */
void print_cert_chain_buf_hex(const SEV_CERT_CHAIN_BUF *p)
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

/**
 * Description:   Reads in a private key pem file and write it to a RSA key
 * Notes:         This function allocates a new RSA key which must be
 *                freed by the calling function
 * Parameters:    [rsa_priv_key] RSA key where the private key gets stored
 */
void read_priv_key_pem_into_rsakey(const std::string& file_name, RSA **rsa_priv_key)
{
    do {
        // New up the EC_KEY with the EC_GROUP
        if(!(*rsa_priv_key = RSA_new()))
            break;

        // Read in the private key file into RSA
        FILE *pFile = fopen(file_name.c_str(), "r");
        if(!pFile)
            break;
        *rsa_priv_key = PEM_read_RSAPrivateKey(pFile, NULL, NULL, NULL);
        fclose(pFile);
        if(!rsa_priv_key)
            break;
    } while (0);
}

/**
 * Description:   Reads in a private key pem file and write it to a EC_KEY
 * Notes:         This function allocates a new EC PrivateKey which must be
 *                freed by the calling function
 * Typical Usage: Usually used to read in OCA or GODH private key
 * Parameters:    [ec_priv_key] EC_KEY where the private key gets stored
 */
void read_priv_key_pem_into_eckey(const std::string& file_name, EC_KEY **ec_priv_key)
{
    do {
        // New up the EC_KEY with the EC_GROUP
        int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
        *ec_priv_key = EC_KEY_new_by_curve_name(nid);

        // Read in the private key file into EVP_PKEY
        FILE *pFile = fopen(file_name.c_str(), "r");
        if(!pFile)
            break;
        *ec_priv_key = PEM_read_ECPrivateKey(pFile, NULL, NULL, NULL);
        fclose(pFile);
        if(!ec_priv_key)
            break;
    } while (0);
}

/**
 * Description:   Calls read_privkey_pem_into_eckey and converts EC key to EVP key
 * Notes:         This function allocates a new EVP key which will free the
 *                associated EC key and the EVP key must be freed by the calling
 *                function
 * Parameters:    [file_name] file of the PEM file to read in
 *                [evp_priv_key] Output EVP key
 */
bool read_priv_key_pem_into_evpkey(const std::string file_name, EVP_PKEY **evp_priv_key)
{
    EC_KEY *ec_privkey = NULL;

    // New up the EVP_PKEY
    if (!(*evp_priv_key = EVP_PKEY_new()))
        return false;

    // Read in the file as an EC key
    read_priv_key_pem_into_eckey(file_name, &ec_privkey);

    // Convert EC key to EVP_PKEY
    // This function links EVP_pubKey to EC_pubKey, so when EVP_pubKey
    //  is freed, EC_pubKey is freed. We don't want the user to have to
    //  manage 2 keys, so just return EVP_PKEY and make sure user free's it
    if(EVP_PKEY_assign_EC_KEY(*evp_priv_key, ec_privkey) != 1)
        return false;

    return true;
}

/**
 * Description: Writes the public key of an EVP_PKEY to a PEM file
 * Parameters:  [file_name] the full path of the file to write
 *              [evp_key_pair] the key which ti pull the public key from
 */
bool write_pub_key_pem(const std::string& file_name, EVP_PKEY *evp_key_pair)
{
    FILE *pFile = NULL;
    pFile = fopen(file_name.c_str(), "wt");
    if(!pFile)
        return false;

    // printf("Writing to file: %s\n", file_name.c_str());
    if(PEM_write_PUBKEY(pFile, evp_key_pair) != 1) {
        printf("Error writing pubkey to file: %s\n", file_name.c_str());
        return false;
    }
    fclose(pFile);
    return true;
}

/**
 * Description: Writes the private key of an EVP_PKEY to a PEM file with no
 *              encryption
 * Parameters:  [file_name] the full path of the file to write
 *              [evp_key_pair] the key which ti pull the public key from
 */
bool write_priv_key_pem(const std::string& file_name, EVP_PKEY *evp_key_pair)
{
    FILE *pFile = NULL;
    pFile = fopen(file_name.c_str(), "wt");
    if(!pFile)
        return false;

    // printf("Writing to file: %s\n", file_name.c_str());
    if(PEM_write_PrivateKey(pFile, evp_key_pair, NULL, NULL, 0, NULL, 0) != 1) {
        printf("Error writing privkey to file: %s\n", file_name.c_str());
        return false;
    }
    fclose(pFile);
    return true;
}

/**
 * Description:   Generates a new P-384 key pair
 * Typical Usage: Used to create a new Guest Owner DH
 *                (Elliptic Curve Diffie Hellman (ECDH)) P-384 key pair
 * Parameters:    [evp_key_pair] the output EVP_PKEY to which the key pair gets
 *                set
 * Note:          This key must be initialized (with EVP_PKEY_new())
 *                before passing in
 */
bool SEVCert::generate_ecdh_key_pair(EVP_PKEY **evp_key_pair)
{
    if(!evp_key_pair)
        return false;

    bool ret = false;
    EC_KEY *ec_key_pair = NULL;

    do {
        // New up the Guest Owner's private EVP_PKEY
        if (!(*evp_key_pair = EVP_PKEY_new()))
            break;

        // New up the EC_KEY with the EC_GROUP
        int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
        ec_key_pair = EC_KEY_new_by_curve_name(nid);

        // Create the new public/private EC key pair. EC_key must have a group
        // associated with it before calling this function
        if(EC_KEY_generate_key(ec_key_pair) != 1)
            break;

        // Convert EC key to EVP_PKEY
        // This function links evp_key_pair to ec_key_pair, so when evp_key_pair is
        //  freed, ec_key_pair is freed. We don't want the user to have to manage 2
        //  keys, so just return EVP_PKEY and make sure user free's it
        if(EVP_PKEY_assign_EC_KEY(*evp_key_pair, ec_key_pair) != 1)
            break;

        if (!evp_key_pair)
            break;

        ret = true;
    } while (0);

    return ret;
}

/**
 * Description:   Populates an empty SEV_CERT using an existing ECDH keypair
 * Typical Usage: Used to generate the Guest Owner Diffie-Hellman cert used in
 *                LaunchStart
 * Parameters:    [api_major] the api_major returned from a PlatformStatus command
 *                  as input to this function, to help populate the cert
 *                [api_minor] the api_minor returned from a PlatformStatus command
 *                  as input to this function, to help populate the cert
 */
bool SEVCert::create_godh_cert(EVP_PKEY **godh_key_pair, uint8_t api_major, uint8_t api_minor)
{
    bool cmd_ret = false;

    if(!godh_key_pair)
        return false;

    do {
        memset(&m_child_cert, 0, sizeof(SEV_CERT));

        m_child_cert.Version = SEV_CERT_MAX_VERSION;
        m_child_cert.ApiMajor = api_major;
        m_child_cert.ApiMinor = api_minor;
        m_child_cert.PubkeyUsage = SEVUsagePDH;
        m_child_cert.PubkeyAlgo = SEVSigAlgoECDHSHA256;
        m_child_cert.Sig1Usage = SEVUsagePEK;
        m_child_cert.Sig1Algo = SEVSigAlgoECDSASHA256;
        m_child_cert.Sig2Usage = SEVUsageInvalid;
        m_child_cert.Sig2Algo = SEVSigAlgoInvalid;

        // Set the pubkey portion of the cert
        if(decompile_public_key_into_certificate(&m_child_cert, *godh_key_pair) != STATUS_SUCCESS)
            break;

        // Set the rest of the params and sign the signature with the newly
        // generated GODH privkey
        // Technically this step is not necessary, as the firmware doesn't
        // validate the GODH signature
        if(!sign_with_key(SEV_CERT_MAX_VERSION, SEVUsagePDH, SEVSigAlgoECDHSHA256,
                        godh_key_pair, SEVUsagePEK, SEVSigAlgoECDSASHA256))
            break;

        cmd_ret = true;
    } while (0);

    return cmd_ret;
}

/**
 * Description:   Populates an empty SEV_CERT using an existing ECDH keypair
 * Typical Usage: Used to generate the Guest Owner Diffie-Hellman cert used in
 *                LaunchStart
 * Parameters:    [api_major] the api_major returned from a PlatformStatus command
 *                  as input to this function, to help populate the cert
 *                [api_minor] the api_minor returned from a PlatformStatus command
 *                  as input to this function, to help populate the cert
 */
bool SEVCert::create_oca_cert(EVP_PKEY **oca_key_pair, uint8_t api_major, uint8_t api_minor)
{
    bool cmd_ret = false;

    if(!oca_key_pair)
        return false;

    do {
        memset(&m_child_cert, 0, sizeof(SEV_CERT));

        m_child_cert.Version = SEV_CERT_MAX_VERSION;
        m_child_cert.ApiMajor = api_major;
        m_child_cert.ApiMinor = api_minor;
        m_child_cert.PubkeyUsage = SEVUsageOCA;
        m_child_cert.PubkeyAlgo = SEVSigAlgoECDSASHA256;
        m_child_cert.Sig1Usage = SEVUsageOCA;
        m_child_cert.Sig1Algo = SEVSigAlgoECDSASHA256;
        m_child_cert.Sig2Usage = SEVUsageInvalid;
        m_child_cert.Sig2Algo = SEVSigAlgoInvalid;

        // Set the pubkey portion of the cert
        if(decompile_public_key_into_certificate(&m_child_cert, *oca_key_pair) != STATUS_SUCCESS)
            break;

        // Set the rest of the params and sign the signature with the newly
        // generated GODH privkey
        // Technically this step is not necessary, as the firmware doesn't
        // validate the GODH signature
        if(!sign_with_key(SEV_CERT_MAX_VERSION, SEVUsageOCA, SEVSigAlgoECDSASHA256,
                        oca_key_pair, SEVUsageOCA, SEVSigAlgoECDSASHA256))
            break;

        cmd_ret = true;
    } while (0);

    return cmd_ret;
}

/**
 * Description: Calculates a hash digest (using SHA256 of SHA384) of the input cert
 * Parameters:  [Cert] is the input SEV_CERT which to be hashed
 *              [PubkeyAlgo] used to determine the algorithm type (RSA/ECDSA/ECDH)
 *               and whether to use SHA256 or SHA384
 *              [PubKeyOffset] number of bytes to be hashed, from the top of the
 *               SEV_CERT until the first signature. Version through and including Pubkey
 *              [sha_digest_256] the output digest, if using SHA256
 *              [sha_digest_384] the output digest, if using SHA384
 */
bool SEVCert::calc_hash_digest(const SEV_CERT *cert, uint32_t pub_key_algo, uint32_t pub_key_offset,
                             HMACSHA256 *sha_digest_256, HMACSHA512 *sha_digest_384)
{
    bool ret = false;
    SHA256_CTX ctx_256;
    SHA512_CTX ctx_384;              // size is the same for 384 and 512

    // SHA256/SHA384 hash the Cert from Version through Pubkey parameters
    // Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
    do {
        if( (pub_key_algo == SEVSigAlgoRSASHA256) ||
            (pub_key_algo == SEVSigAlgoECDSASHA256)) {
            if (SHA256_Init(&ctx_256) != 1)
                break;
            if (SHA256_Update(&ctx_256, cert, pub_key_offset) != 1)
                break;
            if (SHA256_Final((uint8_t *)sha_digest_256, &ctx_256) != 1)  // size = 32
                break;
        }
        else if( (pub_key_algo == SEVSigAlgoRSASHA384) ||
                 (pub_key_algo == SEVSigAlgoECDSASHA384)) {
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
 * Description: This function sets the many params of a cert (the child cert of
 *              the object used to call the this function) and then signs the
 *              cert with the private key provided. Note: Before calling this
 *              function, be sure to manually set the other parameters which
 *              this function does not specifically set, such as ApiMajor,
 *              ApiMajor, and Pubkey, so they get included in the signature
 * Notes:       - sev_cert.c -> sev_cert_create() (kinda)
 *              - Signs the PEK's sig1 with the OCA (private key)
 *              The firmware signs sig2 with the CEK during PEK_CERT_IMPORT
 * Parameters:  [Version][PubKeyUsage][PubKeyAlgorithm] are for the child cert (PEK)
 *              [priv_evp_key][Sig1Usage][Sig1Algo] are for the parent cert (OCA)
 *
 * To optimize this function, can make the PEM read code RSA, EC, or general EVP.
 * The issue is that if it reads it into a common-format EVP_PKEY, how to we get that
 * private key into the EC_KEY or RSA_KEY that we are doing the signing on.
 * Also, to make the EC_KEY validate, I only figured out how to create the EC_KEY with
 * a GROUP as the input parm, not new up the EC_KEY then assign it a GROUP and all other
 * params later (don't know what other params it needed to validate correctly)
 */
bool SEVCert::sign_with_key(uint32_t Version, uint32_t pub_key_usage, uint32_t pub_key_algorithm,
                            EVP_PKEY **priv_evp_key, uint32_t sig1_usage, uint32_t sig1_algo)
{
    bool isValid = false;
    HMACSHA256 sha_digest_256;           // Hash on the cert from Version to PubKey
    HMACSHA512 sha_digest_384;           // Hash on the cert from Version to PubKey
    EC_KEY *priv_ec_key = NULL;
    RSA *priv_rsa_key = NULL;
    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    do {
        // Sign the certificate    sev_cert.c -> sev_cert_sign()
        // The constructor defaults all member vars, and the user can change them
        memset(&m_child_cert.Sig1, 0, sizeof(SEV_CERT::Sig1));
        m_child_cert.Version = Version;
        m_child_cert.PubkeyUsage = pub_key_usage;
        m_child_cert.PubkeyAlgo = pub_key_algorithm;

        m_child_cert.Sig1Usage = sig1_usage;       // Parent cert's sig
        m_child_cert.Sig1Algo = sig1_algo;

        // SHA256/SHA384 hash the Cert from the [Version:Pubkey] params
        uint32_t pub_key_offset = offsetof(SEV_CERT, Sig1Usage);  // 16 + sizeof(SEV_PUBKEY)
        if(!calc_hash_digest(&m_child_cert, sig1_algo, pub_key_offset, &sha_digest_256, &sha_digest_384))
            break;

        if( (sig1_algo == SEVSigAlgoRSASHA256) ||
            (sig1_algo == SEVSigAlgoRSASHA384)) {
            printf("Error: RSA signing untested!");
            // This code probably does not work!

            // Allocates a new RSA private key which is freed at the bottom of this function
            priv_rsa_key = RSA_new();
            priv_rsa_key = EVP_PKEY_get1_RSA(*priv_evp_key);
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
                 (sig1_algo == SEVSigAlgoECDSASHA384)) {
            int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
            priv_ec_key = EC_KEY_new_by_curve_name(nid);

            priv_ec_key = EVP_PKEY_get1_EC_KEY(*priv_evp_key);
            if(!priv_ec_key)
                break;

            if(sig1_algo == SEVSigAlgoECDSASHA256) {
                ECDSA_SIG *sig = ECDSA_do_sign(sha_digest_256, sizeof(sha_digest_256), priv_ec_key); // Contains 2 bignums
                if(!sig)
                    break;

                ECDSA_SIG_get0(sig, &r, &s);
                BN_bn2lebinpad(r, m_child_cert.Sig1.ECDSA.R, sizeof(SEV_ECDSA_SIG::R));    // LE to BE
                BN_bn2lebinpad(s, m_child_cert.Sig1.ECDSA.S, sizeof(SEV_ECDSA_SIG::S));

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

                ECDSA_SIG_get0(sig, &r, &s);
                BN_bn2lebinpad(r, m_child_cert.Sig1.ECDSA.R, sizeof(SEV_ECDSA_SIG::R));    // LE to BE
                BN_bn2lebinpad(s, m_child_cert.Sig1.ECDSA.S, sizeof(SEV_ECDSA_SIG::S));

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
 * Description: Validates the usage parameter of an SEV_CERT
 * Notes:       sev_cert.c  -> usage_is_valid()
 * Parameters:  [Usage] is the input value to be validated
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
 * Description: Gets called from ValidatePublicKey as a subfunction to do the
 *              work of actually validating an RSA public key
 * Notes:       rsa.c -> rsa_pubkey_is_valid()
 * Parameters:  [Cert] the input SEV_CERT which to validate the public key of
 *              [PublicKey] currently unused
 *
 * This function is untested because we don't have any RSA SEV_CERTs to test
 */
SEV_ERROR_CODE SEVCert::validate_rsa_pub_key(const SEV_CERT *cert, const EVP_PKEY *PublicKey)
{
    if (!cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    if (cert->Pubkey.RSA.ModulusSize <= SEV_RSA_PUB_KEY_MAX_BITS)    // bits
        cmd_ret = STATUS_SUCCESS;

    return cmd_ret;
}

/**
 * Description: The generic function to validate the public key of an SEV_CERT.
 *              Calls ValidateRSAPubkey to actually do the work for an RSA pubkey
 * Notes:       rsa.c -> pubkey_is_valid()
 * Parameters:  [Cert] is the child cert
 *              [PublicKey] is the parent's public key
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
            if(validate_rsa_pub_key(cert, PublicKey) != STATUS_SUCCESS)
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
 * Description:
 * Notes:       sev_cert.c -> sev_cert_validate_sig()
 *              This function gets called from a loop, and this function has
 *              to see which of the signatures this currentSig matches to
 * Parameters:  [ChildCert] the cert which we want to validate the signature of.
 *               This is the cert that gets hashed and validated
 *              [ParentCert] tells us the algo used to sign the child cert
 *              [ParentSigningKey] used to validate the hash of the child cert
 *              Ex) ChildCert = PEK. ParentCert = OCA. ParentSigningKey = OCA PubKey
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
        // 1. SHA256 hash the Cert from Version through Pubkey parameters
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

                RSA *rsa = EVP_PKEY_get1_RSA(parent_signing_key);     // Signer's (parent's) public key
                if (!rsa) {
                    printf("Error parent signing key is bad\n");
                    break;
                }

                uint32_t sigLen = sizeof(parent_cert->Sig1.RSA);
                if(parent_cert->PubkeyAlgo == SEVSigAlgoRSASHA256) {
                    if( RSA_verify(NID_sha256, sha_digest_256, sizeof(sha_digest_256), (uint8_t *)&parent_cert->Sig1.RSA, sigLen, rsa) != 1 )
                        break;
                }
                else if(parent_cert->PubkeyAlgo == SEVSigAlgoRSASHA384) {
                    if( RSA_verify(NID_sha384, sha_digest_384, sizeof(sha_digest_384), (uint8_t *)&parent_cert->Sig1.RSA, sigLen, rsa) != 1 )
                        break;
                }
                found_match = true;
                RSA_free(rsa);
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
 * Description: Validates the body (version through and including reserved1) of
 *              an SEV_CERT. Separate functions are used to validate the pubkey
 *              and the sigs
 * Notes:       sev_cert.c -> sev_cert_validate_body()
 * Parameters:  [Cert] the SEV_CERT which to validate the body of
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

/**
 * Description: When a .cert file is imported, the PubKey is in SEV_CERT
 *              format. This function converts that format into a EVP_PKEY
 *              format where it can be used by other openssl functions.
 * Note:        This function NEWs/allocates memory for a EC_KEY that must be
 *              freed in the calling function using EC_KEY_free()
 * Parameters:  [Cert] is the source SEV_CERT containing the public key we want
 *               to extract
 *              [evp_pubkey] is the destination EVP_PKEY where the extracted
 *               public key will go into
 */
SEV_ERROR_CODE SEVCert::compile_public_key_from_certificate(const SEV_CERT *cert, EVP_PKEY *evp_pub_key)
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
            pub_exp = BN_lebin2bn(cert->Pubkey.RSA.PubExp,  sizeof(cert->Pubkey.RSA.PubExp), NULL);
            RSA_set0_key(rsa_pub_key, modulus, pub_exp, NULL);

            // Make sure the key is good.
            // TODO: This step fails because, from the openssl doc:
            //       It does not work on RSA public keys that have only
            //       the modulus and public exponent elements populated
            // if (RSA_check_key(rsa_pub_key) != 1)
            //     break;

            // Create a public EVP_PKEY from the public RSA_KEY
            // This function links evp_pub_key to rsa_pub_key, so when evp_pub_key
            //  is freed, rsa_pub_key is freed. We don't want the user to have to
            //  manage 2 keys, so just return EVP_PKEY and make sure user free's it
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
            // This function links evp_pub_key to ec_pub_key, so when evp_pub_key
            //  is freed, ec_pub_key is freed. We don't want the user to have to
            //  manage 2 keys, so just return EVP_PKEY and make sure user free's it
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
 * Description: This function is the reverse of CompilePublicKeyFromCertificate,
 *              in that is takes an EVP_PKEY and converts it to SEV_CERT format
 * Note:        This function NEWs/allocates memory for a EC_KEY that must be
 *              freed in the calling function using EC_KEY_free()
 * Parameters:  [cert] is the output cert which the public key gets written to
 *              [evp_pubkey] is the input public key
 */
SEV_ERROR_CODE SEVCert::decompile_public_key_into_certificate(SEV_CERT *cert, EVP_PKEY *evp_pubkey)
{
    if(!cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    EC_KEY *ec_pubkey = NULL;
    BIGNUM *x_bignum = NULL;
    BIGNUM *y_bignum = NULL;
    BIGNUM *modulus = NULL;
    BIGNUM *pub_exp = NULL;

    do {
        if( (cert->PubkeyAlgo == SEVSigAlgoRSASHA256) ||
            (cert->PubkeyAlgo == SEVSigAlgoRSASHA384) ) {
            // TODO: THIS CODE IS UNTESTED!!!!!!!!!!!!!!!!!!!!!!!!!!!
            printf("WARNING: You are using untested code in" \
                   "decompile_public_key_into_certificate for RSA cert type!\n");
        }
        else if( (cert->PubkeyAlgo == SEVSigAlgoECDSASHA256) ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDSASHA384) ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDHSHA256)  ||
                 (cert->PubkeyAlgo == SEVSigAlgoECDHSHA384) ) {      // ecdsa.c -> sign_verify_msg

            int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
            EC_GROUP *ec_group = EC_GROUP_new_by_curve_name(nid);

            // Set the curve parameter of the cert's pubkey
            cert->Pubkey.ECDH.Curve = SEVECP384;

            // Create/allocate memory for an EC_KEY object using the NID above
            if (!(ec_pubkey = EC_KEY_new_by_curve_name(nid)))
                break;

            // Pull the EC_KEY from the EVP_PKEY
            ec_pubkey = EVP_PKEY_get1_EC_KEY(evp_pubkey);

            // Make sure the key is good
            if (EC_KEY_check_key(ec_pubkey) != 1)
                break;

            // Get the EC_POINT from the public key
            const EC_POINT *pub = EC_KEY_get0_public_key(ec_pubkey);

            // New up the BIGNUMs
            BIGNUM *x_bignum = BN_new();
            BIGNUM *y_bignum = BN_new();

            // Get the x and y coordinates from the EC_POINT and store as separate BIGNUM objects
            if(!EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x_bignum, y_bignum, NULL))
                break;

            // Store the x and y components into the cert. The values in the
            // BIGNUM are stored as big-endian, so must reverse bytes before
            // storing in SEV certificate as little-endian
            if(BN_bn2lebinpad(x_bignum, (unsigned char *)cert->Pubkey.ECDH.QX, sizeof(cert->Pubkey.ECDH.QX)) <= 0)
                break;
            if(BN_bn2lebinpad(y_bignum, (unsigned char *)cert->Pubkey.ECDH.QY, sizeof(cert->Pubkey.ECDH.QY)) <= 0)
                break;
        }

        if (!evp_pubkey)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory if it was allocated
    BN_free(y_bignum);       // If NULL, does nothing
    BN_free(x_bignum);
    BN_free(modulus);
    BN_free(pub_exp);

    return cmd_ret;
}

/**
 * Description: Takes in a signed certificate and validates the signature(s)
 *              against the public keys in other certificates
 * Notes:       This test assumes ParentCert1 is always valid, and ParentCert2
 *              may be valid
 *              sev_cert.c -> sev_cert_validate()
 * Parameters:  [ParentCert1][ParentCert2] these are used to validate the 1 or 2
 *              signatures in the child cert (passed into the class constructor)
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
