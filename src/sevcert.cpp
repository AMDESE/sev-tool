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
#include "utilities.h"
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <cstring>      // memset
#include <fstream>
#include <stdio.h>
#include <stdexcept>

/**
 * Description: This function prints out an sev_cert in readable ASCII format
 * Parameters:  [cert] is the source cert which to be printed
 *              [out_str][optional] if passed in, will be filled up with the
 *               text output, instead of the output being printed to the screen
 *               using std::out
 */
void print_sev_cert_readable(const sev_cert *cert, std::string &out_str)
{
    char out[sizeof(sev_cert)*3+500];   // 2 chars per byte + 1 spaces + ~500 extra chars for text

    sprintf(out, "%-15s%08x\n", "Version:", cert->version);                         // uint32_t
    sprintf(out+strlen(out), "%-15s%02x\n", "api_major:", cert->api_major);         // uint8_t
    sprintf(out+strlen(out), "%-15s%02x\n", "api_minor:", cert->api_minor);         // uint8_t
    sprintf(out+strlen(out), "%-15s%08x\n", "pub_key_usage:", cert->pub_key_usage); // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "pub_key_algo:", cert->pub_key_algo);   // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "pub_key:");                                 // sev_pubkey
    for (size_t i = 0; i < (size_t)(sizeof(sev_pubkey)); i++) {  //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->pub_key)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%08x\n", "sig_1_usage:", cert->sig_1_usage);     // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "sig_1_algo:", cert->sig_1_algo);       // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "sig_1:");                                   // sev_sig
    for (size_t i = 0; i < (size_t)(sizeof(sev_sig)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->sig_1)[i] );
    }
    sprintf(out+strlen(out), "\n");
    sprintf(out+strlen(out), "%-15s%08x\n", "sig_2_usage:", cert->sig_2_usage);     // uint32_t
    sprintf(out+strlen(out), "%-15s%08x\n", "sig_2_algo:", cert->sig_2_algo);       // uint32_t
    sprintf(out+strlen(out), "%-15s\n", "Sig2:");                                   // sev_sig
    for (size_t i = 0; i < (size_t)(sizeof(sev_sig)); i++) {     //bytes to uint8
        sprintf(out+strlen(out), "%02X ", ((uint8_t *)&cert->sig_2)[i] );
    }
    sprintf(out+strlen(out), "\n");

    if (out_str == "NULL") {
        printf("%s\n", out);
    }
    else {
        out_str += out;
    }
}

/**
 * Description: Prints the contents of an sev_cert as hex bytes to the screen
 * Notes:       To print this to a file, just use write_file() directly
 * Parameters:  [cert] is the source cert which to be printed
 */
void print_sev_cert_hex(const sev_cert *cert)
{
    printf("Printing cert as hex...\n");
    for (size_t i = 0; i < (size_t)(sizeof(sev_cert)); i++) { // bytes to uint8
        printf( "%02X ", ((uint8_t *)cert)[i] );
    }
    printf("\n");
}

/**
 * Description: Prints out the cert chain (PDK, OCA, and CEK) in a readable format
 * Parameters:  [p] is the source cert chain buf to be printed
 *              [out_str][optional] if passed in, will be filled up with the
 *               text output, instead of the output being printed to the screen
 *               using std::out
 */
void print_cert_chain_buf_readable(const sev_cert_chain_buf *p, std::string &out_str)
{
    char out_pek[50];    // Just big enough for string below
    char out_oca[50];
    char out_cek[50];

    std::string out_str_local = "";

    sprintf(out_pek, "PEK Memory: %ld bytes\n", sizeof(sev_cert));
    out_str_local += out_pek;
    print_sev_cert_readable(((sev_cert *)PEK_IN_CERT_CHAIN(p)), out_str_local);

    sprintf(out_oca, "\nOCA Memory: %ld bytes\n", sizeof(sev_cert));
    out_str_local += out_oca;
    print_sev_cert_readable(((sev_cert *)OCA_IN_CERT_CHAIN(p)), out_str_local);

    sprintf(out_cek, "\nCEK Memory: %ld bytes\n", sizeof(sev_cert));
    out_str_local += out_cek;
    print_sev_cert_readable(((sev_cert *)CEK_IN_CERT_CHAIN(p)), out_str_local);

    if (out_str == "NULL") {
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
void print_cert_chain_buf_hex(const sev_cert_chain_buf *p)
{
    printf("PEK Memory: %ld bytes\n", sizeof(sev_cert));
    for (size_t i = 0; i < (size_t)(sizeof(sev_cert)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)PEK_IN_CERT_CHAIN(p))[i] );
    }
    printf("\nOCA Memory: %ld bytes\n", sizeof(sev_cert));
    for (size_t i = 0; i < (size_t)(sizeof(sev_cert)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)OCA_IN_CERT_CHAIN(p))[i] );
    }
    printf("\nCEK Memory: %ld bytes\n", sizeof(sev_cert));
    for (size_t i = 0; i < (size_t)(sizeof(sev_cert)); i++) { //bytes to uint8
        printf( "%02X ", ((uint8_t *)CEK_IN_CERT_CHAIN(p))[i] );
    }
    printf("\n");
}

/**
 * Description:   Reads in a private key pem file and write it to a RSA key
 * Notes:         This function allocates a new RSA key which must be
 *                freed by the calling function
 * Parameters:    [file_name] The name of the pem file being read from
 *                [rsa_priv_key] RSA key where the private key gets stored
 */
void read_priv_key_pem_into_rsakey(const std::string file_name, RSA **rsa_priv_key)
{
    do {
        // New up the EC_KEY with the EC_GROUP
        if (!(*rsa_priv_key = RSA_new()))
            break;

        // Read in the private key file into RSA
        FILE *pFile = fopen(file_name.c_str(), "r");
        if (!pFile)
            break;
        *rsa_priv_key = PEM_read_RSAPrivateKey(pFile, NULL, NULL, NULL);
        fclose(pFile);

        if (!rsa_priv_key)   // TODO find a better check
            break;
    } while (0);
}

/**
 * Description:   Reads in a private key pem file and write it to a EC_KEY
 * Notes:         This function allocates a new EC PrivateKey which must be
 *                freed by the calling function
 * Typical Usage: Usually used to read in OCA or GODH private key
 * Parameters:    [file_name] The name of the pem file being read from
 *                [ec_priv_key] EC_KEY where the private key gets stored
 */
bool read_priv_key_pem_into_eckey(const std::string file_name, EC_KEY **ec_priv_key)
{
    bool success = false;

    do {
        // New up the EC_KEY with the EC_GROUP
        int nid = EC_curve_nist2nid("P-384");   // NID_secp384r1
        *ec_priv_key = EC_KEY_new_by_curve_name(nid);

        // Read in the private key file into EVP_PKEY
        FILE *pFile = fopen(file_name.c_str(), "r");
        if (!pFile)
            break;
        *ec_priv_key = PEM_read_ECPrivateKey(pFile, NULL, NULL, NULL);
        fclose(pFile);

        // Make sure the key is good
        if (EC_KEY_check_key(*ec_priv_key) != 1)
            break;

        success = true;
    } while (0);

    return success;
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
    if (!read_priv_key_pem_into_eckey(file_name, &ec_privkey))
        return false;

    /*
     * Convert EC key to EVP_PKEY
     * This function links EVP_pubKey to EC_pubKey, so when EVP_pubKey
     *  is freed, EC_pubKey is freed. We don't want the user to have to
     *  manage 2 keys, so just return EVP_PKEY and make sure user free's it
     */
    if (EVP_PKEY_assign_EC_KEY(*evp_priv_key, ec_privkey) != 1)
        return false;

    return true;
}

/**
 * Description: Writes the public key of an EVP_PKEY to a PEM file
 * Parameters:  [file_name] the full path of the file to write
 *              [evp_key_pair] the key which ti pull the public key from
 */
bool write_pub_key_pem(const std::string file_name, EVP_PKEY *evp_key_pair)
{
    FILE *pFile = NULL;
    pFile = fopen(file_name.c_str(), "wt");
    if (!pFile)
        return false;

    // printf("Writing to file: %s\n", file_name.c_str());
    if (PEM_write_PUBKEY(pFile, evp_key_pair) != 1) {
        printf("Error writing pubkey to file: %s\n", file_name.c_str());
        fclose(pFile);
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
bool write_priv_key_pem(const std::string file_name, EVP_PKEY *evp_key_pair)
{
    FILE *pFile = NULL;
    pFile = fopen(file_name.c_str(), "wt");
    if (!pFile)
        return false;

    // printf("Writing to file: %s\n", file_name.c_str());
    if (PEM_write_PrivateKey(pFile, evp_key_pair, NULL, NULL, 0, NULL, 0) != 1) {
        printf("Error writing privkey to file: %s\n", file_name.c_str());
        fclose(pFile);
        return false;
    }
    fclose(pFile);
    return true;
}

/**
 * Description:   Populates an empty sev_cert using an existing ecdh keypair
 * Typical Usage: Used to generate the Guest Owner Diffie-Hellman cert used in
 *                LaunchStart
 * Parameters:    [godh_key_pair] the input pub/priv key pair used to populate
 *                  and sign the cert
 *                [api_major] the api_major returned from a PlatformStatus
 *                  command as input to this function, to help populate the cert
 *                [api_minor] the api_minor returned from a PlatformStatus
 *                  command as input to this function, to help populate the cert
 */
bool SEVCert::create_godh_cert(EVP_PKEY **godh_key_pair, uint8_t api_major,
                               uint8_t api_minor)
{
    bool cmd_ret = false;

    if (!godh_key_pair)
        return false;

    do {
        memset(m_child_cert, 0, sizeof(sev_cert));

        m_child_cert->version = SEV_CERT_MAX_VERSION;
        m_child_cert->api_major = api_major;
        m_child_cert->api_minor = api_minor;
        m_child_cert->pub_key_usage = SEV_USAGE_PDH;
        m_child_cert->pub_key_algo = SEV_SIG_ALGO_ECDH_SHA256;
        m_child_cert->sig_1_usage = SEV_USAGE_PEK;
        m_child_cert->sig_1_algo = SEV_SIG_ALGO_ECDSA_SHA256;
        m_child_cert->sig_2_usage = SEV_USAGE_INVALID;
        m_child_cert->sig_2_algo = SEV_SIG_ALGO_INVALID;

        // Set the pubkey portion of the cert
        if (decompile_public_key_into_certificate(m_child_cert, *godh_key_pair) != STATUS_SUCCESS)
            break;

        /*
         * Set the rest of the params and sign the signature with the newly
         * generated GODH privkey
         * Technically this step is not necessary, as the firmware doesn't
         * validate the GODH signature
         */
        if (!sign_with_key(SEV_CERT_MAX_VERSION, SEV_USAGE_PDH, SEV_SIG_ALGO_ECDH_SHA256,
                           godh_key_pair, SEV_USAGE_PEK, SEV_SIG_ALGO_ECDSA_SHA256))
            break;

        cmd_ret = true;
    } while (0);

    return cmd_ret;
}

/**
 * Description:   Populates an empty sev_cert using an existing ECDH keypair
 * Typical Usage: Used to generate the Guest Owner Diffie-Hellman cert used in
 *                LaunchStart
 * Parameters:    [oca_key_pair] the input pub/priv key pair used to populate
 *                  and sign the cert
 *                  command as input to this function, to help populate the cert
 */
bool SEVCert::create_oca_cert(EVP_PKEY **oca_key_pair, SEV_SIG_ALGO algo)
{
    bool cmd_ret = false;

    if (!oca_key_pair)
        return false;

    do {
        memset(m_child_cert, 0, sizeof(sev_cert));

        m_child_cert->version = SEV_CERT_MAX_VERSION;
        m_child_cert->api_major = 0;
        m_child_cert->api_minor = 0;
        m_child_cert->pub_key_usage = SEV_USAGE_OCA;
        m_child_cert->pub_key_algo = algo;
        m_child_cert->sig_1_usage = SEV_USAGE_OCA;
        m_child_cert->sig_1_algo = algo;         // OCA is self-signed (sig algo is algo from OCA's keypair)
        m_child_cert->sig_2_usage = SEV_USAGE_INVALID;
        m_child_cert->sig_2_algo = SEV_SIG_ALGO_INVALID;

        // Set the pubkey portion of the cert
        if (decompile_public_key_into_certificate(m_child_cert, *oca_key_pair) != STATUS_SUCCESS)
            break;

        /*
         * Set the rest of the params and sign the signature with the newly
         * generated GODH privkey
         * Technically this step is not necessary, as the firmware doesn't
         * validate the GODH signature
         */
        if (!sign_with_key(SEV_CERT_MAX_VERSION, SEV_USAGE_OCA, algo,
                        oca_key_pair, SEV_USAGE_OCA, algo))
            break;

        cmd_ret = true;
    } while (0);

    return cmd_ret;
}

/**
 * Description: This function sets the many params of a cert (the child cert of
 *              the object used to call the this function) and then signs the
 *              cert with the private key provided. Note: Before calling this
 *              function, be sure to manually set the other parameters which
 *              this function does not specifically set, such as api_major,
 *              api_major, and pub_key, so they get included in the signature
 * Notes:       - sev_cert.c -> sev_cert_create() (kinda)
 *              - Signs the PEK's sig1 with the OCA (private key)
 *              The firmware signs sig2 with the CEK during PEK_CERT_IMPORT
 * Parameters:  [version][pub_key_usage][pub_key_algo] are for the child cert (PEK)
 *              [priv_evp_key][sig_1_usage][sig_1_algo] are for the parent cert (OCA)
 *
 * To optimize this function, can make the PEM read code RSA, EC, or general EVP.
 * The issue is that if it reads it into a common-format EVP_PKEY, how to we get
 * that private key into the EC_KEY or RSA_KEY that we are doing the signing on.
 * Also, to make the EC_KEY validate, I only figured out how to create the EC_KEY
 * with a GROUP as the input parm, not new up the EC_KEY then assign it a GROUP
 * and all other params later (don't know what other params it needed to validate
 * correctly)
 */
bool SEVCert::sign_with_key(uint32_t version, uint32_t pub_key_usage,
                            uint32_t pub_key_algo, EVP_PKEY **priv_evp_key,
                            uint32_t sig_1_usage, SEV_SIG_ALGO sig_1_algo)
{
    // Sign the certificate    sev_cert.c -> sev_cert_sign()
    // The constructor defaults all member vars, and the user can change them
    memset(&m_child_cert->sig_1, 0, sizeof(sev_cert::sig_1));
    m_child_cert->version = version;
    m_child_cert->pub_key_usage = pub_key_usage;
    m_child_cert->pub_key_algo = pub_key_algo;

    m_child_cert->sig_1_usage = sig_1_usage;       // Parent cert's sig
    m_child_cert->sig_1_algo = (uint32_t)sig_1_algo;

    // SHA256/SHA384 hash the cert from the [version:pub_key] params
    uint32_t pub_key_offset = offsetof(sev_cert, sig_1_usage);  // 16 + sizeof(sev_pubkey)
    return sign_message(&m_child_cert->sig_1, priv_evp_key, (uint8_t *)m_child_cert, pub_key_offset, sig_1_algo);
}

/**
 * Description: Validates the usage parameter of an sev_cert
 * Notes:       sev_cert.c  -> usage_is_valid()
 * Parameters:  [usage] is the input value to be validated
 */
SEV_ERROR_CODE SEVCert::validate_usage(uint32_t usage)
{
    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    switch (usage)
    {
    case SEV_USAGE_ARK:
    case SEV_USAGE_ASK:
    case SEV_USAGE_OCA:
    case SEV_USAGE_PEK:
    case SEV_USAGE_PDH:
    case SEV_USAGE_CEK:
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
 * Parameters:  [cert] the input sev_cert to validate the public key of
 *              [public_key] currently unused
 *
 * This function is untested because we don't have any RSA SEV_CERTs to test
 */
SEV_ERROR_CODE SEVCert::validate_rsa_pub_key(const sev_cert *cert, const EVP_PKEY *PublicKey)
{
    if (!cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    if (cert->pub_key.rsa.modulus_size <= SEV_RSA_PUB_KEY_MAX_BITS)    // bits
        cmd_ret = STATUS_SUCCESS;

    return cmd_ret;
}

/**
 * Description: The generic function to validate the public key of an sev_cert.
 *              Calls ValidateRSAPubkey to actually do the work for an RSA pubkey
 * Notes:       rsa.c -> pubkey_is_valid()
 * Parameters:  [cert] is the child cert
 *              [PublicKey] is the parent's public key
 */
SEV_ERROR_CODE SEVCert::validate_public_key(const sev_cert *cert, const EVP_PKEY *PublicKey)
{
    if (!cert || !PublicKey)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    do {
        if (validate_usage(cert->pub_key_usage) != STATUS_SUCCESS)
            break;

        if ((cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
            (cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
            if (validate_rsa_pub_key(cert, PublicKey) != STATUS_SUCCESS)
                break;
        }
        else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256)  ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384))
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
 * Parameters:  [child_cert] the cert which we want to validate the signature of.
 *               This is the cert that gets hashed and validated
 *              [parent_cert] tells us the algo used to sign the child cert
 *              [parent_signing_key] used to validate the hash of the child cert
 *              Ex) child_cert = PEK. parent_cert = OCA. parent_signing_key = OCA PubKey
 */
SEV_ERROR_CODE SEVCert::validate_signature(const sev_cert *child_cert,
                                           const sev_cert *parent_cert,
                                           EVP_PKEY *parent_signing_key)    // Probably PubKey
{
    if (!child_cert || !parent_cert || !parent_signing_key)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    sev_sig cert_sig[SEV_CERT_MAX_SIGNATURES] = {child_cert->sig_1, child_cert->sig_2};
    uint32_t cert_sig_algo[SEV_CERT_MAX_SIGNATURES] = {child_cert->sig_1_algo, child_cert->sig_2_algo};
    uint32_t cert_sig_usage[SEV_CERT_MAX_SIGNATURES] = {child_cert->sig_1_usage, child_cert->sig_2_usage};
    hmac_sha_256 sha_digest_256;        // Hash on the cert from Version to PubKey
    hmac_sha_512 sha_digest_384;        // Hash on the cert from Version to PubKey
    SHA_TYPE sha_type;
    uint8_t *sha_digest = NULL;
    size_t sha_length = 0;

    do{
        //TODO should this be child cert? should prob combine this function anyway
        // Determine if SHA_TYPE is 256 bit or 384 bit
        if (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256 || parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256 ||
            parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256)
        {
            sha_type = SHA_TYPE_256;
            sha_digest = sha_digest_256;
            sha_length = sizeof(hmac_sha_256);
        }
        else if (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384 || parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384 ||
                 parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)
        {
            sha_type = SHA_TYPE_384;
            sha_digest = sha_digest_384;
            sha_length = sizeof(hmac_sha_512);
        }
        else
        {
            break;
        }

        // 1. SHA256 hash the cert from Version through pub_key parameters
        // Calculate the digest of the input message   rsa.c -> rsa_pss_verify_msg()
        // SHA256/SHA384 hash the cert from the [Version:pub_key] params
        uint32_t pub_key_offset = offsetof(sev_cert, sig_1_usage);  // 16 + sizeof(SEV_PUBKEY)
        if (!digest_sha((uint8_t *)child_cert, pub_key_offset, sha_digest, sha_length, sha_type)) {
            break;
        }

        // 2. Use the pub_key in sig[i] arg to decrypt the sig in child_cert arg
        // Try both sigs in child_cert, to see if either of them match. In PEK, CEK and OCA can be in any order
        bool found_match = false;
        int i;
        for (i = 0; i < SEV_CERT_MAX_SIGNATURES; i++)
        {
            if ((parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
                (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
                uint32_t sig_len = parent_cert->pub_key.rsa.modulus_size/8; // Should be child_cert but SEV_RSA_SIG doesn't have a size param
                uint8_t decrypted[parent_cert->pub_key.rsa.modulus_size] = {0}; // TODO wrong length
                uint8_t signature[parent_cert->pub_key.rsa.modulus_size] = {0};

                RSA *rsa_pub_key = EVP_PKEY_get1_RSA(parent_signing_key);   // Signer's (parent's) public key
                if (!rsa_pub_key) {
                    printf("Error parent signing key is bad\n");
                    break;
                }

                // Swap the bytes of the signature
                memcpy(signature, &cert_sig[i].rsa, parent_cert->pub_key.rsa.modulus_size/8);
                if (!sev::reverse_bytes(signature, parent_cert->pub_key.rsa.modulus_size/8))
                    break;

                // Now we will verify the signature. Start by a RAW decrypt of the signature
                if (RSA_public_decrypt(sig_len, signature, decrypted, rsa_pub_key, RSA_NO_PADDING) == -1)
                    break;

                // Verify the data
                // SLen of -2 means salt length is recovered from the signature
                if (RSA_verify_PKCS1_PSS(rsa_pub_key, sha_digest,
                                        (parent_cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ? EVP_sha256() : EVP_sha384(),
                                        decrypted, -2) != 1)
                {
                    RSA_free(rsa_pub_key);
                    continue;
                }

                found_match = true;
                RSA_free(rsa_pub_key);
                break;
            }
            else if ((parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
                     (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
                     (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256)  ||
                     (parent_cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {      // ecdsa.c -> sign_verify_msg
                ECDSA_SIG *tmp_ecdsa_sig = ECDSA_SIG_new();
                BIGNUM *r_big_num = BN_new();
                BIGNUM *s_big_num = BN_new();

                // Store the x and y components as separate BIGNUM objects. The values in the
                // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
                r_big_num = BN_lebin2bn(cert_sig[i].ecdsa.r, sizeof(sev_ecdsa_sig::r), r_big_num);    // LE to BE
                s_big_num = BN_lebin2bn(cert_sig[i].ecdsa.s, sizeof(sev_ecdsa_sig::s), s_big_num);

                // Calling ECDSA_SIG_set0() transfers the memory management of the values to
                // the ECDSA_SIG object, and therefore the values that have been passed
                // in should not be freed directly after this function has been called
                if (ECDSA_SIG_set0(tmp_ecdsa_sig, r_big_num, s_big_num) != 1) {
                    BN_free(s_big_num);                   // Frees BIGNUMs manually here
                    BN_free(r_big_num);
                    ECDSA_SIG_free(tmp_ecdsa_sig);
                    continue;
                }
                EC_KEY *tmp_ec_key = EVP_PKEY_get1_EC_KEY(parent_signing_key); // Make a local key so you can free it later
                if (ECDSA_do_verify(sha_digest, (uint32_t)sha_length, tmp_ecdsa_sig, tmp_ec_key) != 1) {
                    EC_KEY_free(tmp_ec_key);
                    ECDSA_SIG_free(tmp_ecdsa_sig);      // Frees BIGNUMs too
                    continue;
                }

                found_match = true;
                EC_KEY_free(tmp_ec_key);
                ECDSA_SIG_free(tmp_ecdsa_sig);      // Frees BIGNUMs too
                break;
            }
            else {       // Bad/unsupported signing key algorithm
                printf("Unexpected algorithm! %x\n", parent_cert->pub_key_algo);
                break;
            }
        }
        if (!found_match)
            break;

        // 3. Compare
        // Check if:
        // 1. sig algo and parent key algo and
        // 2. sig usage and parent key usage match
        if((cert_sig_algo[i] != parent_cert->pub_key_algo) ||
           (cert_sig_usage[i] != parent_cert->pub_key_usage)) {
               break;
        }
        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

/**
 * Description: Validates the body (version through and including reserved1) of
 *              an sev_cert. Separate functions are used to validate the pubkey
 *              and the sigs
 * Notes:       sev_cert.c -> sev_cert_validate_body()
 * Parameters:  [cert] the sev_cert which to validate the body of
 */
SEV_ERROR_CODE SEVCert::validate_body(const sev_cert *cert)
{
    if (!cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;

    do {
        if ((cert->version == 0) || (cert->version > SEV_CERT_MAX_VERSION))
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

/**
 * Description: When a .cert file is imported, the PubKey is in sev_cert
 *              format. This function converts that format into a EVP_PKEY
 *              format where it can be used by other openssl functions.
 * Note:        This function NEWs/allocates memory for a EC_KEY that must be
 *              freed in the calling function using EC_KEY_free()
 * Parameters:  [cert] is the source sev_cert containing the public key we want
 *               to extract
 *              [evp_pubkey] is the destination EVP_PKEY where the extracted
 *               public key will go into
 */
SEV_ERROR_CODE SEVCert::compile_public_key_from_certificate(const sev_cert *cert, EVP_PKEY *evp_pub_key)
{
    if (!cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    RSA *rsa_pub_key = NULL;
    EC_KEY *ec_pub_key = NULL;
    BIGNUM *x_big_num = NULL;
    BIGNUM *y_big_num = NULL;
    BIGNUM *modulus = NULL;
    BIGNUM *pub_exp = NULL;

    do {
        if ((cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
            (cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
            // New up the RSA key
            rsa_pub_key = RSA_new();

            // Convert the parent to an RSA key to pass into RSA_verify
            modulus = BN_lebin2bn((uint8_t *)&cert->pub_key.rsa.modulus, cert->pub_key.rsa.modulus_size/8, NULL);  // n    // New's up BigNum
            pub_exp = BN_lebin2bn((uint8_t *)&cert->pub_key.rsa.pub_exp, cert->pub_key.rsa.modulus_size/8, NULL);  // e
            if (RSA_set0_key(rsa_pub_key, modulus, pub_exp, NULL) != 1)
                break;

            // Make sure the key is good.
            // TODO: This step fails because, from the openssl doc:
            //       It does not work on RSA public keys that have only
            //       the modulus and public exponent elements populated
            // if (RSA_check_key(rsa_pub_key) != 1)
            //     break;

            /*
             * Create a public EVP_PKEY from the public RSA_KEY
             * This function links evp_pub_key to rsa_pub_key, so when evp_pub_key
             *  is freed, rsa_pub_key is freed. We don't want the user to have to
             *  manage 2 keys, so just return EVP_PKEY and make sure user free's it
             */
            if (EVP_PKEY_assign_RSA(evp_pub_key, rsa_pub_key) != 1)
                break;
        }
        else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256)  ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384) ) {      // ecdsa.c -> sign_verify_msg

            // Store the x and y components as separate BIGNUM objects. The values in the
            // SEV certificate are little-endian, must reverse bytes before storing in BIGNUM
            if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
                (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384)) {
                x_big_num = BN_lebin2bn(cert->pub_key.ecdsa.qx, sizeof(cert->pub_key.ecdsa.qx), NULL);  // New's up BigNum
                y_big_num = BN_lebin2bn(cert->pub_key.ecdsa.qy, sizeof(cert->pub_key.ecdsa.qy), NULL);
            }
            else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256)  ||
                    (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {
                x_big_num = BN_lebin2bn(cert->pub_key.ecdh.qx, sizeof(cert->pub_key.ecdh.qx), NULL);  // New's up BigNum
                y_big_num = BN_lebin2bn(cert->pub_key.ecdh.qy, sizeof(cert->pub_key.ecdh.qy), NULL);
            }

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

            /*
             * Create a public EVP_PKEY from the public EC_KEY
             * This function links evp_pub_key to ec_pub_key, so when evp_pub_key
             *  is freed, ec_pub_key is freed. We don't want the user to have to
             *  manage 2 keys, so just return EVP_PKEY and make sure user free's it
             */
            if (EVP_PKEY_assign_EC_KEY(evp_pub_key, ec_pub_key) != 1)
                break;
        }

        if (!evp_pub_key)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory if it was allocated
    BN_free(y_big_num);     // If NULL, does nothing
    BN_free(x_big_num);
    // BN_free(modulus);    // Don't free here. RSA key is associated with these
    // BN_free(pub_exp);

    return cmd_ret;
}

/**
 * Description: This function is the reverse of CompilePublicKeyFromCertificate,
 *              in that is takes an EVP_PKEY and converts it to sev_cert format
 * Note:        This function NEWs/allocates memory for a EC_KEY that must be
 *              freed in the calling function using EC_KEY_free()
 * Parameters:  [cert] is the output cert which the public key gets written to
 *              [evp_pubkey] is the input public key
 */
SEV_ERROR_CODE SEVCert::decompile_public_key_into_certificate(sev_cert *cert, EVP_PKEY *evp_pubkey)
{
    if (!cert)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    EC_KEY *ec_pubkey = NULL;
    RSA *rsa_pubkey = NULL;
    const BIGNUM *exponent = NULL;
    const BIGNUM *modulus = NULL;
    BIGNUM *x_bignum = NULL;
    BIGNUM *y_bignum = NULL;
    EC_GROUP *ec_group = NULL;

    do {
        if ((cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA256) ||
            (cert->pub_key_algo == SEV_SIG_ALGO_RSA_SHA384)) {
            // Pull the RSA key from the EVP_PKEY
            rsa_pubkey = EVP_PKEY_get1_RSA(evp_pubkey);
            if (!rsa_pubkey)
                break;

            // Extract the exponent and modulus (RSA_get0_factors() would also work)
            exponent = RSA_get0_e(rsa_pubkey);   // Exponent
            modulus = RSA_get0_n(rsa_pubkey);    // Modulus

            cert->pub_key.rsa.modulus_size = 4096;    // Bits
            if (BN_bn2lebinpad(exponent, (unsigned char *)cert->pub_key.rsa.pub_exp, sizeof(cert->pub_key.rsa.pub_exp)) <= 0)
                break;
            if (BN_bn2lebinpad(modulus, (unsigned char *)cert->pub_key.rsa.modulus, sizeof(cert->pub_key.rsa.modulus)) <= 0)
                break;
        }
        else if ((cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA256) ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDSA_SHA384) ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA256)  ||
                 (cert->pub_key_algo == SEV_SIG_ALGO_ECDH_SHA384)) {      // ecdsa.c -> sign_verify_msg

            // Pull the EC_KEY from the EVP_PKEY
            ec_pubkey = EVP_PKEY_get1_EC_KEY(evp_pubkey);

            // Make sure the key is good
            if (EC_KEY_check_key(ec_pubkey) != 1)
                break;

            // Get the group and nid of the curve
            const EC_GROUP *ec_group = EC_KEY_get0_group(ec_pubkey);
            int nid = EC_GROUP_get_curve_name(ec_group);

            // Set the curve parameter of the cert's pubkey
            if (nid == EC_curve_nist2nid("P-256"))
                cert->pub_key.ecdh.curve = SEV_EC_P256;
            else // if (EC_curve_nist2nid("P-384"))
                cert->pub_key.ecdh.curve = SEV_EC_P384;

            // Get the EC_POINT from the public key
            const EC_POINT *pub = EC_KEY_get0_public_key(ec_pubkey);

            // New up the BIGNUMs
            x_bignum = BN_new();
            y_bignum = BN_new();

            // Get the x and y coordinates from the EC_POINT and store as separate BIGNUM objects
            if (!EC_POINT_get_affine_coordinates_GFp(ec_group, pub, x_bignum, y_bignum, NULL))
                break;

            // Store the x and y components into the cert. The values in the
            // BIGNUM are stored as big-endian, so must reverse bytes before
            // storing in SEV certificate as little-endian
            if (BN_bn2lebinpad(x_bignum, (unsigned char *)cert->pub_key.ecdh.qx, sizeof(cert->pub_key.ecdh.qx)) <= 0)
                break;
            if (BN_bn2lebinpad(y_bignum, (unsigned char *)cert->pub_key.ecdh.qy, sizeof(cert->pub_key.ecdh.qy)) <= 0)
                break;
        }

        if (!evp_pubkey)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory if it was allocated
    BN_free(y_bignum);       // If NULL, does nothing
    BN_free(x_bignum);
    EC_GROUP_free(ec_group);
    EC_KEY_free(ec_pubkey);
    RSA_free(rsa_pubkey);

    return cmd_ret;
}

/**
 * Description: Takes in a signed certificate and validates the signature(s)
 *              against the public keys in other certificates
 * Notes:       This test assumes parent_cert1 is always valid, and parent_cert2
 *              may be valid
 *              sev_cert.c -> sev_cert_validate()
 * Parameters:  [parent_cert1][parent_cert2] these are used to validate the 1 or 2
 *              signatures in the child cert (passed into the class constructor)
 */
SEV_ERROR_CODE SEVCert::verify_sev_cert(const sev_cert *parent_cert1, const sev_cert *parent_cert2)
{
    if (!parent_cert1)
        return ERROR_INVALID_CERTIFICATE;

    SEV_ERROR_CODE cmd_ret = ERROR_INVALID_CERTIFICATE;
    EVP_PKEY *parent_pub_key[SEV_CERT_MAX_SIGNATURES] = {NULL};
    const sev_cert *parent_cert[SEV_CERT_MAX_SIGNATURES] = {parent_cert1, parent_cert2};   // A cert has max of x parents/sigs

    do {
        // Get the public key from parent certs
        int numSigs = (parent_cert1 && parent_cert2) ? 2 : 1;   // Run the loop for 1 or 2 signatures
        int i = 0;
        for (i = 0; i < numSigs; i++) {
            // New up the EVP_PKEY
            if (!(parent_pub_key[i] = EVP_PKEY_new()))
                break;

            // This function allocates memory and attaches an EC_Key
            //  to your EVP_PKEY so, to prevent mem leaks, make sure
            //  the EVP_PKEY is freed at the end of this function
            if (compile_public_key_from_certificate(parent_cert[i], parent_pub_key[i]) != STATUS_SUCCESS)
                break;

            // Now, we have Parent's PublicKey(s), validate them
            if (validate_public_key(m_child_cert, parent_pub_key[i]) != STATUS_SUCCESS)
                break;

            // Validate the signature before we do any other checking
            // Sub-function will need a separate loop to find which of the 2 signatures this one matches to
            if (validate_signature(m_child_cert, parent_cert[i], parent_pub_key[i]) != STATUS_SUCCESS)
                break;
        }
        if (i != numSigs)
            break;

        // Validate the certificate body
        if (validate_body(m_child_cert) != STATUS_SUCCESS)
            break;

        // Although the signature was valid, ensure that the certificate
        // was signed with the proper key(s) in the correct order
        if (m_child_cert->pub_key_usage == SEV_USAGE_PDH) {
            // The PDH certificate must be signed by the PEK
            if (parent_cert1->pub_key_usage != SEV_USAGE_PEK) {
                break;
            }
        }
        else if (m_child_cert->pub_key_usage == SEV_USAGE_PEK) {
            // Checks parent certs for
            // 1. If OCA parent1 and CEK parent2 or
            // 2. If CEK parent1 and OCA parent2 or
            // 3. If OCA parent1 only certificate (signed CSR)
            if (((parent_cert1->pub_key_usage != SEV_USAGE_OCA) && (parent_cert2->pub_key_usage != SEV_USAGE_CEK)) &&
                ((parent_cert1->pub_key_usage != SEV_USAGE_CEK) && (parent_cert2->pub_key_usage != SEV_USAGE_OCA)) &&
                ((numSigs == 1) && (parent_cert1->pub_key_usage != SEV_USAGE_OCA))) {
                break;
            }
        }
        else if (m_child_cert->pub_key_usage == SEV_USAGE_OCA) {
            // The OCA certificate must be self-signed
            if (parent_cert1->pub_key_usage != SEV_USAGE_OCA) {
                break;
            }
        }
        else if (m_child_cert->pub_key_usage == SEV_USAGE_CEK) {
            // The CEK must be signed by the ASK
            if (parent_cert1->pub_key_usage != SEV_USAGE_ASK) {
                break;
            }
        }
        else
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory
    for (int i = 0; i < SEV_CERT_MAX_SIGNATURES; i++) {
        EVP_PKEY_free(parent_pub_key[i]);
    }

    return cmd_ret;
}

SEV_ERROR_CODE SEVCert::verify_signed_pek_csr(const sev_cert *oca_cert)
{
    do {
        if (m_child_cert->version        != 1                         ||
            m_child_cert->pub_key_usage  != SEV_USAGE_PEK             ||
            m_child_cert->pub_key_algo   != SEV_SIG_ALGO_ECDSA_SHA256 ||
            oca_cert->api_minor          != 0                         ||
            oca_cert->api_major          != 0                         ||
            oca_cert->version            != 1                         ||
            oca_cert->pub_key_usage      != SEV_USAGE_OCA ) {
                break;
        }
        uint32_t usage1 = m_child_cert->sig_1_usage, usage2 = m_child_cert->sig_2_usage;
        uint32_t algo1 = m_child_cert->sig_1_algo, algo2 = m_child_cert->sig_2_algo;

        char testblock [SEV_SIG_SIZE];
        memset (testblock, 0, SEV_SIG_SIZE);
        // Check exactly one field empty
        if ((algo1 == SEV_SIG_ALGO_INVALID) && (usage1 == SEV_USAGE_INVALID))
        {
            if (memcmp(testblock, &m_child_cert->sig_1, SEV_SIG_SIZE) != 0) {
                break;
            }
        }
        else if((algo2 == SEV_SIG_ALGO_INVALID) && (usage2 == SEV_USAGE_INVALID)) {
            if (memcmp(testblock, &m_child_cert->sig_2, SEV_SIG_SIZE) != 0) {
                break;
            }
        } else {
            break;
        }
        // Will check subsequent signature flags
        return verify_sev_cert(oca_cert, NULL);
    } while(0);
    return ERROR_INVALID_CERTIFICATE;
}

SEV_ERROR_CODE SEVCert::verify_pek_csr()
{
    if (m_child_cert->version        == 1                         &&
        m_child_cert->pub_key_usage  == SEV_USAGE_PEK             &&
        m_child_cert->pub_key_algo   == SEV_SIG_ALGO_ECDSA_SHA256 &&
        m_child_cert->sig_1_usage    == SEV_USAGE_INVALID         &&
        m_child_cert->sig_1_algo     == SEV_SIG_ALGO_INVALID      &&
        m_child_cert->sig_2_usage    == SEV_USAGE_INVALID         &&
        m_child_cert->sig_2_algo     == SEV_SIG_ALGO_INVALID ) {
        char testblock [SEV_SIG_SIZE];
        memset (testblock, 0, SEV_SIG_SIZE);
        // if both signatures 0
        if (!memcmp(testblock, &m_child_cert->sig_1, SEV_SIG_SIZE) || !memcmp(testblock, &m_child_cert->sig_2, SEV_SIG_SIZE)) {
            return STATUS_SUCCESS;
        }
    }
    return ERROR_INVALID_CERTIFICATE;
}
