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

#ifndef commands_h
#define commands_h

#include "sevapi.h"         // for HMACSHA256, Nonce128, AES128Key
#include <openssl/evp.h>    // for EVP_PKEY
#include <openssl/sha.h>    // for SHA256_DIGEST_LENGTH
#include <string>

#define PDH_FILENAME                    "pdh.cert"          // PDH signed by PEK
#define PDH_READABLE_FILENAME           "pdh_readable.txt"
#define PEK_FILENAME                    "pek.cert"          // PEK signed by CEK
#define PEK_READABLE_FILENAME           "pek_readable.txt"
#define OCA_FILENAME                    "oca.cert"          // OCA signed by P.O.
#define OCA_READABLE_FILENAME           "oca_readable.cert"
#define CEK_FILENAME                    "cek.cert"          // CEK signed by ASK
#define CEK_READABLE_FILENAME           "cek_readable.cert"
#define ASK_FILENAME                    "ask.cert"          // ASK signed by ARK
#define ASK_READABLE_FILENAME           "ask_readable.cert"
#define ARK_FILENAME                    "ark.cert"          // ARK self-signed
#define ARK_READABLE_FILENAME           "ark_readable.cert"

#define CERTS_ZIP_FILENAME              "certs_export"
#define ASK_ARK_FILENAME                "ask_ark.cert"      // For get_ask_ark
#define PEK_CSR_HEX_FILENAME            "pek_csr.cert"
#define PEK_CSR_READABLE_FILENAME       "pek_csr_readable.txt"
#define CERT_CHAIN_HEX_FILENAME         "cert_chain.cert"
#define CERT_CHAIN_READABLE_FILENAME    "cert_chain_readable.txt"
#define GET_ID_S0_FILENAME              "getid_s0_out.txt"
#define GET_ID_S1_FILENAME              "getid_s1_out.txt"
#define CALC_MEASUREMENT_FILENAME       "calc_measurement_out.txt"
#define LAUNCH_BLOB_FILENAME            "launch_blob.txt"
#define GUEST_OWNER_PUBKEY_FILENAME     "godh_pubkey.pem"
#define SECRET_FILENAME                 "secret.txt"
#define PACKAGED_SECRET_FILENAME        "packaged_secret.txt"

#define BITS_PER_BYTE    8
#define NIST_KDF_H_BYTES 32
#define NIST_KDF_H       (NIST_KDF_H_BYTES*BITS_PER_BYTE)   // 32*8=256
#define NIST_KDF_R       sizeof(uint32_t)*BITS_PER_BYTE     // 32

#define SEV_MASTER_SECRET_LABEL "sev-master-secret"
#define SEV_KEK_LABEL           "sev-kek"
#define SEV_KIK_LABEL           "sev-kik"

#define LAUNCH_MEASURE_CTX 0x4
struct measurement_t {
    uint8_t  meas_ctx;  // LAUNCH_MEASURE_CTX
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  build_id;
    uint32_t policy;    // SEV_POLICY
    uint8_t  digest[SHA256_DIGEST_LENGTH];   // gctx_ld
    Nonce128 mnonce;
    AES128Key tik;
};

class Command {
private:
    int calculate_measurement(measurement_t *user_data, HMACSHA256 *final_meas);
    int generate_all_certs(std::string& output_folder);
    int import_all_certs(std::string& output_folder, SEV_CERT *pdh,
                                SEV_CERT *pek, SEV_CERT *oca, SEV_CERT *cek,
                                AMD_CERT *ask, AMD_CERT *ark);
    bool kdf(uint8_t *key_out, size_t key_out_length, const uint8_t *key_in,
             size_t key_in_length, const uint8_t *label, size_t label_length,
             const uint8_t *context, size_t context_length);
    uint8_t* calculate_shared_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_key,
                                   size_t& shared_key_len_out);
    bool derive_master_secret(AES128Key master_secret,
                            const SEV_CERT *pdh_public,
                            const uint8_t nonce[sizeof(Nonce128)]);
    bool derive_kek(AES128Key kik, const AES128Key master_secret);
    bool derive_kik(HMACKey128 kik, const AES128Key master_secret);
    bool gen_hmac(HMACSHA256 *out, HMACKey128 key, uint8_t *msg, size_t msg_len);
    bool encrypt(uint8_t *out, const uint8_t *in, size_t length,
                 const AES128Key Key, const uint8_t IV[128/8]);
    int build_session_buffer(SEV_SESSION_BUF *buf, uint32_t guest_policy, SEV_CERT *pdh_pub);

    std::string m_output_folder = "";
public:
    Command() {};
    ~Command() {};

    int factory_reset(void);
    int platform_status(void);
    int pek_gen(void);
    int pek_csr(std::string& output_folder, int verbose_flag);
    int pdh_gen(void);
    int pdh_cert_export(std::string& output_folder, int verbose_flag);
    int pek_cert_import(std::string& oca_priv_key_file,
                                std::string& oca_cert_file);
    int get_id(std::string& output_folder, int verbose_flag);

    // Non-ioctl (custom) commands
    int sysinfo();
    int set_self_owned(void);
    int set_externally_owned(std::string& oca_priv_key_file,
                                std::string& oca_cert_file);
    int generate_cek_ask(std::string& output_folder);
    int get_ask_ark(std::string& output_folder);
    int export_cert_chain(std::string& output_folder);
    int calc_measurement(std::string& output_folder, int verbose_flag,
                                measurement_t *user_data);
    int validate_cert_chain(std::string& output_folder);
    int generate_launch_blob(std::string& output_folder, int verbose_flag,
                                uint32_t policy);
    int package_secret(std::string& output_folder, uint32_t verbose_flag);
    int encrypt_with_tek(uint8_t *encrypted_mem, const uint8_t *secret_mem,
                                size_t secret_mem_size, const AES128Key tek,
                                const IV128 iv);
};

#endif /* commands_h */
