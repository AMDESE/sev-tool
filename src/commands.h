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

#ifndef COMMANDS_H
#define COMMANDS_H

#include "sevapi.h"         // for HMACSHA256, Nonce128, AES128Key
#include "sevcore.h"        // for SEVDevice
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

#define CERTS_ZIP_FILENAME              "certs_export"          // export_cert_chain
#define ASK_ARK_FILENAME                "ask_ark.cert"          // get_ask_ark
#define PEK_CSR_HEX_FILENAME            "pek_csr.cert"          // pek_csr
#define PEK_CSR_READABLE_FILENAME       "pek_csr_readable.txt"  // pek_csr
#define CERT_CHAIN_HEX_FILENAME         "cert_chain.cert"       // pdh_cert_export
#define CERT_CHAIN_READABLE_FILENAME    "cert_chain_readable.txt"// pdh_cert_export
#define GET_ID_S0_FILENAME              "getid_s0_out.txt"      // get_id
#define GET_ID_S1_FILENAME              "getid_s1_out.txt"      // get_id
#define CALC_MEASUREMENT_FILENAME       "calc_measurement_out.txt" // calc_measurement
#define LAUNCH_BLOB_FILENAME            "launch_blob.bin"       // generate_launch_blob
#define GUEST_OWNER_DH_FILENAME         "godh.cert"             // generate_launch_blob
#define GUEST_TK_FILENAME               "tmp_tk.bin"            // generate_launch_blob
#define SECRET_FILENAME                 "secret.txt"            // package_secret
#define PACKAGED_SECRET_FILENAME        "packaged_secret.bin"   // package_secret
#define PACKAGED_SECRET_HEADER_FILENAME "packaged_secret_header.bin" // package_secret

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
    SEVDevice m_sev_device;
    TEKTIK m_tk;                // Unencrypted TIK/TEK. WrapTK is this enc with KEK
    HMACSHA256 m_measurement;   // Measurement. Used in LaunchSecret header HMAC
    std::string m_output_folder = "";
    int m_verbose_flag = 0;

    int calculate_measurement(measurement_t *user_data, HMACSHA256 *final_meas);
    int generate_all_certs(void);
    int import_all_certs(SEV_CERT *pdh, SEV_CERT *pek, SEV_CERT *oca,
                         SEV_CERT *cek, AMD_CERT *ask, AMD_CERT *ark);
    bool kdf(uint8_t *key_out, size_t key_out_length, const uint8_t *key_in,
             size_t key_in_length, const uint8_t *label, size_t label_length,
             const uint8_t *context, size_t context_length);
    uint8_t* calculate_shared_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_key,
                                     size_t& shared_key_len_out);
    bool derive_master_secret(AES128Key master_secret,
                              EVP_PKEY *godh_priv_key,
                              const SEV_CERT *pdh_public,
                              const uint8_t nonce[sizeof(Nonce128)]);
    bool derive_kek(AES128Key kek, const AES128Key master_secret);
    bool derive_kik(HMACKey128 kik, const AES128Key master_secret);
    bool gen_hmac(HMACSHA256 *out, HMACKey128 key, uint8_t *msg, size_t msg_len);
    bool encrypt(uint8_t *out, const uint8_t *in, size_t length,
                 const AES128Key Key, const uint8_t IV[128/8]);
    int build_session_buffer(SEV_SESSION_BUF *buf, uint32_t guest_policy,
                             EVP_PKEY *godh_priv_key, SEV_CERT *pdh_pub);
    int encrypt_with_tek(uint8_t *encrypted_mem, const uint8_t *secret_mem,
                         size_t secret_mem_size, const IV128 iv);
    bool create_launch_secret_header(SEV_HDR_BUF *out_header, IV128 *iv,
                                     uint8_t *buf, size_t buffer_len,
                                     uint32_t hdr_flags);

public:
    Command() {};
    Command(std::string output_folder, int verbose_flag);
    ~Command() {};

    int factory_reset(void);
    int platform_status(void);
    int pek_gen(void);
    int pek_csr(void);
    int pdh_gen(void);
    int pdh_cert_export(void);
    int pek_cert_import(std::string& oca_priv_key_file);
    int get_id(void);

    // Non-ioctl (custom) commands
    int sys_info(void);
    int get_platform_owner(void);
    int get_platform_es(void);
    int set_self_owned(void);
    int set_externally_owned(std::string& oca_priv_key_file);
    int generate_cek_ask(void);
    int get_ask_ark(void);
    int export_cert_chain(void);
    int calc_measurement(measurement_t *user_data);
    int validate_cert_chain(void);
    int generate_launch_blob(uint32_t policy);
    int package_secret(void);
};

#endif /* commands_h */
