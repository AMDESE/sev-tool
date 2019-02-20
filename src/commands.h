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
#include <openssl/sha.h>    // for SHA256_DIGEST_LENGTH
#include <string>

#define PEK_CSR_HEX_FILENAME            "pek_csr_out.cert"
#define PEK_CSR_READABLE_FILENAME       "pek_csr_readable_out.cert"
#define PDH_CERT_HEX_FILENAME           "pdh_out.cert"
#define PDH_CERT_READABLE_FILENAME      "pdh_readable_out.cert"
#define CERT_CHAIN_HEX_FILENAME         "cert_chain_out.cert"
#define CERT_CHAIN_READABLE_FILENAME    "cert_chain_readable_out.cert"
#define GET_ID_S1_FILENAME              "getid_s1_out.txt"
#define GET_ID_S2_FILENAME              "getid_s2_out.txt"
#define CALC_MEASUREMENT_FILENAME       "calc_measurement_out.txt"
#define CEK_ASK_FILENAME                "cek_ask.cert"
#define ASK_ARK_FILENAME                "ask_ark.cert"
#define ASK_FILENAME                    "ask.cert"
#define ARK_FILENAME                    "ark.cert"

#define LAUNCH_MEASURE_CTX 0x4
struct measurement_t {
    uint8_t  meas_ctx;  // LAUNCH_MEASURE_CTX
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  build_id;
    uint32_t policy;    // SEV_POLICY
    uint8_t digest[SHA256_DIGEST_LENGTH];   // gctx_ld
    Nonce128 mnonce;
    AES128Key tik;
};

class Command {
private:
    int calculate_measurement(measurement_t *user_data, HMACSHA256 *final_meas);
    int validate_platform(SEV_CERT *pdh, SEV_CERT_CHAIN_BUF *pdh_cert_chain,
                                AMD_CERT *ask, AMD_CERT *ark);
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
    int calc_measurement(std::string& output_folder, int verbose_flag,
                                    measurement_t *user_data);
    int set_self_owned(void);
    int set_externally_owned(std::string& oca_priv_key_file,
                                        std::string& oca_cert_file);
    int generate_cek_ask(std::string& output_folder);
    int get_ask_ark(std::string& output_folder);
    int validate_cert_chain(std::string& output_folder);
};

#endif /* commands_h */
