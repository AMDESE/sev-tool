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

#include "sevapi.h"
#include "sevcore.h"
#include "x509cert.h"
#include "linux/psp-sev.h"
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

class Command {

public:
    Command() {};
    ~Command() {};

    SEV_ERROR_CODE factory_reset(void);
    SEV_ERROR_CODE platform_status(void);
    SEV_ERROR_CODE pek_gen(void);
    SEV_ERROR_CODE pek_csr(std::string& output_folder, int verbose_flag);
    SEV_ERROR_CODE pdh_gen(void);
    SEV_ERROR_CODE pdh_cert_export(std::string& output_folder, int verbose_flag);
    SEV_ERROR_CODE pek_cert_import(std::string& oca_priv_key_file,
                                   std::string& oca_cert_file);
    SEV_ERROR_CODE get_id(std::string& output_folder, int verbose_flag);

    SEV_ERROR_CODE calc_measurement(std::string& output_folder, int verbose_flag,
                                    measurement_t *user_data);
    SEV_ERROR_CODE set_self_owned(void);
    SEV_ERROR_CODE set_externally_owned(std::string& oca_priv_key_file,
                                        std::string& oca_cert_file);
};

#endif /* sevcert_h */
