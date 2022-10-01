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

#include "commands.h"  // has measurement_t
#include "tests.h"     // for test_all
#include "utilities.h" // for str_to_array
#include <getopt.h>    // for getopt_long
#include <cstdio>
#include <array>
#include <filesystem>
#include <string>
#include <string_view>

std::string_view const help_array = R"(The following commands are supported:
    sev-tool -[global opts] --[command] [command opts]
(Please see the readme file for more detailed information)
Platform Owner commands:
    factory_reset
    platform_status
    pek_gen
    pek_csr
    pdh_gen
    pdh_cert_export
    pek_cert_import
        Input params:
            pek_csr.signed.cert file
            oca.cert file
    get_id
    sign_pek_csr
        Input params:
            pek_csr.cert file
            [oca private key].pem file
    set_self_owned
    set_externally_owned
        Input params:
            [oca private key].pem file
    generate_cek_ask
    get_ask_ark
    export_cert_chain
Guest Owner commands:
    calc_measurement
        Input params (all in ascii-encoded hex bytes):
            uint8_t  meas_ctx
            uint8_t  api_major
            uint8_t  api_minor
            uint8_t  build_id
            uint32_t policy
            uint32_t digest
            uint8_t  m_nonce[128/8]
            uint8_t  gctx_tik[128/8]
    validate_cert_chain
    generate_launch_blob
        Input params:
            uint32_t policy
    package_secret
    validate_attestation
    validate_guest_report
    validate_cert_chain_vcek
    export_cert_chain_vcek
)";

/* Flag set by '--verbose' */
static int verbose_flag = 0;

static std::array<option, 29> long_options{{
    /* These options set a flag. */
    {"verbose",             no_argument,       &verbose_flag, 1},
    {"brief",               no_argument,       &verbose_flag, 0},

    /* These options don't set a flag. We distinguish them by their indices. */
    /* Platform Owner commands */
    {"factory_reset",            no_argument,       nullptr, 'a'},
    {"platform_status",          no_argument,       nullptr, 'b'},
    {"pek_gen",                  no_argument,       nullptr, 'c'},
    {"pek_csr",                  no_argument,       nullptr, 'd'},
    {"pdh_gen",                  no_argument,       nullptr, 'e'},
    {"pdh_cert_export",          no_argument,       nullptr, 'f'},
    {"pek_cert_import",          required_argument, nullptr, 'g'},
    {"get_id",                   no_argument,       nullptr, 'j'},
    {"set_self_owned",           no_argument,       nullptr, 'k'},
    {"set_externally_owned",     required_argument, nullptr, 'l'},
    {"generate_cek_ask",         no_argument,       nullptr, 'm'},
    {"export_cert_chain",        no_argument,       nullptr, 'p'},
    {"export_cert_chain_vcek",   no_argument,       nullptr, 'q'},
    {"sign_pek_csr",             required_argument, nullptr, 's'},
    /* Guest Owner commands */
    {"get_ask_ark",              no_argument,       nullptr, 'n'},
    {"calc_measurement",         required_argument, nullptr, 't'},
    {"validate_cert_chain",      no_argument,       nullptr, 'u'},
    {"generate_launch_blob",     required_argument, nullptr, 'v'},
    {"package_secret",           no_argument,       nullptr, 'w'},
    {"validate_attestation",     no_argument,       nullptr, 'x'}, // SEV attestation command
    {"validate_guest_report",    no_argument,       nullptr, 'y'}, // SNP GuestRequest ReportRequest
    {"validate_cert_chain_vcek", no_argument,       nullptr, 'z'},

    /* Run tests */
    {"test_all",             no_argument,       nullptr, 'T'},

    {"help",                 no_argument,       nullptr, 'H'},
    {"sys_info",             no_argument,       nullptr, 'I'},
    {"ofolder",              required_argument, nullptr, 'O'},
    {nullptr, 0, nullptr, 0}
}};

int main(int argc, char **argv)
{
    int c = 0;
    int option_index = 0;   /* getopt_long stores the option index here. */
    std::string output_folder = "./";

    int cmd_ret = 0xFFFF;

    while ((c = getopt_long (argc, argv, "hio:", long_options.data(), &option_index)) != -1)
    {
        switch (c) {
            case 'h':           // help
            case 'H': {
                printf("%s\n", help_array.data());
                cmd_ret = 0;
                break;
            }
            case 'i':           // sys_info
            case 'I': {
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.sys_info();  // Display system info
                break;
            }
            case 'o':           // ofolder
            case 'O': {
                output_folder = optarg;
                output_folder += "/";

                // Check that output folder exists, and immediately stop if not
                if (!std::filesystem::is_directory(output_folder)) {
                    printf("Error. Output directory '%s' does not exist or is not a directory.\n", output_folder.c_str());
                    return EXIT_FAILURE;
                }

                break;
            }
            case 'a': {         // PLATFORM_RESET
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.factory_reset();
                break;
            }
            case 'b': {         // PLATFORM_STATUS
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.platform_status();
                break;
            }
            case 'c': {         // PEK_GEN
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.pek_gen();
                break;
            }
            case 'd': {         // PEK_CSR
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.pek_csr();
                break;
            }
            case 'e': {         // PDH_GEN
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.pdh_gen();
                break;
            }
            case 'f': {         // PDH_CERT_EXPORT
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.pdh_cert_export();
                break;
            }
            case 'g': {         // PEK_CERT_IMPORT
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if (argc - optind != 2) {
                    printf("Error: Expecting exactly 2 args for pek_cert_import\n");
                    return EXIT_FAILURE;
                }
                std::string signed_pek_csr_file = argv[optind++];
                std::string oca_cert_file = argv[optind++];

                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.pek_cert_import(signed_pek_csr_file, oca_cert_file);
                break;
            }
            case 'j': {         // GET_ID
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.get_id();
                break;
            }
            case 'k': {         // SET_SELF_OWNED
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.set_self_owned();
                break;
            }
            case 'l': {         // SET_EXTERNALLY_OWNED
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if (argc - optind != 1) {
                    printf("Error: Expecting exactly 1 arg for set_externally_owned\n");
                    return EXIT_FAILURE;
                }

                std::string oca_priv_key_file = argv[optind++];
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.set_externally_owned(oca_priv_key_file);
                break;
            }
            case 'm': {         // GENERATE_CEK_ASK
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.generate_cek_ask();
                break;
            }
            case 'n': {         // GET_ASK_ARK
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.get_ask_ark();
                break;
            }
            case 'p': {         // EXPORT_CERT_CHAIN
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.export_cert_chain();
                break;
            }
            case 'q': {         // EXPORT_CERT_CHAIN_VCEK
                Command cmd(output_folder, verbose_flag);
                cmd_ret = cmd.export_cert_chain_vcek();
                break;
            }
           case 's': {         // SIGN_PEK_CSR
                optind--;
                if (argc - optind != 2) {
                    printf("Error: Expecting exactly 2 args for pek_cert_import\n");
                    return EXIT_FAILURE;
                }
                std::string pek_csr_file = argv[optind++];
                std::string oca_priv_key_file = argv[optind++];

                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.sign_pek_csr(pek_csr_file, oca_priv_key_file);
                break;
            }
            case 't': {         // CALC_MEASUREMENT
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if (argc - optind != 8) {
                    printf("Error: Expecting exactly 8 args for calc_measurement\n");
                    return EXIT_FAILURE;
                }

                measurement_t user_data;
                user_data.meas_ctx  = (uint8_t)strtol(argv[optind++], nullptr, 16);
                user_data.api_major = (uint8_t)strtol(argv[optind++], nullptr, 16);
                user_data.api_minor = (uint8_t)strtol(argv[optind++], nullptr, 16);
                user_data.build_id  = (uint8_t)strtol(argv[optind++], nullptr, 16);
                user_data.policy    = (uint32_t)strtol(argv[optind++], nullptr, 16);
                sev::str_to_array(std::string(argv[optind++]), reinterpret_cast<uint8_t *>(&user_data.digest), sizeof(user_data.digest));
                sev::str_to_array(std::string(argv[optind++]), reinterpret_cast<uint8_t *>(&user_data.mnonce), sizeof(user_data.mnonce));
                sev::str_to_array(std::string(argv[optind++]), reinterpret_cast<uint8_t *>(&user_data.tik),    sizeof(user_data.tik));
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.calc_measurement(&user_data);
                break;
            }
            case 'u': {         // VALIDATE_CERT_CHAIN
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.validate_cert_chain();
                break;
            }
            case 'v': {         // GENERATE_LAUNCH_BLOB
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if (argc - optind != 1) {
                    printf("Error: Expecting exactly 1 arg for generate_launch_blob\n");
                    return EXIT_FAILURE;
                }

                uint32_t guest_policy = (uint8_t)strtol(argv[optind++], nullptr, 16);
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.generate_launch_blob(guest_policy);
                break;
            }
            case 'w': {         // PACKAGE_SECRET
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.package_secret();
                break;
            }
            case 'x': {         // VALIDATE_ATTESTATION
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.validate_attestation();
                break;
            }
            case 'y': {         // VALIDATE_GUEST_REPORT
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.validate_guest_report();
                break;
            }
            case 'z': {         // VALIDATE_CERT_CHAIN_VCEK
                Command cmd(output_folder, verbose_flag, CCP_NOT_REQ);
                cmd_ret = cmd.validate_cert_chain_vcek();
                break;
            }
            case 'T': {         // Run Tests
                Tests test(output_folder, verbose_flag);
                cmd_ret = (test.test_all() == 0); // 0 = fail, 1 = pass
                break;
            }
            case 0:
            case 1 : {
                // Verbose/brief
                break;
            }
            default: {
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return EXIT_FAILURE;
            }
        }
    }

    if (cmd_ret == 0) {
        printf("\nCommand Successful\n");
        return EXIT_SUCCESS;
    }
    else if (cmd_ret == 0xFFFF) {
        printf("\nCommand not supported/recognized. Possibly bad formatting\n");
    }
    else {
        printf("\nCommand Unsuccessful: 0x%02x\n", cmd_ret);
    }
    return EXIT_FAILURE;
}
