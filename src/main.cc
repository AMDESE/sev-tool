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

#include "commands.h"  // has measurement_t
#include "utilities.h" // for StrToArray
#include <cstring>     // memcpy
#include <getopt.h>    // for getopt_long
#include <stdio.h>
#include <string>

char helpArray[] = "The following commands are supported:\n" \
                   " sevtool -[global opts] --[command] [command opts]\n" \
                   "(Please see the readme file for more detailed information)\n" \
                   "  factory_reset\n" \
                   "  platform_status\n" \
                   "  pek_gen\n" \
                   "  pek_csr\n" \
                   "   - Use --verbose to print out cert\n" \
                   "  pdh_gen\n" \
                   "  pdh_cert_export\n" \
                   "  pek_cert_import\n" \
                   "      Input params:\n" \
                   "          oca_key_in.pem file " \
                   "          oca_in.cert file " \
                   "  get_id\n" \
                   "  calc_measurement\n" \
                   "      Input params (all in ascii-encoded hex bytes):\n" \
                   "          uint8_t  meas_ctx\n" \
                   "          uint8_t  api_major\n" \
                   "          uint8_t  api_minor\n" \
                   "          uint8_t  build_id\n" \
                   "          uint32_t policy\n" \
                   "          uint32_t digest\n" \
                   "          uint8_t mnonce[128/8]\n" \
                   "          uint8_t gctx_tik[128/8]\n" \
                   "  set_self_owed\n" \
                   "  set_externally_owned\n" \
                   ;

/* Flag set by '--verbose' */
static int verbose_flag = 0;

static struct option long_options[] =
{
    /* These options set a flag. */
    {"verbose",             no_argument,       &verbose_flag, 1},
    {"brief",               no_argument,       &verbose_flag, 0},

    /* These options don't set a flag. We distinguish them by their indices. */
    {"factory_reset",        no_argument,       0, 'a'},
    {"platform_status",      no_argument,       0, 'b'},
    {"pek_gen",              no_argument,       0, 'c'},
    {"pek_csr",              no_argument,       0, 'd'},
    {"pdh_gen",              no_argument,       0, 'e'},
    {"pdh_cert_export",      no_argument,       0, 'f'},
    {"pek_cert_import",      required_argument, 0, 'g'},
    {"get_id",               no_argument,       0, 'j'},
    {"calc_measurement",     required_argument, 0, 'k'},
    {"set_self_owned",       no_argument,       0, 'l'},
    {"set_externally_owned", required_argument, 0, 'm'},

    {"help",                 no_argument,       0, 'H'},
    {"sysinfo",              no_argument,       0, 'I'},
    {"ofolder",              required_argument, 0, 'O'},
    {0, 0, 0, 0}
};

int main(int argc, char** argv)
{
    int c = 0;
    int option_index = 0;   /* getopt_long stores the option index here. */
    std::string output_folder = "";

    int cmd_ret = 0xFFFF;
    Command cmd;

    while ((c = getopt_long (argc, argv, "hio:", long_options, &option_index)) != -1)
    {
        switch (c) {
            case 'h':
            case 'H': {
                printf("%s\n", helpArray);
                cmd_ret = 0;
                break;
            }
            case 'i':
            case 'I': {
                cmd_ret = cmd.sysinfo();  // Display system info
                break;
            }
            case 'o':
            case 'O': {
                output_folder = optarg;
                // printf("Output folder: %s\n", output_file.c_str());
                break;
            }
            case 'a': {       // PLATFORM_RESET
                cmd_ret = cmd.factory_reset();
                break;
            }
            case 'b': {
                cmd_ret = cmd.platform_status();
                break;
            }
            case 'c': {
                cmd_ret = cmd.pek_gen();
                break;
            }
            case 'd': {
                cmd_ret = cmd.pek_csr(output_folder, verbose_flag);
                break;
            }
            case 'e': {
                cmd_ret = cmd.pdh_gen();
                break;
            }
            case 'f': {
                cmd_ret = cmd.pdh_cert_export(output_folder, verbose_flag);
                break;
            }
            case 'g': {
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if(argc - optind != 2) {
                    printf("Error: Expecting exactly 2 args\n");
                    break;
                }

                std::string oca_priv_key_file = argv[optind++];
                std::string oca_cert_file = argv[optind++];
                cmd_ret = cmd.pek_cert_import(oca_priv_key_file, oca_cert_file);
                break;
            }
            case 'j': {
                cmd_ret = cmd.get_id(output_folder, verbose_flag);
                break;
            }
            case 'k': {
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if(argc - optind != 8) {
                    printf("Error: Expecting exactly 8 args\n");
                    break;
                }

                measurement_t user_data;
                user_data.meas_ctx  = (uint8_t)strtol(argv[optind++], NULL, 16);
                user_data.api_major = (uint8_t)strtol(argv[optind++], NULL, 16);
                user_data.api_minor = (uint8_t)strtol(argv[optind++], NULL, 16);
                user_data.build_id  = (uint8_t)strtol(argv[optind++], NULL, 16);
                user_data.policy    = (uint32_t)strtol(argv[optind++], NULL, 16);
                StrToArray(std::string(argv[optind++]), (uint8_t *)&user_data.digest, sizeof(user_data.digest));
                StrToArray(std::string(argv[optind++]), (uint8_t *)&user_data.mnonce, sizeof(user_data.mnonce));
                StrToArray(std::string(argv[optind++]), (uint8_t *)&user_data.tik,    sizeof(user_data.tik));
                cmd_ret = cmd.calc_measurement(output_folder, verbose_flag, &user_data);
                break;
            }
            case 'l': {
                cmd_ret = cmd.set_self_owned();
                break;
            }
            case 'm': {
                optind--;   // Can't use option_index because it doesn't account for '-' flags
                if(argc - optind != 2) {
                    printf("Error: Expecting exactly 2 args\n");
                    break;
                }

                std::string oca_priv_key_file = argv[optind++];
                std::string oca_cert_file = argv[optind++];
                cmd_ret = cmd.set_externally_owned(oca_priv_key_file, oca_cert_file);
                break;
            }
            case 0:
            case 1 : {
                // Verbose/brief
                break;
            }
            default: {
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                break;
            }
        }
    }

    if(cmd_ret == 0)
        printf("\nCommand Successful\n");
    else if(cmd_ret == 0xFFFF)
        printf("\nCommand not supported/recognized. Possibly bad formatting\n");
    else
        printf("\nCommand Unsuccessful: 0x%02x\n", cmd_ret);

    return 0;
}