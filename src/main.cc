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

#include "commands.h"
#include <stdio.h>
#include <string>
#include <cstring>  // memcpy

char helpArray[] = "The following commands are supported: \n" \
                    "  sev_factory_reset\n" \
                    "  sev_platform_status\n" \
                    "  sev_pek_gen\n" \
                    "  sev_pek_csr\n" \
                    "  sev_pdh_gen\n" \
                    "  sev_pdh_cert_export\n" \
                    "  sev_pek_cert_import\n" \
                    "  sev_get_id\n";

uint32_t map_arg_to_cmd(std::string arg)
{
    uint32_t ret = 0;

    if(strcmp(arg.c_str(), "sev_factory_reset") == 0)
        ret = SEV_FACTORY_RESET;
    else if(strcmp(arg.c_str(), "sev_platform_status") == 0)
        ret = SEV_PLATFORM_STATUS;
    else if(strcmp(arg.c_str(), "sev_pek_gen") == 0)
        ret = SEV_PEK_GEN;
    else if(strcmp(arg.c_str(), "sev_pek_csr") == 0)
        ret = SEV_PEK_CSR;
    else if(strcmp(arg.c_str(), "sev_pdh_gen") == 0)
        ret = SEV_PDH_GEN;
    else if(strcmp(arg.c_str(), "sev_pdh_cert_export") == 0)
        ret = SEV_PDH_CERT_EXPORT;
    else if(strcmp(arg.c_str(), "sev_pek_cert_import") == 0)
        ret = SEV_PEK_CERT_IMPORT;
    else if(strcmp(arg.c_str(), "sev_get_id") == 0)
        ret = SEV_GET_ID;
    else
        ret = SEV_MAX;

    return ret;
}


int main(int argc, char** argv)
{
    Command cmd;
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    printf("You have entered %i arguments\n", argc);
    if(argc == 1)           // User didnt enter any args
        printf("%s\n", helpArray);

    // todo, really an 'if else' on arg[1]
    for (int i = 1; i < argc; ++i)  // First arg is exe name
    {
        printf("%i, %s\n", i, argv[i]);
        uint32_t int_arg = map_arg_to_cmd(argv[i]);
        switch (int_arg) {
            case SEV_FACTORY_RESET: {       // SEV_FACTORY_RESET
                cmd_ret = cmd.factory_reset();
                continue;
            }
	        case SEV_PLATFORM_STATUS: {
                cmd_ret = cmd.platform_status();
                continue;
            }
	        case SEV_PEK_GEN: {
                cmd_ret = cmd.pek_gen();
                continue;
            }
	        case SEV_PEK_CSR: {
                cmd_ret = cmd.pek_csr();
                continue;
            }
	        case SEV_PDH_GEN: {
                cmd_ret = cmd.pdh_gen();
                continue;
            }
	        case SEV_PDH_CERT_EXPORT: {
                cmd_ret = cmd.pdh_cert_export();
                continue;
            }
	        case SEV_PEK_CERT_IMPORT: {
                cmd_ret = cmd.pek_cert_import();
                continue;
            }
	        case SEV_GET_ID: {
                cmd_ret = cmd.get_id();
                continue;
            }
            default: {
                printf("%s\n", helpArray);
                break;
            }
        }
    }

    if(cmd_ret == STATUS_SUCCESS)
        printf("command successful\n");
    else
        printf("command unsuccessful: 0x%02x\n", cmd_ret);

    return 0;
}