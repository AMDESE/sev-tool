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
#include "sevcert.h"
#include "utilities.h"
#include <linux/types.h>
#include <asm/ioctl.h>      // Can take this out when figure out how to call SEV_ISSUE_CMD
#include <stdio.h>          // printf
#include <stdlib.h>         // malloc

SEV_ERROR_CODE Command::factory_reset()
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.factory_reset();

    return cmd_ret;
}

SEV_ERROR_CODE Command::platform_status()
{
    sev_user_data_status data;
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.platform_status(&data);

    if(cmd_ret == STATUS_SUCCESS) {
        // Print ID arrays
        printf("api_major:\t%d\n", data.api_major);
        printf("api_minor:\t%d\n", data.api_minor);
        printf("state:\t\t%d\n", data.state);
        printf("flags:\t\t%d\n", data.flags);
        printf("build:\t\t%d\n", data.build);
        printf("guest_count:\t%d\n", data.guest_count);
    }

    return cmd_ret;
}

SEV_ERROR_CODE Command::pek_gen()
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.pek_gen();

    return cmd_ret;
}

SEV_ERROR_CODE Command::pek_csr(std::string& output_folder, int verbose_flag)
{
    sev_user_data_pek_csr data;
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    // Populate PEKCSR buffer with CSRLength = 0
    void *PEKMem = malloc(sizeof(SEV_CERT));
    SEV_CERT PEKcsr;

    if(!PEKMem)
        return ERROR_RESOURCE_LIMIT;

    cmd_ret = gSEVDevice.pek_csr(&data, PEKMem, &PEKcsr);

    if(cmd_ret == STATUS_SUCCESS) {
        if(verbose_flag) {          // Print off the cert to stdout
            PrintCertReadable(&PEKcsr);
            PrintCertHex((void*)&PEKcsr);
        }
        if(output_folder != "") {   // Print off the cert to a text file
            std::string PEKcsr_readable = "";
            std::string PEKcsr_readable_path = output_folder+"/"+PEK_CSR_READABLE_FILENAME;
            std::string PEKcsr_hex_path = output_folder+"/"+PEK_CSR_HEX_FILENAME;

            PrintCertReadable(&PEKcsr, PEKcsr_readable);
            WriteFile(PEKcsr_readable_path, (void*)PEKcsr_readable.c_str(), PEKcsr_readable.size());
            WriteFile(PEKcsr_hex_path, (void*)&PEKcsr, sizeof(PEKcsr));
        }
    }

    // Free memory
    free(PEKMem);

    return cmd_ret;
}

SEV_ERROR_CODE Command::pdh_gen()
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.pdh_gen();

    return cmd_ret;
}

SEV_ERROR_CODE Command::pdh_cert_export(std::string& output_folder, int verbose_flag)
{
    sev_user_data_pdh_cert_export data;
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    void *PDHCertMem = malloc(sizeof(SEV_CERT));
    void *CertChainMem = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    if(!PDHCertMem || !CertChainMem)
        return ERROR_RESOURCE_LIMIT;

    cmd_ret = gSEVDevice.pdh_cert_export(&data, PDHCertMem, CertChainMem);

    if(cmd_ret == STATUS_SUCCESS) {
        if(verbose_flag) {          // Print off the cert to stdout
            // PrintCertReadable((SEV_CERT*)PDHCertMem);
            // printf("pdh_cert_len: %d bytes\n", data.pdh_cert_len);
            PrintCertHex(PDHCertMem);
            // printf("cert_chain_len: %d bytes\n", data.cert_chain_len);
            PrintCertChainBufReadable(CertChainMem);
        }
        if(output_folder != "") {   // Print off the cert to a text file
            std::string PDH_readable = "";
            std::string cc_readable = "";
            std::string PDH_readable_path = output_folder+"/"+PDH_CERT_READABLE_FILENAME;
            std::string PDH_path          = output_folder+"/"+PDH_CERT_HEX_FILENAME;
            std::string cc_readable_path  = output_folder+"/"+CERT_CHAIN_READABLE_FILENAME;
            std::string cc_path           = output_folder+"/"+CERT_CHAIN_HEX_FILENAME;

            PrintCertReadable((SEV_CERT*)PDHCertMem, PDH_readable);
            PrintCertChainBufReadable(CertChainMem, cc_readable);
            WriteFile(PDH_readable_path, (void*)PDH_readable.c_str(), PDH_readable.size());
            WriteFile(PDH_path, PDHCertMem, sizeof(SEV_CERT));
            WriteFile(cc_readable_path, (void*)cc_readable.c_str(), cc_readable.size());
            WriteFile(cc_path, CertChainMem, sizeof(SEV_CERT_CHAIN_BUF));
        }
    }

    // Free memory
    free(PDHCertMem);
    free(CertChainMem);

    return cmd_ret;
}

SEV_ERROR_CODE Command::pek_cert_import(std::string& oca_priv_key_file,
                                        std::string& oca_cert_file)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    sev_user_data_pdh_cert_export pdh_cert_export_data;  // pdh_cert_export
    void *PDHCertMem = malloc(sizeof(SEV_CERT));
    void *CertChainMem = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    sev_user_data_pek_csr pek_csr_data;                  // pek_csr
    void *PEKMem = malloc(sizeof(SEV_CERT));
    SEV_CERT PEKcsr;

    sev_user_data_pek_cert_import pek_cert_import_data;  // pek_cert_import

    sev_user_data_pdh_cert_export pdh_cert_export_data2; // pdh_cert_export
    void *PDHCertMem2 = malloc(sizeof(SEV_CERT));
    void *CertChainMem2 = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    do {
        if(!PDHCertMem || !CertChainMem || !PEKMem || !PDHCertMem2 || !CertChainMem2) {
            cmd_ret = ERROR_RESOURCE_LIMIT;
            break;
        }

        cmd_ret = gSEVDevice.set_self_owned();
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pdh_cert_export(&pdh_cert_export_data, PDHCertMem, CertChainMem);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pek_csr(&pek_csr_data, PEKMem, &PEKcsr);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pek_cert_import(&pek_cert_import_data, &PEKcsr,
                                             oca_priv_key_file, oca_cert_file);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        // Verify the results
        cmd_ret = gSEVDevice.pdh_cert_export(&pdh_cert_export_data2, PDHCertMem2, CertChainMem2);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        if(0 != memcmp(&pdh_cert_export_data2, &pdh_cert_export_data, sizeof(sev_user_data_pdh_cert_export)))
            break;

        printf("PEK Cert Import SUCCESS!!!\n");
    } while (0);

    // Free memory
    free(PDHCertMem);
    free(CertChainMem);
    free(PEKMem);
    free(PDHCertMem2);
    free(CertChainMem2);

    return cmd_ret;
}

// Must always pass in 128 bytes array, because of how linux /dev/sev ioctl works
SEV_ERROR_CODE Command::get_id(std::string& output_folder, int verbose_flag)
{
    sev_user_data_get_id data;
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.get_id(&data);

    if(cmd_ret == STATUS_SUCCESS) {
        char id1_buf[sizeof(data.socket1)*3] = {0};
        char id2_buf[sizeof(data.socket2)*3] = {0};
        for(uint8_t i = 0; i < sizeof(data.socket1); i++)
        {
            sprintf(id1_buf+strlen(id1_buf), "%02x", data.socket1[i]);
        }
        for(uint8_t i = 0; i < sizeof(data.socket2); i++)
        {
            sprintf(id2_buf+strlen(id2_buf), "%02x", data.socket2[i]);
        }
        std::string id1_str = id1_buf;
        std::string id2_str = id2_buf;

        if(verbose_flag) {          // Print ID arrays
            printf("* GetID Socket1:\n%s", id1_str.c_str());
            printf("\n* GetID Socket2:\n%s", id2_str.c_str());
            printf("\n");
        }
        if(output_folder != "") {   // Print the IDs to a text file
            std::string id1_path = output_folder+"/"+GET_ID_S1_FILENAME;
            std::string id2_path = output_folder+"/"+GET_ID_S2_FILENAME;
            WriteFile(id1_path, (void*)id1_str.c_str(), id1_str.size());
            WriteFile(id2_path, (void*)id2_str.c_str(), id2_str.size());
        }
    }

    return cmd_ret;
}

// ------------------------------------- //
// ---- Non-Linux (Custom) commands ---- //
// ------------------------------------- //

SEV_ERROR_CODE Command::calc_measurement(std::string& output_folder, int verbose_flag,
                                         measurement_t *user_data)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    HMACSHA256 final_meas;

    cmd_ret = gSEVDevice.calc_measurement(user_data, &final_meas);

    if(cmd_ret == STATUS_SUCCESS) {
        char meas_buf[sizeof(final_meas)*3] = {0};
        for(size_t i = 0; i < sizeof(final_meas); i++) {
            sprintf(meas_buf+strlen(meas_buf), "%02x", final_meas[i]);
        }
        std::string meas_str = meas_buf;

        if(verbose_flag) {          // Print ID arrays
            // Print input args for user
            printf("Input Arguments:\n");
            printf("   Context: %02x\n", user_data->meas_ctx);
            printf("   Api Major: %02x\n", user_data->api_major);
            printf("   Api Minor: %02x\n", user_data->api_minor);
            printf("   Build ID: %02x\n", user_data->build_id);
            printf("   Policy: %02x\n", user_data->policy);
            printf("   Digest: ");
            for(size_t i = 0; i < sizeof(user_data->digest); i++) {
                printf("%02x", user_data->digest[i]);
            }
            printf("\n   MNonce: ");
            for(size_t i = 0; i < sizeof(user_data->mnonce); i++) {
                printf("%02x", user_data->mnonce[i]);
            }
            printf("\n   TIK: ");
            for(size_t i = 0; i < sizeof(user_data->tik); i++) {
                printf("*");
            }
            // Print output
            printf("\n\n%s\n", meas_str.c_str());
        }
        if(output_folder != "") {   // Print the IDs to a text file
            std::string meas_path = output_folder+"/"+CALC_MEASUREMENT_FILENAME;
            WriteFile(meas_path, (void*)meas_str.c_str(), meas_str.size());
        }
    }

    return cmd_ret;
}

SEV_ERROR_CODE Command::set_self_owned()
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.set_self_owned();

    return cmd_ret;
}

SEV_ERROR_CODE Command::set_externally_owned(std::string& oca_priv_key_file,
                                             std::string& oca_cert_file)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.set_externally_owned(oca_priv_key_file, oca_cert_file);

    return cmd_ret;
}
