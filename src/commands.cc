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
#include "sevapi.h"
#include "sevcert.h"
#include "sevcore.h"
#include <linux/types.h>
#include <asm/ioctl.h>      // Can take this out when figure out how to call SEV_ISSUE_CMD
#include <stdio.h>          // printf
#include <stdlib.h>         // malloc

int Command::factory_reset()
{
    int cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.factory_reset();

    return cmd_ret;
}

int Command::platform_status()
{
    sev_user_data_status data;
    int cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.platform_status(&data);

    if(cmd_ret == SEV_RET_SUCCESS) {
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

int Command::pek_gen()
{
    int cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.pek_gen();

    return cmd_ret;
}

int Command::pek_csr()
{
    sev_user_data_pek_csr data;
    int cmd_ret = ERROR_UNSUPPORTED;

    // Populate PEKCSR buffer with CSRLength = 0
    void* PEKMem = malloc(sizeof(SEV_CERT));
    SEV_CERT PEKcsr;

    cmd_ret = gSEVDevice.pek_csr(&data, PEKMem, &PEKcsr);

    if(cmd_ret == SEV_RET_SUCCESS) {
        // Print off the cert
        PrintCert(&PEKcsr);
        PrintCertHex((void*)&PEKcsr);
    }

    // Free memory
    free(PEKMem);

    return cmd_ret;
}

int Command::pdh_gen()
{
    int cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.pdh_gen();

    return cmd_ret;
}

int Command::pdh_cert_export()
{
    sev_user_data_pdh_cert_export data;
    int cmd_ret = ERROR_UNSUPPORTED;

    void* PDHCertMem = malloc(sizeof(SEV_CERT));
    void* CertChainMem = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    cmd_ret = gSEVDevice.pdh_cert_export(&data, PDHCertMem, CertChainMem);

    if(cmd_ret == SEV_RET_SUCCESS) {
        // PrintCert((SEV_CERT*)PDHCertMem);
        // printf("pdh_cert_len: %d bytes\n", data.pdh_cert_len);
        PrintCertHex(PDHCertMem);
        // printf("cert_chain_len: %d bytes\n", data.cert_chain_len);
        PrintCertChainBufHex(CertChainMem);
    }

    // Free memory
    free(PDHCertMem);
    free(CertChainMem);

    return cmd_ret;
}

int Command::pek_cert_import()
{
    int cmd_ret = ERROR_UNSUPPORTED;

    sev_user_data_pdh_cert_export pdh_cert_export_data;  // pdh_cert_export
    void* PDHCertMem = malloc(sizeof(SEV_CERT));
    void* CertChainMem = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    sev_user_data_pek_csr pek_csr_data;                  // pek_csr
    void* PEKMem = malloc(sizeof(SEV_CERT));
    SEV_CERT PEKcsr;

    sev_user_data_pek_cert_import pek_cert_import_data;  // pek_cert_import

    sev_user_data_pdh_cert_export pdh_cert_export_data2; // pdh_cert_export
    void* PDHCertMem2 = malloc(sizeof(SEV_CERT));
    void* CertChainMem2 = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    do {
        cmd_ret = gSEVDevice.SetSelfOwned();
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pdh_cert_export(&pdh_cert_export_data, PDHCertMem, CertChainMem);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pek_csr(&pek_csr_data, PEKMem, &PEKcsr);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pek_cert_import(&pek_cert_import_data, &PEKcsr);
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
int Command::get_id()
{
    sev_user_data_get_id data;
    int cmd_ret = ERROR_UNSUPPORTED;

    cmd_ret = gSEVDevice.get_id(&data);

    if(cmd_ret == SEV_RET_SUCCESS) {
        // Print ID arrays
        printf("GetID:\n");
        for(uint8_t i = 0; i < sizeof(data.socket1); i++)
        {
            printf("%02x", data.socket1[i]);
        }
        for(uint8_t i = 0; i < sizeof(data.socket2); i++)
        {
            printf("%02x", data.socket2[i]);
        }
        printf("\n");
    }

    return cmd_ret;
}

// ask brijesh how to force re-load of firmware.
// put fw in correct place, unload driver, and reload driver. on driver reloading,
//  it will look for firmware and download it if its there

// GuestOwner creates guest owner DH key. only user gen key

// Need OCA priv key?
// Yes. And you should use the standard OpenSSL (OpenSSH?) command line tools to
//  generate a key pair, and use those tools to sign the CSR, then use sev-tool to
//  reformat the signed cert in to PEK_CERT_IMPORT form.
// That’s going to be tricky… we’ll have to talk a bit about that. We’ll want to
//  assume that sev-tool cannot see the private key (since it SHOULD be in an HSM).
//  So we may need to reformat the CSR so the signature generated by the external
//  tool is usable with IMPORT.
