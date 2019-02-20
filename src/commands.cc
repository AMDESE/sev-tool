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

#include "amdcert.h"
#include "commands.h"
#include "sevcore.h"
#include "sevcert.h"
#include "utilities.h"      // for WriteToFile
#include <openssl/hmac.h>   // for calc_measurement
#include <stdio.h>          // printf
#include <stdlib.h>         // malloc

int Command::factory_reset()
{
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.factory_reset();

    return (int)cmd_ret;
}

int Command::platform_status()
{
    uint8_t data[sizeof(SEV_PLATFORM_STATUS_CMD_BUF)];
    SEV_PLATFORM_STATUS_CMD_BUF *data_buf = (SEV_PLATFORM_STATUS_CMD_BUF *)&data;
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.platform_status(data);

    if(cmd_ret == STATUS_SUCCESS) {
        // Print ID arrays
        printf("api_major:\t%d\n", data_buf->ApiMajor);
        printf("api_minor:\t%d\n", data_buf->ApiMinor);
        printf("platform_state:\t%d\n", data_buf->CurrentPlatformState);
        if(data_buf->ApiMinor >= 17) {
            printf("owner:\t\t%d\n", data_buf->Owner);
            printf("config:\t\t%d\n", data_buf->Config);
        }
        else {
            printf("flags:\t\t%d\n",
                    ((data_buf->Owner & PLAT_STAT_OWNER_MASK) << PLAT_STAT_OWNER_MASK) +
                    ((data_buf->Config & PLAT_STAT_ES_MASK) << PLAT_STAT_CONFIGES_OFFSET));
        }
        printf("build:\t\t%d\n", data_buf->BuildID);
        printf("guest_count:\t%d\n", data_buf->GuestCount);
    }

    return (int)cmd_ret;
}

int Command::pek_gen()
{
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.pek_gen();

    return (int)cmd_ret;
}

int Command::pek_csr(std::string& output_folder, int verbose_flag)
{
    uint8_t data[sizeof(SEV_PEK_CSR_CMD_BUF)];
    int cmd_ret = -1;

    // Populate PEKCSR buffer with CSRLength = 0
    void *PEKMem = malloc(sizeof(SEV_CERT));
    SEV_CERT PEKcsr;

    if(!PEKMem)
        return -1;

    cmd_ret = gSEVDevice.pek_csr(data, PEKMem, &PEKcsr);

    if(cmd_ret == STATUS_SUCCESS) {
        if(verbose_flag) {          // Print off the cert to stdout
            print_cert_readable(&PEKcsr);
            print_cert_hex((void*)&PEKcsr);
        }
        if(output_folder != "") {   // Print off the cert to a text file
            std::string PEKcsr_readable = "";
            std::string PEKcsr_readable_path = output_folder+"/"+PEK_CSR_READABLE_FILENAME;
            std::string PEKcsr_hex_path = output_folder+"/"+PEK_CSR_HEX_FILENAME;

            print_cert_readable(&PEKcsr, PEKcsr_readable);
            WriteFile(PEKcsr_readable_path, (void*)PEKcsr_readable.c_str(), PEKcsr_readable.size());
            WriteFile(PEKcsr_hex_path, (void*)&PEKcsr, sizeof(PEKcsr));
        }
    }

    // Free memory
    free(PEKMem);

    return (int)cmd_ret;
}

int Command::pdh_gen()
{
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.pdh_gen();

    return (int)cmd_ret;
}

int Command::pdh_cert_export(std::string& output_folder, int verbose_flag)
{
    uint8_t data[sizeof(SEV_PDH_CERT_EXPORT_CMD_BUF)];
    int cmd_ret = -1;

    void *PDHCertMem = malloc(sizeof(SEV_CERT));
    void *CertChainMem = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    if(!PDHCertMem || !CertChainMem)
        return -1;

    cmd_ret = gSEVDevice.pdh_cert_export(data, PDHCertMem, CertChainMem);

    if(cmd_ret == STATUS_SUCCESS) {
        if(verbose_flag) {          // Print off the cert to stdout
            // print_cert_readable((SEV_CERT*)PDHCertMem); printf("\n");
            print_cert_hex(PDHCertMem); printf("\n");
            print_cert_chain_buf_readable(CertChainMem);
        }
        if(output_folder != "") {   // Print off the cert to a text file
            std::string PDH_readable = "";
            std::string cc_readable = "";
            std::string PDH_readable_path = output_folder+"/"+PDH_CERT_READABLE_FILENAME;
            std::string PDH_path          = output_folder+"/"+PDH_CERT_HEX_FILENAME;
            std::string cc_readable_path  = output_folder+"/"+CERT_CHAIN_READABLE_FILENAME;
            std::string cc_path           = output_folder+"/"+CERT_CHAIN_HEX_FILENAME;

            print_cert_readable((SEV_CERT*)PDHCertMem, PDH_readable);
            print_cert_chain_buf_readable(CertChainMem, cc_readable);
            WriteFile(PDH_readable_path, (void*)PDH_readable.c_str(), PDH_readable.size());
            WriteFile(PDH_path, PDHCertMem, sizeof(SEV_CERT));
            WriteFile(cc_readable_path, (void*)cc_readable.c_str(), cc_readable.size());
            WriteFile(cc_path, CertChainMem, sizeof(SEV_CERT_CHAIN_BUF));
        }
    }

    // Free memory
    free(PDHCertMem);
    free(CertChainMem);

    return (int)cmd_ret;
}

int Command::pek_cert_import(std::string& oca_priv_key_file,
                                        std::string& oca_cert_file)
{
    int cmd_ret = -1;

    uint8_t pdh_cert_export_data[sizeof(SEV_PDH_CERT_EXPORT_CMD_BUF)];  // pdh_cert_export
    void *PDHCertMem = malloc(sizeof(SEV_CERT));
    void *CertChainMem = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    uint8_t pek_csr_data[sizeof(SEV_PEK_CSR_CMD_BUF)];                  // pek_csr
    void *PEKMem = malloc(sizeof(SEV_CERT));
    SEV_CERT PEKcsr;

    uint8_t pek_cert_import_data[sizeof(SEV_PEK_CERT_IMPORT_CMD_BUF)];  // pek_cert_import

    uint8_t pdh_cert_export_data2[sizeof(SEV_PDH_CERT_EXPORT_CMD_BUF)]; // pdh_cert_export
    void *PDHCertMem2 = malloc(sizeof(SEV_CERT));
    void *CertChainMem2 = malloc(sizeof(SEV_CERT_CHAIN_BUF));

    do {
        if(!PDHCertMem || !CertChainMem || !PEKMem || !PDHCertMem2 || !CertChainMem2) {
            cmd_ret = -1;
            break;
        }

        cmd_ret = gSEVDevice.set_self_owned();
        if(cmd_ret != 0)
            break;

        cmd_ret = gSEVDevice.pdh_cert_export(pdh_cert_export_data, PDHCertMem, CertChainMem);
        if(cmd_ret != 0)
            break;

        cmd_ret = gSEVDevice.pek_csr(pek_csr_data, PEKMem, &PEKcsr);
        if(cmd_ret != 0)
            break;

        cmd_ret = gSEVDevice.pek_cert_import(pek_cert_import_data, &PEKcsr,
                                             oca_priv_key_file, oca_cert_file);
        if(cmd_ret != 0)
            break;

        // Verify the results
        cmd_ret = gSEVDevice.pdh_cert_export(pdh_cert_export_data2, PDHCertMem2, CertChainMem2);
        if(cmd_ret != 0)
            break;

        if(0 != memcmp(pdh_cert_export_data2, pdh_cert_export_data, sizeof(SEV_PDH_CERT_EXPORT_CMD_BUF)))
            break;

        printf("PEK Cert Import SUCCESS!!!\n");
    } while (0);

    // Free memory
    free(PDHCertMem);
    free(CertChainMem);
    free(PEKMem);
    free(PDHCertMem2);
    free(CertChainMem2);

    return (int)cmd_ret;
}

// Must always pass in 128 bytes array, because of Linux /dev/sev ioctl
// doesn't follow the API
int Command::get_id(std::string& output_folder, int verbose_flag)
{
    uint8_t data[sizeof(SEV_GET_ID_CMD_BUF)];
    SEV_GET_ID_CMD_BUF *data_buf = (SEV_GET_ID_CMD_BUF *)&data;
    int cmd_ret = -1;
    uint32_t default_id_length = 0;

    // Send the first command with a length of 0, then use the returned length
    // as the input parameter for the 'real' command which will succeed
    SEV_GET_ID_CMD_BUF data_buf_temp;
    cmd_ret = gSEVDevice.get_id((uint8_t *)&data_buf_temp, NULL);  // Sets IDLength
    if(cmd_ret != ERROR_INVALID_LENGTH)     // What we expect to happen
        return cmd_ret;
    default_id_length = data_buf_temp.IDLength;

    // Always allocate 2 ID's worth because Linux will always write 2 ID's worth.
    // If you have 1 ID and you are not in Linux, allocating extra is fine
    void *IDMem = malloc(2*default_id_length);
    if(!IDMem)
        return cmd_ret;

    cmd_ret = gSEVDevice.get_id(data, IDMem, 2*default_id_length);

    if(cmd_ret == STATUS_SUCCESS) {
        char id1_buf[default_id_length*2+1] = {0};  // 2 chars per byte +1 for null term
        char id2_buf[default_id_length*2+1] = {0};
        for(uint8_t i = 0; i < default_id_length; i++)
        {
            sprintf(id1_buf+strlen(id1_buf), "%02x", ((uint8_t *)(data_buf->IDPAddr))[i]);
            sprintf(id2_buf+strlen(id2_buf), "%02x", ((uint8_t *)(data_buf->IDPAddr))[i+default_id_length]);
        }

        if(verbose_flag) {          // Print ID arrays
            printf("* GetID Socket1:\n%s", id1_buf);
            printf("\n* GetID Socket2:\n%s", id2_buf);
            printf("\n");
        }
        if(output_folder != "") {   // Print the IDs to a text file
            std::string id1_path = output_folder+"/"+GET_ID_S1_FILENAME;
            std::string id2_path = output_folder+"/"+GET_ID_S2_FILENAME;
            WriteFile(id1_path, (void*)id1_buf, sizeof(id1_buf)-1);   // Don't write null term
            WriteFile(id2_path, (void*)id2_buf, sizeof(id2_buf)-1);
        }
    }

    // Free memory
    free(IDMem);

    return (int)cmd_ret;
}

// ------------------------------------- //
// ---- Non-ioctl (Custom) commands ---- //
// ------------------------------------- //
int Command::sysinfo()
{
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.sysinfo();

    return (int)cmd_ret;
}

// We cannot call LaunchMeasure to get the MNonce because that command doesn't
// exist in this context, so we user the user input params for all of our data
// This function assumes the API version is at >= 0.17
int Command::calculate_measurement(measurement_t *user_data, HMACSHA256 *final_meas)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    uint32_t MeasurementLength = sizeof(final_meas);

    // Create and initialize the context
    HMAC_CTX *ctx;
    if (!(ctx = HMAC_CTX_new()))
        return ERROR_BAD_MEASUREMENT;

    do {
        if (HMAC_Init_ex(ctx, user_data->tik, sizeof(user_data->tik), EVP_sha256(), NULL) != 1)
            break;
        //if (MinAPIVersion(0,17)) {
            if (HMAC_Update(ctx, &user_data->meas_ctx, sizeof(user_data->meas_ctx)) != 1)
                break;
            if (HMAC_Update(ctx, &user_data->api_major, sizeof(user_data->api_major)) != 1)
                break;
            if (HMAC_Update(ctx, &user_data->api_minor, sizeof(user_data->api_minor)) != 1)
                break;
            if (HMAC_Update(ctx, &user_data->build_id, sizeof(user_data->build_id)) != 1)
                break;
        //}
        if (HMAC_Update(ctx, (uint8_t *)&user_data->policy, sizeof(user_data->policy)) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t *)&user_data->digest, sizeof(user_data->digest)) != 1)
            break;
        // Use the same random MNonce as the FW in our validation calculations
        if (HMAC_Update(ctx, (uint8_t *)&user_data->mnonce, sizeof(user_data->mnonce)) != 1)
            break;
        if (HMAC_Final(ctx, (uint8_t *)final_meas, &MeasurementLength) != 1)  // size = 32
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    HMAC_CTX_free(ctx);
    return cmd_ret;
}

int Command::calc_measurement(std::string& output_folder, int verbose_flag,
                                         measurement_t *user_data)
{
    int cmd_ret = -1;
    HMACSHA256 final_meas;

    cmd_ret = calculate_measurement(user_data, &final_meas);

    if(cmd_ret == STATUS_SUCCESS) {
        char meas_buf[sizeof(final_meas)*2+1] = {0};  // 2 chars per byte +1 for null term
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

    return (int)cmd_ret;
}

int Command::set_self_owned()
{
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.set_self_owned();

    return (int)cmd_ret;
}

int Command::set_externally_owned(std::string& oca_priv_key_file,
                                             std::string& oca_cert_file)
{
    int cmd_ret = -1;

    cmd_ret = gSEVDevice.set_externally_owned(oca_priv_key_file, oca_cert_file);

    return (int)cmd_ret;
}

int Command::generate_cek_ask(std::string& output_folder)
{
    int cmd_ret = -1;

    std::string cert_file = CEK_ASK_FILENAME;

    cmd_ret = gSEVDevice.generate_cek_ask(output_folder, cert_file);

    return (int)cmd_ret;
}

int Command::get_ask_ark(std::string& output_folder)
{
    int cmd_ret = -1;

    std::string cert_file = ASK_ARK_FILENAME;

    cmd_ret = gSEVDevice.get_ask_ark(output_folder, cert_file);

    return (int)cmd_ret;
}

int Command::validate_platform(SEV_CERT *pdh, SEV_CERT_CHAIN_BUF *pdh_cert_chain,
                                    AMD_CERT *ask, AMD_CERT *ark)
{
    int cmd_ret = STATUS_SUCCESS;
    SEV_CERT *pek = PEKinCertChain(pdh_cert_chain);
    SEV_CERT *oca = OCAinCertChain(pdh_cert_chain);
    SEV_CERT *cek = CEKinCertChain(pdh_cert_chain);
    SEV_CERT ask_pubkey;
    SEVCert tmp_sev_cek(*cek);
    SEVCert tmp_sev_pek(*pek);
    SEVCert tmp_sev_pdh(*pdh);
    AMDCert tmp_amd;

    do {
        // Validate the ARK
        cmd_ret = tmp_amd.amd_cert_validate_ark(ark);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the ASK
        cmd_ret = tmp_amd.amd_cert_validate_ask(ask, ark);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Export the ASK to an SEV cert public key
        // The verify_sev_cert function takes in a parent of an SEV_CERT not
        //   an AMD_CERT, so need to pull the pubkey out of the AMD_CERT and
        //   place it into a tmp SEV_CERT to help validate the cek
        cmd_ret = tmp_amd.amd_cert_export_pubkey(ask, &ask_pubkey);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the CEK
        cmd_ret = tmp_sev_cek.verify_sev_cert(&ask_pubkey);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the PEK with the CEK and OCA
        cmd_ret = tmp_sev_pek.verify_sev_cert(cek, oca);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the PDH
        cmd_ret = tmp_sev_pdh.verify_sev_cert(pek);
        if (cmd_ret != STATUS_SUCCESS)
            break;

    } while (0);

    return cmd_ret;
}

int Command::validate_cert_chain(std::string& output_folder)
{
    int cmd_ret = -1;
    uint8_t pdh_cert_export_data[sizeof(SEV_PDH_CERT_EXPORT_CMD_BUF)];  // pdh_cert_export
    SEV_CERT *pdh = (SEV_CERT *)malloc(sizeof(SEV_CERT));        // PDH
    SEV_CERT_CHAIN_BUF *cert_chain = (SEV_CERT_CHAIN_BUF *)malloc(sizeof(SEV_CERT_CHAIN_BUF)); // PEK, OCA, CEK
    SEV_CERT cek_ask;
    AMD_CERT ask;
    AMD_CERT ark;
    std::string cek_ask_file = CEK_ASK_FILENAME;
    std::string ask_ark_file = ASK_ARK_FILENAME;
    SEV_CERT dummy;
    SEVCert tmp_sev(dummy);
    AMDCert tmp_amd;

    do {
        // Get the PDH Cert Chain
        cmd_ret = gSEVDevice.pdh_cert_export(pdh_cert_export_data, (void *)pdh, (void *)cert_chain);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        // Generate the cek_ask
        cmd_ret = gSEVDevice.generate_cek_ask(output_folder, cek_ask_file);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        // Generate the ask_ark
        cmd_ret = gSEVDevice.get_ask_ark(output_folder, ask_ark_file);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        // Read in the cek_ask
        std::string cek_ask_full = output_folder + "/" + cek_ask_file;
        if(ReadFile(cek_ask_full, &cek_ask, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;
        // print_cert_readable(&cek_ask);

        // Read in the ask_ark
        uint8_t ask_ark_buf[sizeof(AMD_CERT)*2] = {0};
        std::string ask_ark_full = output_folder + "/" + ask_ark_file;
        if(ReadFile(ask_ark_full, ask_ark_buf, sizeof(ask_ark_buf)) == 0)
            break;

        // Initialize the ASK cert
        cmd_ret = tmp_amd.amd_cert_init(&ask, ask_ark_buf);
        if (cmd_ret != STATUS_SUCCESS)
            break;
        // print_amd_cert_readable(&ask);

        // Initialize the ARK
        size_t ask_size = tmp_amd.amd_cert_get_size(&ask);
        cmd_ret = tmp_amd.amd_cert_init(&ark, (uint8_t *)(ask_ark_buf + ask_size));
        if (cmd_ret != STATUS_SUCCESS)
            break;
        // print_amd_cert_readable(&ark);

        // Note that the CEK in the cert chain is unsigned, so we want to use
        // the one 'cached by the hypervisor' that's signed by the ask
        memcpy(CEKinCertChain(cert_chain), &cek_ask, sizeof(SEV_CERT));

        // Validate the cert chain
        cmd_ret = validate_platform(pdh, cert_chain, &ask, &ark);
        if(cmd_ret != STATUS_SUCCESS)
            break;

    } while (0);

    // Free memory
    free(pdh);
    free(cert_chain);

    return (int)cmd_ret;
}
