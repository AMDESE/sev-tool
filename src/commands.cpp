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

#include "amdcert.h"
#include "commands.h"
#include "crypto.h"
#include "sevcert.h"
#include "utilities.h"      // for WriteToFile
#include <openssl/hmac.h>   // for calc_measurement
#include <stdio.h>          // printf
#include <stdlib.h>         // malloc

Command::Command(void)
       : m_sev_device(&SEVDevice::get_sev_device())
{
    // Intentionally Empty
}

Command::Command(std::string output_folder, int verbose_flag, ccp_required_t ccp)
       : m_sev_device((ccp == CCP_REQ) ? &SEVDevice::get_sev_device() : NULL),
         m_output_folder(output_folder),
         m_verbose_flag(verbose_flag)
{
    // Intentionally Empty
}

Command::~Command(void)
{
    //delete m_sev_device;
}

int Command::factory_reset(void)
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->factory_reset();

    return (int)cmd_ret;
}

int Command::platform_status(void)
{
    uint8_t data[sizeof(sev_platform_status_cmd_buf)];
    sev_platform_status_cmd_buf *data_buf = (sev_platform_status_cmd_buf *)&data;
    int cmd_ret = -1;

    cmd_ret = m_sev_device->platform_status(data);

    if (cmd_ret == STATUS_SUCCESS) {
        // Print ID arrays
        printf("api_major:\t%d\n", data_buf->api_major);
        printf("api_minor:\t%d\n", data_buf->api_minor);
        printf("platform_state:\t%d\n", data_buf->current_platform_state);
        if (sev::min_api_version(data_buf->api_major, data_buf->api_minor, 0, 17)) {
            printf("owner:\t\t%d\n", data_buf->owner);
            printf("config:\t\t%d\n", data_buf->config);
        }
        else {
            printf("flags:\t\t%d\n",
                    ((data_buf->owner & PLAT_STAT_OWNER_MASK) << PLAT_STAT_OWNER_MASK) +
                    ((data_buf->config & PLAT_STAT_ES_MASK) << PLAT_STAT_CONFIGES_OFFSET));
        }
        printf("build:\t\t%d\n", data_buf->build_id);
        printf("guest_count:\t%d\n", data_buf->guest_count);
    }

    return (int)cmd_ret;
}

int Command::pek_gen(void)
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->pek_gen();

    return (int)cmd_ret;
}

int Command::pek_csr(void)
{
    uint8_t data[sizeof(sev_pek_csr_cmd_buf)];
    int cmd_ret = -1;

    // Populate PEKCSR buffer with CSRLength = 0
    sev_cert *pek_mem = new sev_cert_t;
    sev_cert pek_csr;

    if (!pek_mem)
        return -1;

    cmd_ret = m_sev_device->pek_csr(data, pek_mem, &pek_csr);

    if (cmd_ret == STATUS_SUCCESS) {
        if (m_verbose_flag) {            // Print off the cert to stdout
            // print_sev_cert_hex(&pek_csr);
            print_sev_cert_readable(&pek_csr);
        }
        if (m_output_folder != "") {     // Print off the cert to a text file
            std::string pek_csr_readable = "";
            std::string pek_csr_readable_path = m_output_folder+PEK_CSR_READABLE_FILENAME;
            std::string pek_csr_hex_path = m_output_folder+PEK_CSR_HEX_FILENAME;

            print_sev_cert_readable(&pek_csr, pek_csr_readable);
            sev::write_file(pek_csr_readable_path, (void *)pek_csr_readable.c_str(), pek_csr_readable.size());
            sev::write_file(pek_csr_hex_path, (void *)&pek_csr, sizeof(pek_csr));
        }
    }

    // Free memory
    delete pek_mem;

    return (int)cmd_ret;
}

int Command::pdh_gen(void)
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->pdh_gen();

    return (int)cmd_ret;
}

int Command::pdh_cert_export(void)
{
    uint8_t data[sizeof(sev_pdh_cert_export_cmd_buf)];
    int cmd_ret = -1;

    sev_cert *pdh_cert_mem = new sev_cert_t;
    sev_cert_chain_buf_t *cert_chain_mem = new sev_cert_chain_buf_t();

    if (!pdh_cert_mem || !cert_chain_mem)
        return -1;

    cmd_ret = m_sev_device->pdh_cert_export(data, pdh_cert_mem, cert_chain_mem);

    if (cmd_ret == STATUS_SUCCESS) {
        if (m_verbose_flag) {            // Print off the cert to stdout
            // print_sev_cert_readable((sev_cert *)pdh_cert_mem); printf("\n");
            print_sev_cert_hex((sev_cert *)pdh_cert_mem); printf("\n");
            print_cert_chain_buf_readable((sev_cert_chain_buf *)cert_chain_mem);
        }
        if (m_output_folder != "") {     // Print off the cert to a text file
            std::string PDH_readable = "";
            std::string cc_readable = "";
            std::string PDH_readable_path = m_output_folder+PDH_READABLE_FILENAME;
            std::string PDH_path          = m_output_folder+PDH_FILENAME;
            std::string cc_readable_path  = m_output_folder+CERT_CHAIN_READABLE_FILENAME;
            std::string cc_path           = m_output_folder+CERT_CHAIN_HEX_FILENAME;

            print_sev_cert_readable((sev_cert *)pdh_cert_mem, PDH_readable);
            print_cert_chain_buf_readable((sev_cert_chain_buf *)cert_chain_mem, cc_readable);
            sev::write_file(PDH_readable_path, (void *)PDH_readable.c_str(), PDH_readable.size());
            sev::write_file(PDH_path, pdh_cert_mem, sizeof(sev_cert));
            sev::write_file(cc_readable_path, (void *)cc_readable.c_str(), cc_readable.size());
            sev::write_file(cc_path, cert_chain_mem, sizeof(sev_cert_chain_buf));
        }
    }

    // Free memory
    delete pdh_cert_mem;
    delete cert_chain_mem;

    return (int)cmd_ret;
}

int Command::pek_cert_import(std::string signed_pek_csr_file, std::string oca_cert_file)
{
    int cmd_ret = -1;

    // Initial PDH cert chain export, so we can confirm that it
    // changed after running the pek_cert_import
    uint8_t pdh_cert_export_data[sizeof(sev_pdh_cert_export_cmd_buf)];  // pdh_cert_export
    sev_cert *pdh_cert_mem = new sev_cert_t;
    sev_cert_chain_buf *cert_chain_mem = new sev_cert_chain_buf_t;

    // The signed CSR
    sev_cert signed_pek_csr;
    sev_cert oca_cert;

    // Second PDH cert chain export for confirmation
    uint8_t pek_cert_import_data[sizeof(sev_pek_cert_import_cmd_buf)];  // pek_cert_import
    uint8_t pdh_cert_export_data2[sizeof(sev_pdh_cert_export_cmd_buf)]; // pdh_cert_export
    sev_cert *pdh_cert_mem2 = new sev_cert_t;
    sev_cert_chain_buf *cert_chain_mem2 = new sev_cert_chain_buf_t;

    do {
        if (!pdh_cert_mem || !cert_chain_mem || !pdh_cert_mem2 || !cert_chain_mem2) {
            cmd_ret = -1;
            break;
        }

        // Read in the signed pek_csr (has sev_cert format)
        if (sev::read_file(signed_pek_csr_file, &signed_pek_csr, sizeof(sev_cert)) != sizeof(sev_cert)) {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        // Read in the oca_cert
        if (sev::read_file(oca_cert_file, &oca_cert, sizeof(sev_cert)) != sizeof(sev_cert)) {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        cmd_ret = m_sev_device->set_self_owned();
        if (cmd_ret != 0)
            break;

        // Just used to confirm afterwards that the cert chain has changed
        cmd_ret = m_sev_device->pdh_cert_export(pdh_cert_export_data, pdh_cert_mem, cert_chain_mem);
        if (cmd_ret != 0)
            break;

        // Run the pek_cert_import command
        // Call validates signature against OCA
        cmd_ret = m_sev_device->pek_cert_import(pek_cert_import_data, &signed_pek_csr, &oca_cert);
        if (cmd_ret != 0)
            break;

        // Export the cert chain again, so we can compare that it has changed
        // after running the pek_cert_import
        cmd_ret = m_sev_device->pdh_cert_export(pdh_cert_export_data2, pdh_cert_mem2, cert_chain_mem2);
        if (cmd_ret != 0)
            break;

        // Make sure the cert chain changed after running the pek_cert_import
        if (0 != memcmp(pdh_cert_export_data2, pdh_cert_export_data, sizeof(sev_pdh_cert_export_cmd_buf)))
            break;

        printf("PEK Cert Import SUCCESS!!!\n");
    } while (0);

    // Free memory
    delete pdh_cert_mem;
    delete cert_chain_mem;
    delete pdh_cert_mem2;
    delete cert_chain_mem2;

    return (int)cmd_ret;
}

// Must always pass in 128 bytes array, because of Linux /dev/sev ioctl
// doesn't follow the API
int Command::get_id(void)
{
    uint8_t data[sizeof(sev_get_id_cmd_buf)];
    sev_get_id_cmd_buf *data_buf = (sev_get_id_cmd_buf *)&data;
    int cmd_ret = -1;
    uint32_t default_id_length = 0;

    // Send the first command with a length of 0, then use the returned length
    // as the input parameter for the 'real' command which will succeed
    sev_get_id_cmd_buf data_buf_temp;
    cmd_ret = m_sev_device->get_id((uint8_t *)&data_buf_temp, NULL); // Sets IDLength
    if (cmd_ret != ERROR_INVALID_LENGTH)     // What we expect to happen
        return cmd_ret;
    default_id_length = data_buf_temp.id_length;

    // Always allocate 2 ID's worth because Linux will always write 2 ID's worth.
    // If you have 1 ID and you are not in Linux, allocating extra is fine
    void *id_mem = malloc(2*default_id_length);
    if (!id_mem)
        return cmd_ret;

    cmd_ret = m_sev_device->get_id(data, id_mem, 2*default_id_length);

    if (cmd_ret == STATUS_SUCCESS) {
        char id0_buf[default_id_length*2+1] = {0};  // 2 chars per byte +1 for null term
        char id1_buf[default_id_length*2+1] = {0};
        for (uint8_t i = 0; i < default_id_length; i++) {
            sprintf(id0_buf+strlen(id0_buf), "%02x", ((uint8_t *)(data_buf->id_p_addr))[i]);
            sprintf(id1_buf+strlen(id1_buf), "%02x", ((uint8_t *)(data_buf->id_p_addr))[i+default_id_length]);
        }

        if (m_verbose_flag) {            // Print ID arrays
            printf("* GetID Socket0:\n%s", id0_buf);
            printf("\n* GetID Socket1:\n%s", id1_buf);
            printf("\n");
        }
        if (m_output_folder != "") {     // Print the IDs to a text file
            std::string id0_path = m_output_folder+GET_ID_S0_FILENAME;
            std::string id1_path = m_output_folder+GET_ID_S1_FILENAME;
            sev::write_file(id0_path, (void *)id0_buf, sizeof(id0_buf)-1);  // Don't write null term
            sev::write_file(id1_path, (void *)id1_buf, sizeof(id1_buf)-1);
        }
    }

    // Free memory
    free(id_mem);

    return (int)cmd_ret;
}

// ------------------------------------- //
// ---- Non-ioctl (Custom) commands ---- //
// ------------------------------------- //
int Command::sys_info(void)
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->sys_info();

    return (int)cmd_ret;
}

int Command::get_platform_owner(void)
{
    uint8_t data[sizeof(sev_platform_status_cmd_buf)];
    int cmd_ret = -1;

    cmd_ret = m_sev_device->platform_status(data);
    if (cmd_ret != STATUS_SUCCESS)
        return -1;

    return m_sev_device->get_platform_owner(data);
}

int Command::get_platform_es(void)
{
    uint8_t data[sizeof(sev_platform_status_cmd_buf)];
    int cmd_ret = -1;

    cmd_ret = m_sev_device->platform_status(data);
    if (cmd_ret != STATUS_SUCCESS)
        return -1;

    return m_sev_device->get_platform_es(data);
}

int Command::set_self_owned(void)
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->set_self_owned();

    return (int)cmd_ret;
}

int Command::set_externally_owned(std::string oca_priv_key_file)
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->set_externally_owned(oca_priv_key_file);

    return (int)cmd_ret;
}

int Command::generate_cek_ask(void)
{
    int cmd_ret = -1;

    std::string cert_file = CEK_FILENAME;

    cmd_ret = m_sev_device->generate_cek_ask(m_output_folder, cert_file);

    return (int)cmd_ret;
}

int Command::get_ask_ark(void)
{
    int cmd_ret = -1;

    std::string cert_file = ASK_ARK_FILENAME;

    cmd_ret = sev::get_ask_ark(m_output_folder, cert_file);

    return (int)cmd_ret;
}

int Command::generate_all_certs(void)
{
    int cmd_ret = -1;
    uint8_t pdh_cert_export_data[sizeof(sev_pdh_cert_export_cmd_buf)];  // pdh_cert_export
    sev_cert_t *pdh = new sev_cert_t;
    sev_cert_chain_buf *cert_chain = new sev_cert_chain_buf_t; // PEK, OCA, CEK
    amd_cert ask;
    amd_cert ark;

    std::string cek_file = CEK_FILENAME;
    std::string ask_ark_file = ASK_ARK_FILENAME;
    std::string ask_ark_full = m_output_folder + ASK_ARK_FILENAME;
    std::string pdh_full = m_output_folder + PDH_FILENAME;
    std::string pek_full = m_output_folder + PEK_FILENAME;
    std::string oca_full = m_output_folder + OCA_FILENAME;
    std::string cek_full = m_output_folder + CEK_FILENAME;
    std::string ask_full = m_output_folder + ASK_FILENAME;
    std::string ark_full = m_output_folder + ARK_FILENAME;
    AMDCert tmp_amd;
    std::string ask_string = ""; // For printing. AMD certs can't just print straight
    std::string ark_string = ""; // bytes because they're unions based on key sizes

    do {
        // Get the pdh Cert Chain (pdh and pek, oca, cek)
        cmd_ret = m_sev_device->pdh_cert_export(pdh_cert_export_data, pdh, cert_chain);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Generate the cek from the AMD KDS server
        cmd_ret = m_sev_device->generate_cek_ask(m_output_folder, cek_file);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Get the ask_ark from AMD dev site
        cmd_ret = sev::get_ask_ark(m_output_folder, ask_ark_file);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Read in the ask_ark so we can split it into 2 separate cert files
        uint8_t ask_ark_buf[sizeof(amd_cert)*2] = {0};
        if (sev::read_file(ask_ark_full, ask_ark_buf, sizeof(ask_ark_buf)) == 0)
            break;

        // Initialize the ask
        cmd_ret = tmp_amd.amd_cert_init(&ask, ask_ark_buf);
        if (cmd_ret != STATUS_SUCCESS)
            break;
        // print_amd_cert_readable(&ask);

        // Initialize the ark
        size_t ask_size = tmp_amd.amd_cert_get_size(&ask);
        cmd_ret = tmp_amd.amd_cert_init(&ark, (uint8_t *)(ask_ark_buf + ask_size));
        if (cmd_ret != STATUS_SUCCESS)
            break;
        // print_amd_cert_readable(&ark);

        // Write all certs to individual files
        // Note that the CEK in the cert chain is unsigned, so we want to use
        //   the one 'cached by the hypervisor' that's signed by the ask
        //   (the one from the AMD dev site)
        size_t ark_size = tmp_amd.amd_cert_get_size(&ark);
        if (sev::write_file(pdh_full, pdh, sizeof(sev_cert)) != sizeof(sev_cert))
            break;
        if (sev::write_file(pek_full, PEK_IN_CERT_CHAIN(cert_chain), sizeof(sev_cert)) != sizeof(sev_cert))
            break;
        if (sev::write_file(oca_full, OCA_IN_CERT_CHAIN(cert_chain), sizeof(sev_cert)) != sizeof(sev_cert))
            break;
        print_amd_cert_hex(&ask, ask_string);       // TODO refactor this
        print_amd_cert_hex(&ark, ark_string);
        uint8_t ask_binary[ask_size*2];
        uint8_t ark_binary[ark_size*2];
        sev::ascii_hex_bytes_to_binary(ask_binary, ask_string.c_str(), ask_size);
        sev::ascii_hex_bytes_to_binary(ark_binary, ark_string.c_str(), ark_size);
        if (sev::write_file(ask_full, ask_binary, ask_size) != ask_size)
            break;
        if (sev::write_file(ark_full, ark_binary, ark_size) != ark_size)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    // Free memory
    delete pdh;
    delete cert_chain;

    return (int)cmd_ret;
}

int Command::export_cert_chain(void)
{
    int cmd_ret = -1;
    std::string zip_name = CERTS_ZIP_FILENAME;
    std::string space = " ";
    std::string cert_names = m_output_folder + PDH_FILENAME + space +
                             m_output_folder + PEK_FILENAME + space +
                             m_output_folder + OCA_FILENAME + space +
                             m_output_folder + CEK_FILENAME + space +
                             m_output_folder + ASK_FILENAME + space +
                             m_output_folder + ARK_FILENAME;

    do {
        cmd_ret = generate_all_certs();
        if (cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = sev::zip_certs(m_output_folder, zip_name, cert_names);
    } while (0);
    return (int)cmd_ret;
}

// We cannot call LaunchMeasure to get the MNonce because that command doesn't
// exist in this context, so we read the user input params for all of our data
int Command::calculate_measurement(measurement_t *user_data, hmac_sha_256 *final_meas)
{
    int cmd_ret = ERROR_UNSUPPORTED;

    uint32_t measurement_length = sizeof(final_meas);

    // Create and initialize the context
    HMAC_CTX *ctx;
    if (!(ctx = HMAC_CTX_new()))
        return ERROR_BAD_MEASUREMENT;

    do {
        if (HMAC_Init_ex(ctx, user_data->tik, sizeof(user_data->tik), EVP_sha256(), NULL) != 1)
            break;
        if (sev::min_api_version(user_data->api_major, user_data->api_minor, 0, 17)) {
            if (HMAC_Update(ctx, &user_data->meas_ctx, sizeof(user_data->meas_ctx)) != 1)
                break;
            if (HMAC_Update(ctx, &user_data->api_major, sizeof(user_data->api_major)) != 1)
                break;
            if (HMAC_Update(ctx, &user_data->api_minor, sizeof(user_data->api_minor)) != 1)
                break;
            if (HMAC_Update(ctx, &user_data->build_id, sizeof(user_data->build_id)) != 1)
                break;
        }
        if (HMAC_Update(ctx, (uint8_t *)&user_data->policy, sizeof(user_data->policy)) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t *)&user_data->digest, sizeof(user_data->digest)) != 1)
            break;
        // Use the same random MNonce as the FW in our validation calculations
        if (HMAC_Update(ctx, (uint8_t *)&user_data->mnonce, sizeof(user_data->mnonce)) != 1)
            break;
        if (HMAC_Final(ctx, (uint8_t *)final_meas, &measurement_length) != 1)  // size = 32
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    HMAC_CTX_free(ctx);
    return cmd_ret;
}

int Command::calc_measurement(measurement_t *user_data)
{
    int cmd_ret = -1;
    hmac_sha_256 final_meas;

    cmd_ret = calculate_measurement(user_data, &final_meas);

    if (cmd_ret == STATUS_SUCCESS) {
        char meas_buf[sizeof(final_meas)*2+1] = {0}; // 2 chars per byte +1 for null term
        for (size_t i = 0; i < sizeof(final_meas); i++) {
            sprintf(meas_buf+strlen(meas_buf), "%02x", final_meas[i]);
        }
        std::string meas_str = meas_buf;

        if (m_verbose_flag) {          // Print ID arrays
            // Print input args for user
            printf("Input Arguments:\n");
            printf("   context: %02x\n", user_data->meas_ctx);
            printf("   Api Major: %02x\n", user_data->api_major);
            printf("   Api Minor: %02x\n", user_data->api_minor);
            printf("   Build ID: %02x\n", user_data->build_id);
            printf("   Policy: %02x\n", user_data->policy);
            printf("   Digest: ");
            for (size_t i = 0; i < sizeof(user_data->digest); i++) {
                printf("%02x", user_data->digest[i]);
            }
            printf("\n   MNonce: ");
            for (size_t i = 0; i < sizeof(user_data->mnonce); i++) {
                printf("%02x", user_data->mnonce[i]);
            }
            printf("\n   TIK: ");
            for (size_t i = 0; i < sizeof(user_data->tik); i++) {
                printf("%02x", user_data->tik[i]);
            }
            // Print output
            printf("\n\n%s\n", meas_str.c_str());
        }
        if (m_output_folder != "") {     // Print the IDs to a text file
            std::string meas_path = m_output_folder+CALC_MEASUREMENT_FILENAME;
            sev::write_file(meas_path, (void *)meas_str.c_str(), meas_str.size());
        }
    }

    return (int)cmd_ret;
}

int Command::import_all_certs(sev_cert *pdh, sev_cert *pek, sev_cert *oca,
                              sev_cert *cek, amd_cert *ask, amd_cert *ark)
{
    int cmd_ret = ERROR_INVALID_CERTIFICATE;
    AMDCert tmp_amd;
    std::string ark_full = m_output_folder + ARK_FILENAME;
    std::string ask_full = m_output_folder + ASK_FILENAME;
    std::string cek_full = m_output_folder + CEK_FILENAME;
    std::string oca_full = m_output_folder + OCA_FILENAME;
    std::string pek_full = m_output_folder + PEK_FILENAME;
    std::string pdh_full = m_output_folder + PDH_FILENAME;

    do {
        // Read in the ark
        uint8_t ark_buf[sizeof(amd_cert)] = {0};
        if (sev::read_file(ark_full, ark_buf, sizeof(amd_cert)) == 0) // Variable size
            break;

        // Initialize the ark
        cmd_ret = tmp_amd.amd_cert_init(ark, ark_buf);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Read in the ark
        uint8_t ask_buf[sizeof(amd_cert)] = {0};
        if (sev::read_file(ask_full, ask_buf, sizeof(amd_cert)) == 0) // Variable size
            break;

        // Initialize the ark
        cmd_ret = tmp_amd.amd_cert_init(ask, ask_buf);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Read in the cek
        if (sev::read_file(cek_full, cek, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Read in the oca
        if (sev::read_file(oca_full, oca, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Read in the pek
        if (sev::read_file(pek_full, pek, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Read in the pdh
        if (sev::read_file(pdh_full, pdh, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return (int)cmd_ret;
}

int Command::validate_cert_chain(void)
{
    int cmd_ret = -1;
    sev_cert pdh;
    sev_cert pek;
    sev_cert oca;
    sev_cert cek;
    amd_cert ask;
    amd_cert ark;

    sev_cert ask_pubkey;

    do {
        cmd_ret = import_all_certs(&pdh, &pek, &oca, &cek, &ask, &ark);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Temp structs because they are class functions
        SEVCert tmp_sev_cek(&cek);   // Pass in child cert in constructor
        SEVCert tmp_sev_pek(&pek);
        SEVCert tmp_sev_pdh(&pdh);
        AMDCert tmp_amd;

        // Validate the ARK
        cmd_ret = tmp_amd.amd_cert_validate_ark(&ark);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the ASK
        cmd_ret = tmp_amd.amd_cert_validate_ask(&ask, &ark);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Export the ASK to an AMD cert public key
        // The verify_sev_cert function takes in a parent of an sev_cert not
        //   an amd_cert, so need to pull the pubkey out of the amd_cert and
        //   place it into a tmp sev_cert to help validate the cek
        cmd_ret = tmp_amd.amd_cert_export_pub_key(&ask, &ask_pubkey);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the CEK
        cmd_ret = tmp_sev_cek.verify_sev_cert(&ask_pubkey);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the PEK with the CEK and OCA
        cmd_ret = tmp_sev_pek.verify_sev_cert(&cek, &oca);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Validate the PDH
        cmd_ret = tmp_sev_pdh.verify_sev_cert(&pek);
        if (cmd_ret != STATUS_SUCCESS)
            break;
    } while (0);

    return (int)cmd_ret;
}

int Command::generate_launch_blob(uint32_t policy)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    sev_session_buf session_data_buf;
    std::string buf_file = m_output_folder + LAUNCH_BLOB_FILENAME;
    sev_cert pdh;
    EVP_PKEY *godh_key_pair = NULL;      // Guest Owner Diffie-Hellman
    sev_cert godh_pubkey_cert;

    memset(&session_data_buf, 0, sizeof(sev_session_buf));

    do {
        // Read in the PDH (Platform Diffie-Hellman Public Key)
        std::string pdh_full = m_output_folder+PDH_FILENAME;
        if (sev::read_file(pdh_full, &pdh, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Launch Start needs the GODH Pubkey as a cert, so need to create it
        SEVCert cert_obj(&godh_pubkey_cert);

        // Generate a new GODH Public/Private keypair
        if (!generate_ecdh_key_pair(&godh_key_pair)) {
            printf("Error generating new GODH ECDH keypair\n");
            break;
        }

        // This cert is really just a way to send over the godh public key,
        // so the api major/minor don't matter here
        if (!cert_obj.create_godh_cert(&godh_key_pair, 0, 0)) {
            printf("Error creating GODH certificate\n");
            break;
        }

        // Write the cert to file
        std::string godh_cert_file = m_output_folder + GUEST_OWNER_DH_FILENAME;
        if (sev::write_file(godh_cert_file, &godh_pubkey_cert, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        cmd_ret = build_session_buffer(&session_data_buf, policy, godh_key_pair, &pdh);
        if (cmd_ret == STATUS_SUCCESS) {
            if (m_verbose_flag) {
                printf("Guest Policy (input): %08x\n", policy);
                printf("nonce:\n");
                for (size_t i = 0; i < sizeof(session_data_buf.nonce); i++) {
                    printf("%02x ", session_data_buf.nonce[i]);
                }
                printf("\nWrapTK TEK:\n");
                for (size_t i = 0; i < sizeof(session_data_buf.wrap_tk.tek); i++) {
                    printf("%02x ", session_data_buf.wrap_tk.tek[i]);
                }
                printf("\nWrapTK TIK:\n");
                for (size_t i = 0; i < sizeof(session_data_buf.wrap_tk.tik); i++) {
                    printf("%02x ", session_data_buf.wrap_tk.tik[i]);
                }
                printf("\nWrapIV:\n");
                for (size_t i = 0; i < sizeof(session_data_buf.wrap_iv); i++) {
                    printf("%02x ", session_data_buf.wrap_iv[i]);
                }
                printf("\nWrapMAC:\n");
                for (size_t i = 0; i < sizeof(session_data_buf.wrap_mac); i++) {
                    printf("%02x ", session_data_buf.wrap_mac[i]);
                }
                printf("\nPolicyMAC:\n");
                for (size_t i = 0; i < sizeof(session_data_buf.policy_mac); i++) {
                    printf("%02x ", session_data_buf.policy_mac[i]);
                }
                printf("\n");
            }

            // Write the unencrypted TK (TIK and TEK) to a tmp file so it can be
            // read in during package_secret
            std::string tmp_tk_file = m_output_folder + GUEST_TK_FILENAME;
            sev::write_file(tmp_tk_file, &m_tk, sizeof(m_tk));

            sev::write_file(buf_file, (void *)&session_data_buf, sizeof(sev_session_buf));
        }
    } while (0);

    return (int)cmd_ret;
}

int Command::package_secret(void)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    sev_hdr_buf packaged_secret_header;
    std::string tmp_tk_file = m_output_folder + GUEST_TK_FILENAME;
    std::string secret_file = m_output_folder + SECRET_FILENAME;
    std::string pek_file = m_output_folder + PEK_FILENAME;
    std::string packaged_secret_file = m_output_folder + PACKAGED_SECRET_FILENAME;
    std::string packaged_secret_header_file = m_output_folder + PACKAGED_SECRET_HEADER_FILENAME;
    sev_cert pek;

    uint32_t flags = 0;
    iv_128 iv;
    sev::gen_random_bytes(&iv, sizeof(iv));     // Pick a random IV

    do {
        // Get the size of the secret, so we can allocate that much memory
        size_t secret_size = sev::get_file_size(secret_file);
        if (secret_size < 8) {
            printf("Error: SEV requires a secret greater than 8 bytes\n");
            break;
        }
        uint8_t secret_mem[secret_size];
        uint8_t encrypted_mem[secret_size];

        // Read in the secret
        // printf("Attempting to read in Secrets file\n");
        if (sev::read_file(secret_file, secret_mem, secret_size) != secret_size)
            break;

        // Read in the blob to import the TEK
        // printf("Attempting to read in LaunchBlob file to import TEK\n");
        if (sev::read_file(pek_file, &pek, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Read in the unencrypted TK (TIK and TEK) created in build_session_buffer
        if (sev::read_file(tmp_tk_file, &m_tk, sizeof(m_tk)) != sizeof(m_tk)) {
            printf("Error reading in %s\n", tmp_tk_file.c_str());
            break;
        }

        // Encrypt the secret with the TEK
        encrypt_with_tek(encrypted_mem, secret_mem, secret_size, iv);

        if (m_verbose_flag) {
            printf("Random IV\n");
            for (size_t i = 0; i < sizeof(iv); i++) {
                printf("%02x ", iv[i]);
            }
            printf("\n");
        }

        // Read in the measurement, to be used as part of the launch secret header hmac
        std::string measurement_file = m_output_folder + CALC_MEASUREMENT_FILENAME;
        if (sev::read_file(measurement_file, &m_measurement, sizeof(m_measurement)) != sizeof(m_measurement)) {
            printf("Error reading in %s\n", measurement_file.c_str());
            break;
        }

        // Write the encrypted secret to a file
        sev::write_file(packaged_secret_file, encrypted_mem, secret_size);

        // Set up the Launch_Secret packet header
        if (!create_launch_secret_header(&packaged_secret_header, &iv, encrypted_mem,
                                        sizeof(encrypted_mem), flags, pek.api_major, pek.api_minor)) {
            break;
        }

        // Write the header to a file
        sev::write_file(packaged_secret_header_file, &packaged_secret_header, sizeof(packaged_secret_header));

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return (int)cmd_ret;
}

int Command::sign_pek_csr(std::string pek_csr_file, std::string oca_priv_key_file)
{
    int cmd_ret = ERROR_UNSUPPORTED;

    EVP_PKEY *oca_priv_key = NULL;
    sev_cert oca_cert;
    SEVCert cert_obj(&oca_cert);
    sev_cert pek_csr;

    std::string pek_oca_path = m_output_folder + OCA_FILENAME;
    std::string pek_csr_signed_path = m_output_folder + SIGNED_PEK_CSR_FILENAME;

    do {
        // Read in the pek_csr (has sev_cert format)
        if (sev::read_file(pek_csr_file, &pek_csr, sizeof(sev_cert)) != sizeof(sev_cert)) {
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }
        SEVCert csr_obj(&pek_csr);
        if(csr_obj.verify_pek_csr() != STATUS_SUCCESS){
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        // Import the OCA pem file and turn it into an sev_cert
        if (!read_priv_key_pem_into_evpkey(oca_priv_key_file, &oca_priv_key)) {
            printf("Error importing OCA Priv Key\n");
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }
        if (!cert_obj.create_oca_cert(&oca_priv_key, SEV_SIG_ALGO_ECDSA_SHA256)) {
            printf("Error creating OCA cert\n");
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        // Sign CSR
        // TODO it is possible to validate CSR (no other fields set apart from cert, API and usage itself)
        SEVCert CSRCert(&pek_csr);
        if(!CSRCert.sign_with_key(SEV_CERT_MAX_VERSION, SEV_USAGE_PEK, SEV_SIG_ALGO_ECDSA_SHA256,
                              &oca_priv_key, SEV_USAGE_OCA, SEV_SIG_ALGO_ECDSA_SHA256)) {
            printf("Error self-signing OCA cert.\n");
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        // Verify signature
        cmd_ret = CSRCert.verify_signed_pek_csr((const sev_cert *) &oca_cert);
        if (cmd_ret != STATUS_SUCCESS) {
            printf("Error created signature could not be validated with OCA cert.\n");
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }
        sev::write_file(pek_oca_path, (void *)&oca_cert, sizeof(oca_cert));
        sev::write_file(pek_csr_signed_path, (void *)&pek_csr, sizeof(pek_csr));
        cmd_ret = STATUS_SUCCESS;
    } while (0);
    // TODO free oca_priv_key somehow...
    EVP_PKEY_free(oca_priv_key);
    return cmd_ret;
}

// --------------------------------------------------------------- //
// ---------------- generate_launch_blob functions --------------- //
// --------------------------------------------------------------- //
/*
 * NIST Compliant KDF
 */
bool Command::kdf(uint8_t *key_out,       size_t key_out_length,
                  const uint8_t *key_in,  size_t key_in_length,
                  const uint8_t *label,   size_t label_length,
                  const uint8_t *context, size_t context_length)
{
    if (!key_out || !key_in || !label || (key_out_length == 0) ||
       (key_in_length == 0) || (label_length == 0))
        return false;

    bool cmd_ret = false;
    uint8_t null_byte = '\0';
    unsigned int out_len = 0;
    uint8_t prf_out[NIST_KDF_H_BYTES];      // Buffer to collect PRF output

    // length in bits of derived key
    uint32_t l = (uint32_t)(key_out_length * BITS_PER_BYTE);

    // number of iterations to produce enough derived key bits
    uint32_t n = ((l - 1) / NIST_KDF_H) + 1;

    size_t bytes_left = key_out_length;
    uint32_t offset = 0;

    // Create and initialize the context
    HMAC_CTX *ctx;
    if (!(ctx = HMAC_CTX_new()))
        return cmd_ret;

    for (unsigned int i = 1; i <= n; i++)
    {
        if (HMAC_CTX_reset(ctx) != 1)
            break;

        // calculate a chunk of random data from the PRF
        if (HMAC_Init_ex(ctx, key_in, (int)key_in_length, EVP_sha256(), NULL) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t *)&i, sizeof(i)) != 1)
            break;
        if (HMAC_Update(ctx, (unsigned char*)label, label_length) != 1)
            break;
        if (HMAC_Update(ctx, &null_byte, sizeof(null_byte)) != 1)
            break;
        if ((context) && (context_length != 0)) {
            if (HMAC_Update(ctx, (unsigned char*)context, context_length) != 1)
                break;
        }
        if (HMAC_Update(ctx, (uint8_t *)&l, sizeof(l)) != 1)
            break;
        if (HMAC_Final(ctx, prf_out, &out_len) != 1)
            break;

        // Write out the key bytes
        if (bytes_left <= NIST_KDF_H_BYTES) {
            memcpy(key_out + offset, prf_out, bytes_left);
        }
        else {
            memcpy(key_out + offset, prf_out, NIST_KDF_H_BYTES);
            offset     += NIST_KDF_H_BYTES;
            bytes_left -= NIST_KDF_H_BYTES;
        }

        if (i == n)          // If successfully finished all iterations
            cmd_ret = true;
    }

    HMAC_CTX_free(ctx);
    return cmd_ret;
}

/*
 * Note that this function NEWs/allocates memory for a
 * uint8_t array using OPENSSL_malloc that must be freed
 * in the calling function using OPENSSL_FREE()
 */
uint8_t * Command::calculate_shared_secret(EVP_PKEY *priv_key, EVP_PKEY *peer_key,
                                           size_t& shared_key_len_out)
{
    if (!priv_key || !peer_key)
        return NULL;

    bool success = false;
    EVP_PKEY_CTX *ctx = NULL;
    uint8_t *shared_key = NULL;

    do {
        // Create the context using your private key
        if (!(ctx = EVP_PKEY_CTX_new(priv_key, NULL)))
            break;

        // Calculate the intermediate secret
        if (EVP_PKEY_derive_init(ctx) <= 0)
            break;
        if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
            break;

        // Determine buffer length
        if (EVP_PKEY_derive(ctx, NULL, &shared_key_len_out) <= 0)
            break;

        // Need to free shared_key using OPENSSL_FREE() in the calling function
        shared_key = (unsigned char*)OPENSSL_malloc(shared_key_len_out);
        if (!shared_key)
            break;      // malloc failure

        // Compute the shared secret with the ECDH key material.
        if (EVP_PKEY_derive(ctx, shared_key, &shared_key_len_out) <= 0)
            break;

        success = true;
    } while (0);

    EVP_PKEY_CTX_free(ctx);

    return success ? shared_key : NULL;
}

/*
 * Generate a master_secret value from our (test suite) Private DH key,
 *   the Platform's public DH key, and a nonce
 * This function calls two functions (above) which allocate memory
 *   for keys, and this function must free that memory
 */
bool Command::derive_master_secret(aes_128_key master_secret,
                                   EVP_PKEY *godh_priv_key,
                                   const sev_cert *pdh_public,
                                   const uint8_t nonce[sizeof(nonce_128)])
{
    if (!godh_priv_key || !pdh_public)
        return false;

    sev_cert dummy;
    memset(&dummy, 0, sizeof(sev_cert));    // To remove compile warnings
    SEVCert temp_obj(&dummy);               // TODO. Hack b/c just want to call function later
    bool ret = false;
    EVP_PKEY *plat_pub_key = NULL;    // Platform public key
    size_t shared_key_len = 0;

    do {
        // New up the Platform's public EVP_PKEY
        if (!(plat_pub_key = EVP_PKEY_new()))
            break;

        // Get the friend's Public EVP_PKEY from the certificate
        // This function allocates memory and attaches an EC_Key
        //  to your EVP_PKEY so, to prevent mem leaks, make sure
        //  the EVP_PKEY is freed at the end of this function
        if (temp_obj.compile_public_key_from_certificate(pdh_public, plat_pub_key) != STATUS_SUCCESS)
            break;

        // Calculate the shared secret
        // This function is allocating memory for this uint8_t[],
        //  must free it at the end of this function
        uint8_t *shared_key = calculate_shared_secret(godh_priv_key, plat_pub_key, shared_key_len);
        if (!shared_key)
            break;

        // Derive the master secret from the intermediate secret
        if (!kdf((unsigned char*)master_secret, sizeof(aes_128_key), shared_key,
            shared_key_len, (uint8_t *)SEV_MASTER_SECRET_LABEL,
            sizeof(SEV_MASTER_SECRET_LABEL)-1, nonce, sizeof(nonce_128))) // sizeof(nonce), bad?
            break;

        // Free memory allocated in calculate_shared_secret
        OPENSSL_free(shared_key);    // Local variable

        ret = true;
    } while (0);

    // Free memory
    EVP_PKEY_free(plat_pub_key);

    return ret;
}

bool Command::derive_kek(aes_128_key kek, const aes_128_key master_secret)
{
    bool ret = kdf((unsigned char*)kek, sizeof(aes_128_key), master_secret, sizeof(aes_128_key),
                   (uint8_t *)SEV_KEK_LABEL, sizeof(SEV_KEK_LABEL)-1, NULL, 0);
    return ret;
}

bool Command::derive_kik(hmac_key_128 kik, const aes_128_key master_secret)
{
    bool ret = kdf((unsigned char*)kik, sizeof(aes_128_key), master_secret, sizeof(aes_128_key),
                   (uint8_t *)SEV_KIK_LABEL, sizeof(SEV_KIK_LABEL)-1, NULL, 0);
    return ret;
}

bool Command::gen_hmac(hmac_sha_256 *out, hmac_key_128 key, uint8_t *msg, size_t msg_len)
{
    if (!out || !msg)
        return false;

    unsigned int out_len = 0;
    HMAC(EVP_sha256(), key, sizeof(hmac_key_128), msg,    // Returns NULL or value of out
         msg_len, (uint8_t *)out, &out_len);

    if ((out != NULL) && (out_len == sizeof(hmac_sha_256)))
        return true;
    else
        return false;
}

/*
 * AES128 Encrypt a buffer
 */
bool Command::encrypt(uint8_t *out, const uint8_t *in, size_t length,
                      const aes_128_key Key, const iv_128 IV)
{
    if (!out || !in)
        return false;

    EVP_CIPHER_CTX *ctx;
    int len = 0;
    bool cmd_ret = false;

    do {
        // Create and initialize the context
        if (!(ctx = EVP_CIPHER_CTX_new()))
            break;

        // Initialize the encryption operation. IMPORTANT - ensure you
        // use a key and IV size appropriate for your cipher
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, Key, IV) != 1)
            break;

        // Provide the message to be encrypted, and obtain the encrypted output
        if (EVP_EncryptUpdate(ctx, out, &len, in, (int)length) != 1)
            break;

        // Finalize the encryption. Further out bytes may be written at
        // this stage
        if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1)
            break;

        cmd_ret = true;
    } while (0);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return cmd_ret;
}

int Command::build_session_buffer(sev_session_buf *buf, uint32_t guest_policy,
                                  EVP_PKEY *godh_priv_key, sev_cert *pdh_pub)
{
    int cmd_ret = -1;

    aes_128_key master_secret;
    nonce_128 nonce;
    aes_128_key kek;
    hmac_key_128 kik;
    iv_128 iv;
    tek_tik wrap_tk;
    hmac_sha_256 wrap_mac;
    hmac_sha_256 policy_mac;

    do {
        // Generate a random nonce
        sev::gen_random_bytes(nonce, sizeof(nonce_128));

        // Derive Master Secret
        if (!derive_master_secret(master_secret, godh_priv_key, pdh_pub, nonce))
            break;

        // Derive the KEK and KIK
        if (!derive_kek(kek, master_secret))
            break;
        if (!derive_kik(kik, master_secret))
            break;

        // Generate a random TEK and TIK. Combine in to TK. Wrap.
        // Preserve TK for use in LAUNCH_MEASURE and LAUNCH_SECRET
        sev::gen_random_bytes(m_tk.tek, sizeof(m_tk.tek));
        sev::gen_random_bytes(m_tk.tik, sizeof(m_tk.tik));

        // Create an IV and wrap the TK with KEK and IV
        sev::gen_random_bytes(iv, sizeof(iv_128));
        if (!encrypt((uint8_t *)&wrap_tk, (uint8_t *)&m_tk, sizeof(m_tk), kek, iv))
            break;

        // Generate the HMAC for the wrap_tk
        if (!gen_hmac(&wrap_mac, kik, (uint8_t *)&wrap_tk, sizeof(wrap_tk)))
            break;

        // Generate the HMAC for the Policy bits
        if (!gen_hmac(&policy_mac, m_tk.tik, (uint8_t *)&guest_policy, sizeof(guest_policy)))
            break;

        // Copy everything to the session data buffer
        memcpy(&buf->nonce, &nonce, sizeof(buf->nonce));
        memcpy(&buf->wrap_tk, &wrap_tk, sizeof(buf->wrap_tk));
        memcpy(&buf->wrap_iv, &iv, sizeof(buf->wrap_iv));
        memcpy(&buf->wrap_mac, &wrap_mac, sizeof(buf->wrap_mac));
        memcpy(&buf->policy_mac, &policy_mac, sizeof(buf->policy_mac));

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    return cmd_ret;
}

// --------------------------------------------------------------- //
// ------------------- package_secret functions ------------------ //
// --------------------------------------------------------------- //
/*
 * Used in Launch_Secret to encrypt the transfer data with the TEK
 */
int Command::encrypt_with_tek(uint8_t *encrypted_mem, const uint8_t *secret_mem,
                              size_t secret_mem_size, const iv_128 iv)
{
    return encrypt(encrypted_mem, secret_mem, secret_mem_size, m_tk.tek, iv); // AES-128-CTR
}

bool Command::create_launch_secret_header(sev_hdr_buf *out_header, iv_128 *iv,
                                          uint8_t *buf, size_t buffer_len,
                                          uint32_t hdr_flags, uint8_t api_major, uint8_t api_minor)
{
    bool ret = false;

    // Note: API <= 0.16 and older does LaunchSecret differently than Naples API >= 0.17
    const uint8_t meas_ctx = 0x01;
    sev_hdr_buf header;
    uint32_t measurement_length = sizeof(header.mac);
    const uint32_t buf_len = (uint32_t)buffer_len;

    memcpy(header.iv, iv, sizeof(iv_128));
    header.flags = hdr_flags;

    // Create and initialize the context
    HMAC_CTX *ctx;
    if (!(ctx = HMAC_CTX_new()))
        return ret;

    do {
        if (HMAC_Init_ex(ctx, m_tk.tik, sizeof(m_tk.tik), EVP_sha256(), NULL) != 1)
            break;
        if (HMAC_Update(ctx, &meas_ctx, sizeof(meas_ctx)) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t *)&header.flags, sizeof(header.flags)) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t *)&header.iv, sizeof(header.iv)) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t *)&buf_len, sizeof(buf_len)) != 1) // Guest Length
            break;
        if (HMAC_Update(ctx, (uint8_t *)&buf_len, sizeof(buf_len)) != 1) // Trans Length
            break;
        if (HMAC_Update(ctx, buf, buf_len) != 1)                        // Data
            break;
        if (sev::min_api_version(api_major, api_minor, 0, 17)) {
            if (HMAC_Update(ctx, m_measurement, sizeof(m_measurement)) != 1) // Measure
                break;
        }
        if (HMAC_Final(ctx, (uint8_t *)&header.mac, &measurement_length) != 1)
            break;

        memcpy(out_header, &header, sizeof(sev_hdr_buf));
        ret = true;
    } while (0);

    HMAC_CTX_free(ctx);

    return ret;
}
