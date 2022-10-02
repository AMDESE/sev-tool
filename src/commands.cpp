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
#include "rmp.h"
#include "sevcert.h"
#include "utilities.h"      // for WriteToFile
#include "x509cert.h"
#include <openssl/hmac.h>   // for calc_measurement
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <cstdio>          // printf
#include <cstdlib>         // malloc
#include <memory>
#include <utility>

Command::Command()
       : m_sev_device(&SEVDevice::get_sev_device())
{
    // Intentionally Empty
}

Command::Command(std::string output_folder, int verbose_flag, ccp_required_t ccp)
       : m_sev_device((ccp == CCP_REQ) ? &SEVDevice::get_sev_device() : nullptr),
         m_output_folder(std::move(output_folder)),
         m_verbose_flag(verbose_flag)
{
    // Intentionally Empty
}

Command::~Command()
{
    //delete m_sev_device;
}

int Command::factory_reset()
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->factory_reset();

    return (int)cmd_ret;
}

int Command::platform_status()
{
    sev_platform_status_cmd_buf data;
    int cmd_ret = -1;

    cmd_ret = m_sev_device->platform_status(reinterpret_cast<uint8_t *>(&data));

    if (cmd_ret == STATUS_SUCCESS) {
        // Print ID arrays
        printf("api_major:\t%d\n", data.api_major);
        printf("api_minor:\t%d\n", data.api_minor);
        printf("platform_state:\t%d\n", data.current_platform_state);
        if (sev::min_api_version(data.api_major, data.api_minor, 0, 17)) {
            printf("owner:\t\t%d\n", data.owner);
            printf("config:\t\t%d\n", data.config);
        }
        else {
            printf("flags:\t\t%d\n",
                    ((data.owner & PLAT_STAT_OWNER_MASK) << PLAT_STAT_OWNER_MASK) +
                    ((data.config & PLAT_STAT_ES_MASK) << PLAT_STAT_CONFIGES_OFFSET));
        }
        printf("build:\t\t%d\n", data.build_id);
        printf("guest_count:\t%d\n", data.guest_count);
    }

    return (int)cmd_ret;
}

int Command::pek_gen()
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->pek_gen();

    return (int)cmd_ret;
}

int Command::pek_csr()
{
    sev_platform_status_cmd_buf data_buf;
    std::array<uint8_t, sizeof(sev_pek_csr_cmd_buf)> data{};
    int cmd_ret = -1;
    std::string pek_csr_readable_path = m_output_folder + PEK_CSR_READABLE_FILENAME;
    std::string pek_csr_hex_path = m_output_folder + PEK_CSR_HEX_FILENAME;

    // Populate PEKCSR buffer with CSRLength = 0
    auto pek_mem = std::make_unique<sev_cert_t>();
    sev_cert pek_csr;

    if (!pek_mem)
        return -1;

    cmd_ret = m_sev_device->platform_status(reinterpret_cast<uint8_t *>(&data_buf));

    if (cmd_ret != STATUS_SUCCESS) {
            return cmd_ret;
    }
    if (data_buf.owner != PLATFORM_STATUS_OWNER_SELF) {
            printf("Error: Platform must be self-owned first for the obtaining ownership procedure to work.");
            return -1;
    }

    cmd_ret = m_sev_device->pek_csr(data.data(), pek_mem.get(), &pek_csr);

    if (cmd_ret == STATUS_SUCCESS) {
        if (m_verbose_flag) {            // Print off the cert to stdout
            // print_sev_cert_hex(&pek_csr);
            print_sev_cert_readable(&pek_csr);
        }
        if (m_output_folder != "") {     // Print off the cert to a text file
            std::string pek_csr_readable = "";

            print_sev_cert_readable(&pek_csr, pek_csr_readable);
            sev::write_file(pek_csr_readable_path, (void *)pek_csr_readable.c_str(), pek_csr_readable.size());
            sev::write_file(pek_csr_hex_path, (void *)&pek_csr, sizeof(pek_csr));
        }
    }

    return (int)cmd_ret;
}

int Command::pdh_gen()
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->pdh_gen();

    return (int)cmd_ret;
}

int Command::pdh_cert_export()
{
    sev_pdh_cert_export_cmd_buf data;
    int cmd_ret = -1;
    std::string PDH_readable_path = m_output_folder + PDH_READABLE_FILENAME;
    std::string PDH_path          = m_output_folder + PDH_FILENAME;
    std::string cc_readable_path  = m_output_folder + CERT_CHAIN_READABLE_FILENAME;
    std::string cc_path           = m_output_folder + CERT_CHAIN_HEX_FILENAME;

    auto pdh_cert_mem = std::make_unique<sev_cert_t>();
    auto cert_chain_mem = std::make_unique<sev_cert_chain_buf_t>();

    if (!pdh_cert_mem || !cert_chain_mem)
        return -1;

    cmd_ret = m_sev_device->pdh_cert_export(reinterpret_cast<uint8_t *>(&data), pdh_cert_mem.get(), cert_chain_mem.get());

    if (cmd_ret == STATUS_SUCCESS) {
        if (m_verbose_flag) {            // Print off the cert to stdout
            // print_sev_cert_readable((sev_cert *)pdh_cert_mem); printf("\n");
            print_sev_cert_hex(pdh_cert_mem.get()); printf("\n");
            print_cert_chain_buf_readable(cert_chain_mem.get());
        }
        if (m_output_folder != "") {     // Print off the cert to a text file
            std::string PDH_readable = "";
            std::string cc_readable = "";

            print_sev_cert_readable(pdh_cert_mem.get(), PDH_readable);
            print_cert_chain_buf_readable(cert_chain_mem.get(), cc_readable);
            sev::write_file(PDH_readable_path, (void *)PDH_readable.c_str(), PDH_readable.size());
            sev::write_file(PDH_path, pdh_cert_mem.get(), sizeof(sev_cert));
            sev::write_file(cc_readable_path, (void *)cc_readable.c_str(), cc_readable.size());
            sev::write_file(cc_path, cert_chain_mem.get(), sizeof(sev_cert_chain_buf));
        }
    }

    return (int)cmd_ret;
}

int Command::pek_cert_import(std::string signed_pek_csr_file, std::string oca_cert_file)
{
    int cmd_ret = -1;

    // Initial PDH cert chain export, so we can confirm that it
    // changed after running the pek_cert_import
    sev_pdh_cert_export_cmd_buf pdh_cert_export_data;  // pdh_cert_export
    auto pdh_cert_mem = std::make_unique<sev_cert_t>();
    auto cert_chain_mem = std::make_unique<sev_cert_chain_buf_t>();

    // The signed CSR
    sev_cert signed_pek_csr;
    sev_cert oca_cert;

    // The actual pek_cert_import command
    sev_pek_cert_import_cmd_buf pek_cert_import_data{};  // pek_cert_import

    // Afterwards PDH cert chain export, to verify that the certs
    // have changed after running pek_cert_import
    sev_pdh_cert_export_cmd_buf pdh_cert_export_data2{}; // pdh_cert_export
    auto pdh_cert_mem2 = std::make_unique<sev_cert_t>();
    auto cert_chain_mem2 = std::make_unique<sev_cert_chain_buf_t>();

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

        // Just used to confirm afterwards that the cert chain has changed
        cmd_ret = m_sev_device->pdh_cert_export(reinterpret_cast<uint8_t *>(&pdh_cert_export_data), pdh_cert_mem.get(), cert_chain_mem.get());
        if (cmd_ret != 0)
            break;

        // Run the pek_cert_import command
        cmd_ret = m_sev_device->pek_cert_import(reinterpret_cast<uint8_t *>(&pek_cert_import_data), &signed_pek_csr, &oca_cert);
        if (cmd_ret != 0)
            break;

        // Export the cert chain again, so we can compare that it has changed
        // after running the pek_cert_import
        cmd_ret = m_sev_device->pdh_cert_export(reinterpret_cast<uint8_t *>(&pdh_cert_export_data2), pdh_cert_mem2.get(), cert_chain_mem2.get());
        if (cmd_ret != 0)
            break;

        // Make sure the cert chain changed after running the pek_cert_import
        if (0 != memcmp(&pdh_cert_export_data2, &pdh_cert_export_data, sizeof(pdh_cert_export_data)))
            break;

        printf("PEK Cert Import SUCCESS.\n");
    } while (false);

    return (int)cmd_ret;
}

int Command::sign_pek_csr(std::string pek_csr_file, std::string oca_priv_key_file)
{
    int cmd_ret = ERROR_UNSUPPORTED;

    EVP_PKEY *oca_priv_key = nullptr;
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
        if (csr_obj.validate_pek_csr() != STATUS_SUCCESS) {
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
        if (!csr_obj.sign_with_key(SEV_CERT_MAX_VERSION, SEV_USAGE_PEK, SEV_SIG_ALGO_ECDSA_SHA256,
                              &oca_priv_key, SEV_USAGE_OCA, SEV_SIG_ALGO_ECDSA_SHA256)) {
            printf("Error self-signing OCA cert.\n");
            cmd_ret = ERROR_INVALID_CERTIFICATE;
            break;
        }

        sev::write_file(pek_oca_path, (void *)&oca_cert, sizeof(oca_cert));
        sev::write_file(pek_csr_signed_path, (void *)&pek_csr, sizeof(pek_csr));
        cmd_ret = STATUS_SUCCESS;
    } while (false);
    EVP_PKEY_free(oca_priv_key);
    return cmd_ret;
}

// Must always pass in 128 bytes array, because of Linux /dev/sev ioctl
// doesn't follow the API
int Command::get_id()
{
    sev_get_id_cmd_buf data{};
    int cmd_ret = -1;
    uint32_t default_id_length = 0;
    std::string id0_path = m_output_folder + GET_ID_S0_FILENAME;
    std::string id1_path = m_output_folder + GET_ID_S1_FILENAME;

    // Send the first command with a length of 0, then use the returned length
    // as the input parameter for the 'real' command which will succeed
    sev_get_id_cmd_buf data_buf_temp;
    cmd_ret = m_sev_device->get_id(reinterpret_cast<uint8_t *>(&data_buf_temp), nullptr); // Sets IDLength
    if (cmd_ret != ERROR_INVALID_LENGTH)     // What we expect to happen
        return cmd_ret;
    default_id_length = data_buf_temp.id_length;

    // Always allocate 2 ID's worth because Linux will always write 2 ID's worth.
    // If you have 1 ID and you are not in Linux, allocating extra is fine
    void *id_mem = malloc(2*default_id_length);
    if (!id_mem)
        return cmd_ret;

    cmd_ret = m_sev_device->get_id(reinterpret_cast<uint8_t *>(&data), id_mem, 2*default_id_length);

    if (cmd_ret == STATUS_SUCCESS) {
        std::string id0_buf{};
        id0_buf.resize(default_id_length*2);// 2 chars per byte
        std::string id1_buf{};
        id1_buf.resize(default_id_length*2);
        for (uint8_t i = 0; i < default_id_length; i++) {
            sprintf(id0_buf.data()+2*i, "%02x", reinterpret_cast<uint8_t *>(data.id_p_addr)[i]);
            sprintf(id1_buf.data()+2*i, "%02x", reinterpret_cast<uint8_t *>(data.id_p_addr)[i+default_id_length]);
        }

        if (m_verbose_flag) {            // Print ID arrays
            printf("* GetID Socket0:\n%s", id0_buf.data());
            printf("\n* GetID Socket1:\n%s", id1_buf.data());
            printf("\n");
        }
        if (m_output_folder != "") {     // Print the IDs to a text file
            sev::write_file(id0_path, id0_buf.data(), id0_buf.size());  // Don't write null term
            sev::write_file(id1_path, id1_buf.data(), id1_buf.size());
        }
    }

    // Free memory
    free(id_mem);

    return (int)cmd_ret;
}

// ------------------------------------- //
// ---- Non-ioctl (Custom) commands ---- //
// ------------------------------------- //
int Command::sys_info()
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->sys_info();

    return (int)cmd_ret;
}

int Command::get_platform_owner()
{
    sev_platform_status_cmd_buf data{};
    int cmd_ret = -1;

    cmd_ret = m_sev_device->platform_status(reinterpret_cast<uint8_t *>(&data));
    if (cmd_ret != STATUS_SUCCESS)
        return -1;

    return m_sev_device->get_platform_owner(reinterpret_cast<uint8_t *>(&data));
}

int Command::get_platform_es()
{
    sev_platform_status_cmd_buf data{};
    int cmd_ret = -1;

    cmd_ret = m_sev_device->platform_status(reinterpret_cast<uint8_t *>(&data));
    if (cmd_ret != STATUS_SUCCESS)
        return -1;

    return m_sev_device->get_platform_es(reinterpret_cast<uint8_t *>(&data));
}

int Command::set_self_owned()
{
    int cmd_ret = -1;

    cmd_ret = m_sev_device->set_self_owned();

    return (int)cmd_ret;
}

int Command::set_externally_owned(std::string oca_priv_key_file)
{
    int cmd_ret = -1;

    std::string pek_oca_path = m_output_folder + OCA_FILENAME;
    std::string pek_csr_signed_path = m_output_folder + SIGNED_PEK_CSR_FILENAME;
    std::string pek_csr_hex_path = m_output_folder + PEK_CSR_HEX_FILENAME;

    // set self-owned before exporting PEK CSR
    cmd_ret = set_self_owned();
    if (cmd_ret != STATUS_SUCCESS)
        return cmd_ret;

    // export PEK CSR
    cmd_ret = pek_csr();
    if (cmd_ret != STATUS_SUCCESS)
        return cmd_ret;

    // sign PEK CSR
    cmd_ret = sign_pek_csr(pek_csr_hex_path, oca_priv_key_file);
    if (cmd_ret != STATUS_SUCCESS)
        return cmd_ret;

    // import CSR
    cmd_ret = pek_cert_import(pek_csr_signed_path, pek_oca_path);
    return cmd_ret;
}

int Command::generate_cek_ask()
{
    int cmd_ret = -1;

    std::string cert_file = CEK_FILENAME;

    cmd_ret = m_sev_device->generate_cek_ask(m_output_folder, cert_file);

    return (int)cmd_ret;
}

int Command::get_ask_ark()
{
    int cmd_ret = -1;

    std::string cert_file = ASK_ARK_FILENAME;

    cmd_ret = sev::get_ask_ark(m_output_folder, cert_file);

    return (int)cmd_ret;
}

int Command::generate_all_certs()
{
    int cmd_ret = -1;
    sev_pdh_cert_export_cmd_buf pdh_cert_export_data{};  // pdh_cert_export
    auto pdh = std::make_unique<sev_cert_t>();
    auto cert_chain = std::make_unique<sev_cert_chain_buf_t>(); // PEK, OCA, CEK
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
        cmd_ret = m_sev_device->pdh_cert_export(reinterpret_cast<uint8_t *>(&pdh_cert_export_data), pdh.get(), cert_chain.get());
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
        std::array<uint8_t, sizeof(amd_cert)*2> ask_ark_buf{};
        if (sev::read_file(ask_ark_full, ask_ark_buf.data(), sizeof(ask_ark_buf)) == 0)
            break;

        // Initialize the ask
        cmd_ret = tmp_amd.amd_cert_init(&ask, ask_ark_buf.data());
        if (cmd_ret != STATUS_SUCCESS)
            break;
        // print_amd_cert_readable(&ask);

        // Initialize the ark
        size_t ask_size = tmp_amd.amd_cert_get_size(&ask);
        cmd_ret = tmp_amd.amd_cert_init(&ark, (uint8_t *)(ask_ark_buf.data() + ask_size));
        if (cmd_ret != STATUS_SUCCESS)
            break;
        // print_amd_cert_readable(&ark);

        // Write all certs to individual files
        // Note that the CEK in the cert chain is unsigned, so we want to use
        //   the one 'cached by the hypervisor' that's signed by the ask
        //   (the one from the AMD dev site)
        size_t ark_size = tmp_amd.amd_cert_get_size(&ark);
        if (sev::write_file(pdh_full, pdh.get(), sizeof(sev_cert)) != sizeof(sev_cert))
            break;
        if (sev::write_file(pek_full, PEK_IN_CERT_CHAIN(cert_chain.get()), sizeof(sev_cert)) != sizeof(sev_cert))
            break;
        if (sev::write_file(oca_full, OCA_IN_CERT_CHAIN(cert_chain.get()), sizeof(sev_cert)) != sizeof(sev_cert))
            break;
        print_amd_cert_hex(&ask, ask_string);       // TODO refactor this
        print_amd_cert_hex(&ark, ark_string);
        auto ask_binary = sev::ascii_hex_bytes_to_binary(ask_string.c_str(), ask_size);
        auto ark_binary = sev::ascii_hex_bytes_to_binary(ark_string.c_str(), ark_size);
        if (sev::write_file(ask_full, ask_binary.data(), ask_size) != ask_size)
            break;
        if (sev::write_file(ark_full, ark_binary.data(), ark_size) != ark_size)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (false);

    return (int)cmd_ret;
}

int Command::export_cert_chain()
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
    } while (false);
    return (int)cmd_ret;
}

int Command::generate_all_certs_vcek()
{
    int cmd_ret = -1;

    std::string vcek_der_file = VCEK_DER_FILENAME;
    std::string vcek_pem_file = VCEK_PEM_FILENAME;
    std::string cert_chain_file = VCEK_CERT_CHAIN_PEM_FILENAME;
    std::string ask_file = VCEK_ASK_PEM_FILENAME;
    std::string ark_file = VCEK_ARK_PEM_FILENAME;

    do {
        // Generate the vcek from the AMD KDS server
        cmd_ret = m_sev_device->generate_vcek_ask(m_output_folder, vcek_der_file,
                                                  vcek_pem_file);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Get the cert_chain (ask_ark) from the AMD KDS server
        cmd_ret = sev::get_ask_ark_pem(m_output_folder, cert_chain_file,
                                       ask_file, ark_file);
        if (cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (false);

    return (int)cmd_ret;
}

int Command::export_cert_chain_vcek()
{
    int cmd_ret = -1;
    std::string zip_name = CERTS_VCEK_ZIP_FILENAME;
    std::string space = " ";
    std::string cert_names = m_output_folder + VCEK_DER_FILENAME + space +
                             m_output_folder + VCEK_PEM_FILENAME + space +
                             m_output_folder + VCEK_CERT_CHAIN_PEM_FILENAME + space +
                             m_output_folder + VCEK_ASK_PEM_FILENAME + space +
                             m_output_folder + VCEK_ARK_PEM_FILENAME;

    do {
        if (sev::get_device_type() != PSP_DEVICE_TYPE_MILAN) {
            printf("Error: export_cert_chain_vcek() is only supported on Milan platforms\n");
            cmd_ret = ERROR_UNSUPPORTED;
            break;
        }

        cmd_ret = generate_all_certs_vcek();
        if (cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = sev::zip_certs(m_output_folder, zip_name, cert_names);
    } while (false);
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
        if (HMAC_Init_ex(ctx, user_data->tik, sizeof(user_data->tik), EVP_sha256(), nullptr) != 1)
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
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t *>(&user_data->policy), sizeof(user_data->policy)) != 1)
            break;
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t *>(&user_data->digest), sizeof(user_data->digest)) != 1)
            break;
        // Use the same random MNonce as the FW in our validation calculations
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t *>(&user_data->mnonce), sizeof(user_data->mnonce)) != 1)
            break;
        if (HMAC_Final(ctx, reinterpret_cast<uint8_t *>(final_meas), &measurement_length) != 1)  // size = 32
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (false);

    HMAC_CTX_free(ctx);
    return cmd_ret;
}

int Command::calc_measurement(measurement_t *user_data)
{
    int cmd_ret = -1;
    hmac_sha_256 final_meas;
    std::string meas_path = m_output_folder + CALC_MEASUREMENT_FILENAME;
    std::string meas_readable_path = m_output_folder + CALC_MEASUREMENT_READABLE_FILENAME;

    cmd_ret = calculate_measurement(user_data, &final_meas);

    if (cmd_ret == STATUS_SUCCESS) {
        std::string meas_str{};
        meas_str.resize(sizeof(final_meas)*2);
        for (size_t i = 0; i < sizeof(final_meas); i++) {
            sprintf(meas_str.data()+2*i, "%02x", final_meas[i]);
        }

        if (m_verbose_flag) {          // Print ID arrays
            // Print input args for user
            printf("Input Arguments:\n");
            printf("   context: %02x\n", user_data->meas_ctx);
            printf("   Api Major: %02x\n", user_data->api_major);
            printf("   Api Minor: %02x\n", user_data->api_minor);
            printf("   Build ID: %02x\n", user_data->build_id);
            printf("   Policy: %02x\n", user_data->policy);
            printf("   Digest: ");
            for (auto i: user_data->digest) {
                printf("%02x", i);
            }
            printf("\n   MNonce: ");
            for (auto i: user_data->mnonce) {
                printf("%02x", i);
            }
            printf("\n   TIK: ");
            for (auto i: user_data->tik) {
                printf("%02x", i);
            }
            // Print output
            printf("\n\n%s\n", meas_str.c_str());
        }
        if (m_output_folder != "") {     // Print the IDs to a text file
            sev::write_file(meas_readable_path, (void *)meas_str.c_str(), meas_str.size());
            sev::write_file(meas_path, (void *)final_meas, sizeof(final_meas));
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
        amd_cert ark_buf{};
        if (sev::read_file(ark_full, &ark_buf, sizeof(amd_cert)) == 0) // Variable size
            break;

        // Initialize the ark
        cmd_ret = tmp_amd.amd_cert_init(ark, reinterpret_cast<uint8_t *>(&ark_buf));
        if (cmd_ret != STATUS_SUCCESS)
            break;

        // Read in the ark
        amd_cert ask_buf{};
        if (sev::read_file(ask_full, &ask_buf, sizeof(amd_cert)) == 0) // Variable size
            break;

        // Initialize the ark
        cmd_ret = tmp_amd.amd_cert_init(ask, reinterpret_cast<uint8_t *>(&ask_buf));
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
    } while (false);

    return (int)cmd_ret;
}

int Command::validate_cert_chain()
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
    } while (false);

    return (int)cmd_ret;
}

int Command::generate_launch_blob(uint32_t policy)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    sev_session_buf session_data_buf;
    std::string pdh_full = m_output_folder + PDH_FILENAME;
    std::string godh_cert_file = m_output_folder + GUEST_OWNER_DH_FILENAME;
    std::string tmp_tk_file = m_output_folder + GUEST_TK_FILENAME;
    std::string buf_file = m_output_folder + LAUNCH_BLOB_FILENAME;
    sev_cert pdh;
    EVP_PKEY *godh_key_pair = nullptr;      // Guest Owner Diffie-Hellman
    sev_cert godh_pubkey_cert;

    memset(&session_data_buf, 0, sizeof(sev_session_buf));

    do {
        // Read in the PDH (Platform Diffie-Hellman Public Key)
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
        memcpy(&godh_pubkey_cert, cert_obj.data(), sizeof(sev_cert)); // TODO, shouldn't need this?

        // Write the cert to file
        if (sev::write_file(godh_cert_file, &godh_pubkey_cert, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        cmd_ret = build_session_buffer(&session_data_buf, policy, godh_key_pair, &pdh);
        if (cmd_ret == STATUS_SUCCESS) {
            if (m_verbose_flag) {
                printf("Guest Policy (input): %08x\n", policy);
                printf("nonce:\n");
                for (auto i: session_data_buf.nonce) {
                    printf("%02x ", i);
                }
                printf("\nWrapTK TEK:\n");
                for (auto i: session_data_buf.wrap_tk.tek) {
                    printf("%02x ", i);
                }
                printf("\nWrapTK TIK:\n");
                for (auto i: session_data_buf.wrap_tk.tik) {
                    printf("%02x ", i);
                }
                printf("\nWrapIV:\n");
                for (auto i: session_data_buf.wrap_iv) {
                    printf("%02x ", i);
                }
                printf("\nWrapMAC:\n");
                for (auto i: session_data_buf.wrap_mac) {
                    printf("%02x ", i);
                }
                printf("\nPolicyMAC:\n");
                for (auto i: session_data_buf.policy_mac) {
                    printf("%02x ", i);
                }
                printf("\n");
            }

            // Write the unencrypted TK (TIK and TEK) to a tmp file so it can be
            // read in during package_secret
            sev::write_file(tmp_tk_file, &m_tk, sizeof(m_tk));

            sev::write_file(buf_file, (void *)&session_data_buf, sizeof(sev_session_buf));
        }
    } while (false);

    return (int)cmd_ret;
}

int Command::package_secret()
{
    int cmd_ret = ERROR_UNSUPPORTED;
    sev_hdr_buf packaged_secret_header;
    std::string secret_file = m_output_folder + SECRET_FILENAME;
    std::string pek_file = m_output_folder + PEK_FILENAME;
    std::string packaged_secret_file = m_output_folder + PACKAGED_SECRET_FILENAME;
    std::string packaged_secret_header_file = m_output_folder + PACKAGED_SECRET_HEADER_FILENAME;
    std::string measurement_file = m_output_folder + CALC_MEASUREMENT_FILENAME;
    std::string tmp_tk_file = m_output_folder + GUEST_TK_FILENAME;
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
        std::vector<uint8_t> secret_mem(secret_size);
        std::vector<uint8_t> encrypted_mem(secret_size);

        // Read in the secret
        // printf("Attempting to read in Secrets file\n");
        if (sev::read_file(secret_file, secret_mem.data(), secret_mem.size()) != secret_size)
            break;

        // Read in the PEK to obtain API major/minor version
        // printf("Attempting to read in PEK file to get the API Maj/Min versions\n");
        if (sev::read_file(pek_file, &pek, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Read in the unencrypted TK (TIK and TEK) created in build_session_buffer
        if (sev::read_file(tmp_tk_file, &m_tk, sizeof(m_tk)) != sizeof(m_tk)) {
            printf("Error reading in %s\n", tmp_tk_file.c_str());
            break;
        }

        // Encrypt the secret with the TEK
        encrypt_with_tek(encrypted_mem.data(), secret_mem.data(), secret_mem.size(), iv);

        if (m_verbose_flag) {
            printf("Random IV\n");
            for (auto i: iv) {
                printf("%02x ", i);
            }
            printf("\n");
        }

        // Read in the measurement, to be used as part of the launch secret header hmac
        if (sev::read_file(measurement_file, &m_measurement, sizeof(m_measurement)) != sizeof(m_measurement)) {
            printf("Error reading in %s\n", measurement_file.c_str());
            break;
        }

        // Write the encrypted secret to a file
        sev::write_file(packaged_secret_file, encrypted_mem.data(), encrypted_mem.size());

        // Set up the Launch_Secret packet header
        if (!create_launch_secret_header(&packaged_secret_header, &iv, encrypted_mem.data(),
                                         encrypted_mem.size(), flags,
                                         pek.api_major, pek.api_minor)) {
            break;
        }

        // Write the header to a file
        sev::write_file(packaged_secret_header_file, &packaged_secret_header, sizeof(packaged_secret_header));

        cmd_ret = STATUS_SUCCESS;
    } while (false);

    return (int)cmd_ret;
}

int Command::validate_attestation()
{
    int cmd_ret = ERROR_UNSUPPORTED;
    std::string report_file = m_output_folder + ATTESTATION_REPORT_FILENAME;
    std::string pek_full = m_output_folder + PEK_FILENAME;
    bool success = false;
    EVP_PKEY *pek_pub_key = nullptr;
    sev_cert pek;

    do {
        // Get the size of the report, so we can allocate that much memory
        size_t report_size = sev::get_file_size(report_file);
        if (report_size != sizeof(attestation_report)) {
            printf("Error: The size of the attestation report is %ld bytes\n", sizeof(attestation_report));
            break;
        }
        attestation_report report{};

        // Read in the report
        // printf("Attempting to read in Report file\n");
        if (sev::read_file(report_file, &report, report_size) != report_size)
            break;

        // Read in the PEK (Platform Encryption Public Key)
        if (sev::read_file(pek_full, &pek, sizeof(sev_cert)) != sizeof(sev_cert))
            break;

        // Build up a pek_pub_key so we can verify the signature on the report
        // New up the pek_pub_key
        if (!(pek_pub_key = EVP_PKEY_new()))
            break;

        // Get the friend's Public EVP_PKEY from the certificate
        // This function allocates memory and attaches an EC_Key
        //  to your EVP_PKEY so, to prevent mem leaks, make sure
        //  the EVP_PKEY is freed at the end of this function
        if (SEVCert::compile_public_key_from_certificate(&pek, pek_pub_key) != STATUS_SUCCESS)
            break;

        // Validate the report
        success = verify_message(reinterpret_cast<sev_sig *>(&report.sig1), // FIXME: sig1 seems to be smaller than sev_sig
                                  &pek_pub_key, reinterpret_cast<uint8_t *>(&report),
                                  offsetof(attestation_report, sig_usage),
                                  SEV_SIG_ALGO_ECDSA_SHA256);
        if (!success) {
            printf("Error: Attestation report failed to validate\n");
            break;
        }

        printf("Attestation report validated successfully!\n");
        cmd_ret = STATUS_SUCCESS;
    } while (false);

    // Free memory
    EVP_PKEY_free(pek_pub_key);

    return (int)cmd_ret;
}

int Command::validate_guest_report()
{
    int cmd_ret = ERROR_UNSUPPORTED;
    std::string report_file = m_output_folder + GUEST_REPORT_FILENAME;
    std::string vcek_file = m_output_folder + VCEK_PEM_FILENAME;
    bool success = false;
    EVP_PKEY *vcek_pub_key = nullptr;
    X509 *x509_vcek = nullptr;

    do {
        // Get the size of the report, so we can allocate that much memory
        size_t report_size = sev::get_file_size(report_file);
        if (report_size != sizeof(snp_attestation_report_t)) {
            printf("Error: The size of the attestation report is %ld bytes\n", sizeof(snp_attestation_report_t));
            break;
        }
        snp_attestation_report_t report{};

        // Read in the report
        // printf("Attempting to read in Report file\n");
        if (sev::read_file(report_file, &report, report_size) != report_size)
            break;

        // Read in the VCEK
        if (!read_pem_into_x509(vcek_file, &x509_vcek))
            break;
        // X509_print_fp(stdout, x509_vcek);

        vcek_pub_key = X509_get_pubkey(x509_vcek);
        if (!vcek_pub_key)
            break;

        // Print the key
        // BIO *out2;
        // out2 = BIO_new_fp(stdout, BIO_NOCLOSE);
        // EVP_PKEY_print_public(out2, vcek_pub_key, 2, NULL);
        // EVP_PKEY_print_params(out2, vcek_pub_key, 3, NULL);
        // BIO_free(out2);

        // Validate the report
        success = verify_message(reinterpret_cast<sev_sig *>(&report.signature),
                                  &vcek_pub_key, reinterpret_cast<uint8_t *>(&report),
                                  offsetof(snp_attestation_report_t, signature),
                                  SEV_SIG_ALGO_ECDSA_SHA384);
        if (!success) {
            printf("Error: Guest report failed to validate\n");
            break;
        }

        printf("Guest report validated successfully!\n");
        cmd_ret = STATUS_SUCCESS;
    } while (false);

    // Free memory
    EVP_PKEY_free(vcek_pub_key);
    X509_free(x509_vcek);

    return (int)cmd_ret;
}

int Command::validate_cert_chain_vcek()
{
    int cmd_ret = ERROR_UNSUPPORTED;
    std::string vcek_file = m_output_folder + VCEK_PEM_FILENAME;
    std::string ask_file = m_output_folder + VCEK_ASK_PEM_FILENAME;
    std::string ark_file = m_output_folder + VCEK_ARK_PEM_FILENAME;
    X509 *x509_vcek = nullptr;
    X509 *x509_ask = nullptr;
    X509 *x509_ark = nullptr;
    EVP_PKEY *vcek_pub_key = nullptr;

    do {
        // Read in the ARK, ASK, and VCEK pem files
        if (!read_pem_into_x509(ark_file, &x509_ark))
            break;
        if (!read_pem_into_x509(ask_file, &x509_ask))
            break;
        if (!read_pem_into_x509(vcek_file, &x509_vcek))
            break;
        // X509_print_fp(stdout, x509_vcek);

        // Extract the vcek public key
        vcek_pub_key = X509_get_pubkey(x509_vcek);
        if (!vcek_pub_key)
            break;

        // Verify the signatures of the certs
        if (!x509_validate_signature(x509_ark, nullptr, x509_ark)) {   // Verify the ARK self-signed the ARK
            printf("Error validating signature of x509_ark certs\n");
            break;
        }

        if (!x509_validate_signature(x509_ask, nullptr, x509_ark)) {   // Verify the ARK signed the ASK
            printf("Error validating signature of x509_ask certs\n");
            break;
        }

        if (!x509_validate_signature(x509_vcek, x509_ask, x509_ark)) {  // Verify the ASK signed the VCEK
            printf("Error validating signature of x509_vcek certs\n");
            break;
        }

        printf("VCEK cert chain validated successfully!\n");
        cmd_ret = STATUS_SUCCESS;
    } while (false);

    // Free memory
    EVP_PKEY_free(vcek_pub_key);
    X509_free(x509_vcek);
    X509_free(x509_ask);
    X509_free(x509_ark);

    return (int)cmd_ret;
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
    std::array<uint8_t, NIST_KDF_H_BYTES> prf_out;      // Buffer to collect PRF output

    // length in bits of derived key
    auto l = (uint32_t)(key_out_length * BITS_PER_BYTE);

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
        if (HMAC_Init_ex(ctx, key_in, (int)key_in_length, EVP_sha256(), nullptr) != 1)
            break;
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t const *>(&i), sizeof(i)) != 1)
            break;
        if (HMAC_Update(ctx, reinterpret_cast<unsigned char const *>(label), label_length) != 1)
            break;
        if (HMAC_Update(ctx, &null_byte, sizeof(null_byte)) != 1)
            break;
        if ((context) && (context_length != 0)) {
            if (HMAC_Update(ctx, (unsigned char const*)context, context_length) != 1)
                break;
        }
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t const *>(&l), sizeof(l)) != 1)
            break;
        if (HMAC_Final(ctx, prf_out.data(), &out_len) != 1)
            break;

        // Write out the key bytes
        if (bytes_left <= prf_out.size()) {
            memcpy(key_out + offset, prf_out.data(), bytes_left);
        }
        else {
            memcpy(key_out + offset, prf_out.data(), prf_out.size());
            offset     += prf_out.size();
            bytes_left -= prf_out.size();
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
        return nullptr;

    bool success = false;
    EVP_PKEY_CTX *ctx = nullptr;
    uint8_t *shared_key = nullptr;

    do {
        // Create the context using your private key
        if (!(ctx = EVP_PKEY_CTX_new(priv_key, nullptr)))
            break;

        // Calculate the intermediate secret
        if (EVP_PKEY_derive_init(ctx) <= 0)
            break;
        if (EVP_PKEY_derive_set_peer(ctx, peer_key) <= 0)
            break;

        // Determine buffer length
        if (EVP_PKEY_derive(ctx, nullptr, &shared_key_len_out) <= 0)
            break;

        // Need to free shared_key using OPENSSL_FREE() in the calling function
        shared_key = reinterpret_cast<unsigned char*>(OPENSSL_malloc(shared_key_len_out));
        if (!shared_key)
            break;      // malloc failure

        // Compute the shared secret with the ECDH key material.
        if (EVP_PKEY_derive(ctx, shared_key, &shared_key_len_out) <= 0)
            break;

        success = true;
    } while (false);

    EVP_PKEY_CTX_free(ctx);

    return success ? shared_key : nullptr;
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
                                   const nonce_128 nonce)
{
    if (!godh_priv_key || !pdh_public)
        return false;

    sev_cert dummy;
    memset(&dummy, 0, sizeof(sev_cert));    // To remove compile warnings
    SEVCert temp_obj(&dummy);                // TODO. Hack b/c just want to call function later
    bool ret = false;
    EVP_PKEY *plat_pub_key = nullptr;    // Platform public key
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
            shared_key_len, reinterpret_cast<uint8_t const *>(SEV_MASTER_SECRET_LABEL),
            sizeof(SEV_MASTER_SECRET_LABEL)-1, reinterpret_cast<uint8_t *>(&nonce), sizeof(nonce_128))) // sizeof(nonce), bad?
            break;

        // Free memory allocated in calculate_shared_secret
        OPENSSL_free(shared_key);    // Local variable

        ret = true;
    } while (false);

    // Free memory
    EVP_PKEY_free(plat_pub_key);

    return ret;
}

bool Command::derive_kek(aes_128_key kek, const aes_128_key master_secret)
{
    bool ret = kdf((unsigned char*)kek, sizeof(aes_128_key), master_secret, sizeof(aes_128_key),
                   reinterpret_cast<uint8_t const *>(SEV_KEK_LABEL), sizeof(SEV_KEK_LABEL)-1, nullptr, 0);
    return ret;
}

bool Command::derive_kik(hmac_key_128 kik, const aes_128_key master_secret)
{
    bool ret = kdf((unsigned char*)kik, sizeof(aes_128_key), master_secret, sizeof(aes_128_key),
                   reinterpret_cast<uint8_t const *>(SEV_KIK_LABEL), sizeof(SEV_KIK_LABEL)-1, nullptr, 0);
    return ret;
}

bool Command::gen_hmac(hmac_sha_256 *out, hmac_key_128 key, uint8_t *msg, size_t msg_len)
{
    if (!out || !msg)
        return false;

    unsigned int out_len = 0;
    HMAC(EVP_sha256(), key, sizeof(hmac_key_128), msg,    // Returns NULL or value of out
         msg_len, reinterpret_cast<uint8_t *>(out), &out_len);

    if ((out != nullptr) && (out_len == sizeof(hmac_sha_256)))
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
        if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, Key, IV) != 1)
            break;

        // Provide the message to be encrypted, and obtain the encrypted output
        if (EVP_EncryptUpdate(ctx, out, &len, in, (int)length) != 1)
            break;

        // Finalize the encryption. Further out bytes may be written at
        // this stage
        if (EVP_EncryptFinal_ex(ctx, out + len, &len) != 1)
            break;

        cmd_ret = true;
    } while (false);

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
        if (!encrypt(reinterpret_cast<uint8_t *>(&wrap_tk), reinterpret_cast<uint8_t *>(&m_tk), sizeof(m_tk), kek, iv))
            break;

        // Generate the HMAC for the wrap_tk
        if (!gen_hmac(&wrap_mac, kik, reinterpret_cast<uint8_t *>(&wrap_tk), sizeof(wrap_tk)))
            break;

        // Generate the HMAC for the Policy bits
        if (!gen_hmac(&policy_mac, m_tk.tik, reinterpret_cast<uint8_t *>(&guest_policy), sizeof(guest_policy)))
            break;

        // Copy everything to the session data buffer
        memcpy(&buf->nonce, &nonce, sizeof(buf->nonce));
        memcpy(&buf->wrap_tk, &wrap_tk, sizeof(buf->wrap_tk));
        memcpy(&buf->wrap_iv, &iv, sizeof(buf->wrap_iv));
        memcpy(&buf->wrap_mac, &wrap_mac, sizeof(buf->wrap_mac));
        memcpy(&buf->policy_mac, &policy_mac, sizeof(buf->policy_mac));

        cmd_ret = STATUS_SUCCESS;
    } while (false);

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
                                          uint32_t hdr_flags,
                                          uint8_t api_major, uint8_t api_minor)
{
    bool ret = false;

    // Note: API <= 0.16 and older does LaunchSecret differently than Naples API >= 0.17
    const uint8_t meas_ctx = 0x01;
    sev_hdr_buf header;
    uint32_t measurement_length = sizeof(header.mac);
    const auto buf_len = (uint32_t)buffer_len;

    memcpy(header.iv, iv, sizeof(iv_128));
    header.flags = hdr_flags;

    // Create and initialize the context
    HMAC_CTX *ctx;
    if (!(ctx = HMAC_CTX_new()))
        return ret;

    do {
        if (HMAC_Init_ex(ctx, m_tk.tik, sizeof(m_tk.tik), EVP_sha256(), nullptr) != 1)
            break;
        if (HMAC_Update(ctx, &meas_ctx, sizeof(meas_ctx)) != 1)
            break;
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t const *>(&header.flags), sizeof(header.flags)) != 1)
            break;
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t const *>(&header.iv), sizeof(header.iv)) != 1)
            break;
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t const *>(&buf_len), sizeof(buf_len)) != 1) // Guest Length
            break;
        if (HMAC_Update(ctx, reinterpret_cast<uint8_t const *>(&buf_len), sizeof(buf_len)) != 1) // Trans Length
            break;
        if (HMAC_Update(ctx, buf, buf_len) != 1)                        // Data
            break;
        if (sev::min_api_version(api_major, api_minor, 0, 17)) {
            if (HMAC_Update(ctx, m_measurement, sizeof(m_measurement)) != 1) // Measure
                break;
        }
        if (HMAC_Final(ctx, reinterpret_cast<uint8_t *>(&header.mac), &measurement_length) != 1)
            break;

        memcpy(out_header, &header, sizeof(sev_hdr_buf));
        ret = true;
    } while (false);

    HMAC_CTX_free(ctx);

    return ret;
}
