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

#ifdef __linux__
#include "sevcore.h"
#include "utilities.h"
#include "psp-sev.h"
#include "rmp.h"
#include "x509cert.h"
#include <sys/ioctl.h>      // for ioctl()
#include <sys/mman.h>       // for mmap() and friends
#include <cstdio>           // for std::rename
#include <cerrno>           // for errorno
#include <fcntl.h>          // for O_RDWR
#include <unistd.h>         // for close()
#include <uuid/uuid.h>
#include <stdexcept>        // for std::runtime_error()

char *SEV_PIPE_FILES[2];

// -------------- Global Functions that don't require ioctls -------------- //
void sev::get_family_model(uint32_t *family, uint32_t *model)
{
    std::string cmd = "";
    std::string fam_str = "";
    std::string model_str = "";

    cmd = "lscpu | grep -E \"CPU family:\" | awk {'print $3'}";
    sev::execute_system_command(cmd, &fam_str);
    cmd = "lscpu | grep -E \"Model:\" | awk {'print $2'}";
    sev::execute_system_command(cmd, &model_str);

    *family = std::stoi(fam_str, NULL, 10);
    *model = std::stoi(model_str, NULL, 10);
}

ePSP_DEVICE_TYPE sev::get_device_type(void)
{
    uint32_t family = 0;
    uint32_t model = 0;

    sev::get_family_model(&family, &model);

    if (family == NAPLES_FAMILY && (int)model >= (int)NAPLES_MODEL_LOW && model <= NAPLES_MODEL_HIGH) {
        return PSP_DEVICE_TYPE_NAPLES;
    }
    else if (family == ROME_FAMILY && model >= ROME_MODEL_LOW && model <= ROME_MODEL_HIGH) {
        return PSP_DEVICE_TYPE_ROME;
    }
    else if (family == MILAN_FAMILY && (int)model >= (int)MILAN_MODEL_LOW && model <= MILAN_MODEL_HIGH) {
        return PSP_DEVICE_TYPE_MILAN;
    }
    else
        return PSP_DEVICE_TYPE_INVALID;
}

/**
 * Verify current FW is >= API version major.minor
 * Returns true if the firmware API version is at least major.minor
 * Has to be an offline comparison (can't call platform_status itself because
 *   it needs to be used in calc_measurement)
 */
bool sev::min_api_version(unsigned platform_major, unsigned platform_minor,
                          unsigned api_major, unsigned api_minor)
{
    if ((platform_major < api_major) ||
        (platform_major == api_major && platform_minor < api_minor))
        return false;
    else
        return true;
}

int sev::get_ask_ark(const std::string output_folder, const std::string cert_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    std::string cmd = "wget ";
    std::string output = "";
    ePSP_DEVICE_TYPE device_type = PSP_DEVICE_TYPE_INVALID;
    std::string cert_w_path = "";

    do {
        cmd += "-O " + output_folder + cert_file + " ";
        cert_w_path = output_folder + cert_file;

        // Don't re-download the CEK from the KDS server if you already have it
        if (sev::get_file_size(cert_w_path) != 0) {
            // printf("ASK_ARK already exists, not re-downloading\n");
            cmd_ret = SEV_RET_SUCCESS;
            break;
        }

        device_type = get_device_type();
        if (device_type == PSP_DEVICE_TYPE_NAPLES) {
            cmd += ASK_ARK_NAPLES_SITE;
        }
        else if (device_type == PSP_DEVICE_TYPE_ROME) {
            cmd += ASK_ARK_ROME_SITE;
        }
        else if (device_type == PSP_DEVICE_TYPE_MILAN) {
            cmd += ASK_ARK_MILAN_SITE;
        }
        else {
            printf("Error: Unable to determine Platform type. " \
                        "Detected %i\n", (uint32_t)device_type);
            break;
        }

        // Download the certificate from the AMD server
        if (!sev::execute_system_command(cmd, &output)) {
            printf("Error: pipe not opened for system command\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Check if the file got downloaded
        if (sev::get_file_size(cert_w_path) == 0) {
            printf("Error: command to get ask_ark cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        cmd_ret = SEV_RET_SUCCESS;
    } while (0);

    return cmd_ret;
}

int sev::get_ask_ark_pem(const std::string output_folder, const std::string cert_chain_file,
                         const std::string ask_file, const std::string ark_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    std::string cmd = "wget ";
    std::string output = "";
    std::string cert_chain_w_path = output_folder + cert_chain_file;
    std::string ask_w_path = output_folder + ask_file;
    std::string ark_w_path = output_folder + ark_file;

    do {
        cmd += "-O " + cert_chain_w_path;  // Really ASK and ARK
        cmd += " \"";
        cmd += KDS_VCEK;
        cmd += "Milan/";
        cmd += KDS_VCEK_CERT_CHAIN;
        cmd += "\"";

        // Don't re-download the CEK from the KDS server if you already have it
        if (sev::get_file_size(cert_chain_w_path) != 0) {
            // printf("ASK_ARK pem already exists, not re-downloading\n");
            cmd_ret = SEV_RET_SUCCESS;
            break;
        }

        // Download the certificate from the AMD server
        if (!sev::execute_system_command(cmd, &output)) {
            printf("Error: pipe not opened for system command\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Check if the file got downloaded
        if (sev::get_file_size(cert_chain_w_path) == 0) {
            printf("Error: command to get ask_ark cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Split it from ask_ark into 2 separate pem files
        cmd = "csplit -z -f " SEV_DEFAULT_DIR "cert_chain- ";
        cmd += cert_chain_w_path;
        cmd += " '/-----BEGIN CERTIFICATE-----/' '{*}'";
        if (!execute_system_command(cmd, &output)) {
            printf("Error: pipe not opened for system command\n");
            break;
        }

        // Move the file from "cert_chain-xx" to something known (cert_chain_w_path)
        if (std::rename(SEV_DEFAULT_DIR "cert_chain-00", ask_w_path.c_str()) != 0) {
            printf("Error: renaming vcek cert chain file\n");
            break;
        }
        if (std::rename(SEV_DEFAULT_DIR "cert_chain-01", ark_w_path.c_str()) != 0) {
            printf("Error: renaming vcek cert chain file\n");
            break;
        }

        cmd_ret = SEV_RET_SUCCESS;
    } while (0);

    return cmd_ret;
}

int sev::zip_certs(const std::string output_folder, const std::string zip_name,
                   const std::string files_to_zip)
{
    int cmd_ret = SEV_RET_SUCCESS;
    std::string cmd = "";
    std::string output = "";
    std::string error = "zip error";

    cmd = "zip " + output_folder + zip_name + " " + files_to_zip;
    sev::execute_system_command(cmd, &output);

    if (output.find(error) != std::string::npos) {
        printf("Error when zipping up files!");
        cmd_ret = -1;
    }

    return cmd_ret;
}

// -------------------------- SEVDevice Functions -------------------------- //
SEVDevice::~SEVDevice()
{
    if (mFd >= 0) {
        close(mFd);
    }
    mFd = -1;
}

SEVDevice& SEVDevice::get_sev_device(void)
{
    static SEVDevice m_sev_device;
    m_sev_device.mFd = open(DEFAULT_SEV_DEVICE.c_str(), O_RDWR);
    m_sev_device.dep_bits = {{false, false, false, false, false}};
    if (m_sev_device.mFd < 0) {
        throw std::runtime_error("Can't open " + std::string(DEFAULT_SEV_DEVICE) + "!\n");
    }
    return m_sev_device;
}

int SEVDevice::sev_ioctl(int cmd, void *data, int *cmd_ret)
{
    int ioctl_ret = -1;
    sev_issue_cmd arg;

    arg.cmd = (uint32_t)cmd;
    arg.data = (uint64_t)data;

    if (cmd == SEV_GET_ID) {
        /*
         * Note: There is a cache alignment bug in Naples SEV Firmware
         *       version < 0.17.19 where it will sometimes return the wrong
         *       value of P0. This happens when it's the first command run after
         *       a bootup or when it's run a few seconds after switching between
         *       self-owned and externally-owned (both directions).
         */
        sev_user_data_status status_data;  // Platform Status
        *cmd_ret = platform_status((uint8_t *)&status_data);
        if (*cmd_ret != 0)
            return ioctl_ret;

        if (status_data.api_major == 0 && status_data.api_minor <= 17 &&
            status_data.build < 19) {
            printf("Adding a 5 second delay to account for Naples GetID bug...\n");
            ioctl_ret = ioctl(get_fd(), SEV_ISSUE_CMD, &arg);
            usleep(5000000);    // 5 seconds
        }
    }

    ioctl_ret = ioctl(get_fd(), SEV_ISSUE_CMD, &arg);
    *cmd_ret = arg.error;
    // if (ioctl_ret != 0) {    // Sometimes you expect it to fail
    //     printf("Error: cmd %#x ioctl_ret=%d (%#x)\n", cmd, ioctl_ret, arg.error);
    // }

    return ioctl_ret;
}

int SEVDevice::factory_reset()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = SEV_RET_UNSUPPORTED;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    sev_ioctl(SEV_FACTORY_RESET, &data, &cmd_ret);

    return (int)cmd_ret;
}

int SEVDevice::get_platform_owner(void *data)
{
    return ((sev_user_data_status *)data)->flags & PLAT_STAT_OWNER_MASK;
}

int SEVDevice::get_platform_es(void *data)
{
    return ((sev_user_data_status *)data)->flags & PLAT_STAT_ES_MASK;
}

int SEVDevice::platform_status(uint8_t *data)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_status));

    sev_ioctl(SEV_PLATFORM_STATUS, data, &cmd_ret);

    return (int)cmd_ret;
}

int SEVDevice::pek_gen()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = SEV_RET_UNSUPPORTED;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    sev_ioctl(SEV_PEK_GEN, &data, &cmd_ret);

    return (int)cmd_ret;
}

bool SEVDevice::validate_pek_csr(sev_cert *pek_csr)
{
    if (pek_csr->version       == 1                         &&
        pek_csr->pub_key_usage == SEV_USAGE_PEK             &&
        pek_csr->pub_key_algo  == SEV_SIG_ALGO_ECDSA_SHA256 &&
        pek_csr->sig_1_usage   == SEV_USAGE_INVALID         &&
        pek_csr->sig_1_algo    == SEV_SIG_ALGO_INVALID      &&
        pek_csr->sig_2_usage   == SEV_USAGE_INVALID         &&
        pek_csr->sig_2_algo    == SEV_SIG_ALGO_INVALID) {
        return true;
    }
    else {
        return false;
    }
}

int SEVDevice::pek_csr(uint8_t *data, void *pek_mem, sev_cert *csr)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pek_csr *data_buf = (sev_user_data_pek_csr *)data;

    // Set struct to 0
    memset(data_buf, 0, sizeof(sev_user_data_pek_csr));

    do {
        // Populate PEKCSR buffer with CSRLength = 0
        data_buf->address = (uint64_t)pek_mem;
        data_buf->length = 0;

        // Send the command. This is to get the MinSize length. If you
        // already know it, then you don't have to send the command twice
        ioctl_ret = sev_ioctl(SEV_PEK_CSR, data_buf, &cmd_ret);
        if (ioctl_ret != -1)
            break;

        // Verify the results. Now the CSRLength will be updated to MinSize
        if (cmd_ret != SEV_RET_INVALID_LEN)
            break;

        // Send the command again with CSRLength=MinSize
        ioctl_ret = sev_ioctl(SEV_PEK_CSR, data_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

        // Verify the CSR complies to API specification
        memcpy(csr, (sev_cert*)data_buf->address, sizeof(sev_cert));
        if (!validate_pek_csr(csr)) {
            cmd_ret = SEV_RET_INVALID_CERTIFICATE;
            break;
        }
    } while (0);

    return (int)cmd_ret;
}

int SEVDevice::pdh_gen()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = SEV_RET_UNSUPPORTED;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    sev_ioctl(SEV_PDH_GEN, &data, &cmd_ret);

    return (int)cmd_ret;
}

int SEVDevice::pdh_cert_export(uint8_t *data, void *pdh_cert_mem,
                               void *cert_chain_mem)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pdh_cert_export *data_buf = (sev_user_data_pdh_cert_export *)data;

    // Set struct to 0
    memset(data_buf, 0, sizeof(sev_user_data_pdh_cert_export));

    do {
        data_buf->pdh_cert_address = (uint64_t)pdh_cert_mem;
        data_buf->pdh_cert_len = sizeof(sev_cert);
        data_buf->cert_chain_address = (uint64_t)cert_chain_mem;
        data_buf->cert_chain_len = sizeof(sev_cert_chain_buf);

        // Send the command
        ioctl_ret = sev_ioctl(SEV_PDH_CERT_EXPORT, data_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

    } while (0);

    return (int)cmd_ret;
}

int SEVDevice::pek_cert_import(uint8_t *data, sev_cert *pek_csr,
                               const std::string oca_priv_key_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pek_cert_import *data_buf = (sev_user_data_pek_cert_import *)data;
    sev_user_data_status status_data;  // Platform Status

    EVP_PKEY *oca_priv_key = NULL;
    sev_cert *oca_cert = new sev_cert_t;
    if (!oca_cert)
        return SEV_RET_HWSEV_RET_PLATFORM;

    // Submit the signed cert to PEKCertImport
    memset(data_buf, 0, sizeof(sev_user_data_pek_cert_import)); // Set struct to 0

    do {
        // Verify the CSR complies to API specification
        if (!validate_pek_csr(pek_csr)) {
            cmd_ret = SEV_RET_INVALID_CERTIFICATE;
            break;
        }

        // Do a platform_status to get api_major and api_minor to create oca cert
        cmd_ret = platform_status((uint8_t *)&status_data);
        if (cmd_ret != 0)
            break;

        // Import the OCA pem file and turn it into an sev_cert
        SEVCert cert_obj(oca_cert);
        if (!read_priv_key_pem_into_evpkey(oca_priv_key_file, &oca_priv_key)) {
            printf("Error importing OCA Priv Key\n");
            cmd_ret = SEV_RET_INVALID_CERTIFICATE;
            break;
        }
        if (!cert_obj.create_oca_cert(&oca_priv_key, SEV_SIG_ALGO_ECDSA_SHA256)) {
            printf("Error creating OCA cert\n");
            cmd_ret = SEV_RET_INVALID_CERTIFICATE;
            break;
        }
        // print_sev_cert_readable((sev_cert *)oca_cert);

        // Sign the PEK CSR with the OCA private key
        SEVCert CSRCert(pek_csr);
        CSRCert.sign_with_key(SEV_CERT_MAX_VERSION, SEV_USAGE_PEK, SEV_SIG_ALGO_ECDSA_SHA256,
                              &oca_priv_key, SEV_USAGE_OCA, SEV_SIG_ALGO_ECDSA_SHA256);

        data_buf->pek_cert_address = (uint64_t)CSRCert.data();
        data_buf->pek_cert_len = sizeof(sev_cert);
        data_buf->oca_cert_address = (uint64_t)oca_cert;
        data_buf->oca_cert_len = sizeof(sev_cert);

        // Send the command
        ioctl_ret = sev_ioctl(SEV_PEK_CERT_IMPORT, data_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

    } while (0);

    // Free memory
    delete oca_cert;

    return (int)cmd_ret;
}

// Must always pass in 128 bytes array, because of how linux /dev/sev ioctl works
int SEVDevice::get_id(void *data, void *id_mem, uint32_t id_length)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_get_id id_buf;    // Linux buffer is different than API spec. Don't point it to *data

    // Set struct to 0
    memset(&id_buf, 0, sizeof(sev_user_data_get_id));

    do {
        if (id_length != 128) {  // Linux is hard-coded to 128 bytes
            id_length = 64;        // PSP returns length of 1 ID, if length isn't correct
            cmd_ret = SEV_RET_INVALID_LEN;
            break;
        }

        // Send the command
        ioctl_ret = sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        memcpy(id_mem, &id_buf, id_length);
    } while (0);

    // The other functions in this file can do a direct mapping of the Linux
    //   struct to the SEV API struct in sevapi.h, however, for this function,
    //   this Linux struct doesn't match (at all) the API
    // Hard coded hack mapping to sevapi.h. Don't want to include sevapi.h in this file
    ((uint64_t *)data)[0] = (uint64_t)id_mem;      // Set address of id_mem as 64 bit PAddr from sevapi.h
    ((uint32_t *)data)[2] = id_length;  // 3rd 32-bit chunk in the cmd_buf

    return (int)cmd_ret;
}

std::string SEVDevice::display_build_info(void)
{
    SEVDevice sev_device;
    uint8_t status_data[sizeof(sev_platform_status_cmd_buf)];
    sev_platform_status_cmd_buf *status_data_buf = (sev_platform_status_cmd_buf *)&status_data;
    int cmd_ret = -1;

    std::string api_major_ver = "API_Major: xxx";
    std::string api_minor_ver = "API_Minor: xxx";
    std::string build_id_ver  = "BuildID: xxx";

    cmd_ret = sev_device.platform_status(status_data);
    if (cmd_ret != 0)
        return "";

    char major_buf[4], minor_buf[4], build_id_buf[4];   // +1 for Null char
    sprintf(major_buf, "%d", status_data_buf->api_major);
    sprintf(minor_buf, "%d", status_data_buf->api_minor);
    sprintf(build_id_buf, "%d", status_data_buf->build_id);
    api_major_ver.replace(11, 3, major_buf);
    api_minor_ver.replace(11, 3, minor_buf);
    build_id_ver.replace(9, 3, build_id_buf);

    return api_major_ver + ", " + api_minor_ver + ", " + build_id_ver;
}

/**
 * Verifies that the SEV kernel modules have been loaded successfully for KVM.
 */
bool SEVDevice::kvm_amd_sev_enabled(void)
{
    uint8_t retval = 0;
    std::ifstream fin(KVM_AND_SEV_PARAM);

    if (fin.is_open())
    {
        retval = (uint8_t)fin.get();
    }

    fin.close();
    return retval != '0';
}

/**
 * Runs the virConnectGetDomainCapabilities command, and checks for the proper
 * SEV support which should be listed.
 */
bool SEVDevice::valid_libvirt(virConnectPtr con)
{
    char *result = virConnectGetDomainCapabilities(con, NULL, "x86_64",
                                                   NULL, "kvm", 0);

    return std::strstr(result, LIBVIRT_SEV_SUPPORTED) ? true : false;
}

/**
 * Validates that qemu has the function query-sev-capabilities exists,
 * indicating that the correct SEV functionality has been backkported to the
 * running instance of QEMU.
 */
bool SEVDevice::valid_qemu(virDomainPtr dom)
{
    char **result = (char **) malloc(sizeof *result);
    bool ret_val = false;

    // Check that qemu has the functions required for SEV.
    virDomainQemuMonitorCommand(dom, QMP_SEV_CAPS_CMD, result,
                                VIR_DOMAIN_QEMU_MONITOR_COMMAND_DEFAULT);

    ret_val = std::strstr(*result, COMMAND_NOT_FOUND) ? false : true;

    free(result);

    return ret_val;
}

std::string SEVDevice::find_sev_ovmf_bin(char *capabilities)
{
    char *ovmf_bin_loc = (char *) malloc(strlen(capabilities));
    strncpy(ovmf_bin_loc, capabilities, strlen(capabilities));

    char *p_val_end = strstr(ovmf_bin_loc, "</value>");

    if (p_val_end)
    {
        ovmf_bin_loc[p_val_end - ovmf_bin_loc] = '\0';
        ovmf_bin_loc = strstr(ovmf_bin_loc, "<value>");
        ovmf_bin_loc ? ovmf_bin_loc += sizeof("<value>") - 1 : "";
    }

    return ovmf_bin_loc;
}

std::string SEVDevice::find_sev_c_bit_pos(char * capabilities)
{
    char *c_bit_pos = (char *) malloc(strlen(capabilities));
    strncpy(c_bit_pos, capabilities, strlen(capabilities));

    char *p_c_bit_end = strstr(c_bit_pos, "</cbitpos>");

    if (p_c_bit_end)
    {
        c_bit_pos[p_c_bit_end - c_bit_pos] = '\0';
        c_bit_pos = strstr(c_bit_pos, "<cbitpos>");
        c_bit_pos ? c_bit_pos += sizeof("<cbitpos>") - 1 : "";
    }

    return c_bit_pos;
}

std::string SEVDevice::find_sev_reduced_phys_bits(char * capabilities)
{
    char *reduced_phys_bits = (char *) malloc(strlen(capabilities));
    strncpy(reduced_phys_bits, capabilities, strlen(capabilities));

    char *p_reduced_phys_bit_end = strstr(reduced_phys_bits, "</reducedPhysBits>");

    if (p_reduced_phys_bit_end)
    {
        reduced_phys_bits[p_reduced_phys_bit_end - reduced_phys_bits] = '\0';
        reduced_phys_bits = strstr(reduced_phys_bits, "<reducedPhysBits>");
        reduced_phys_bits ?
            reduced_phys_bits += sizeof("<reducedPhysBits>") - 1 : "";
    }

    return reduced_phys_bits;
}

/**
 * Creates a local pipe to the shell vm for validating OVMF.
 */
void SEVDevice::create_sev_pipe_files(char * sev_temp_dir)
{
    if (sev_temp_dir)
    {
        for (uint8_t i = 0; i < 2; i++)
        {
            // Allocate just enough size for the UUID being generated.
            SEV_PIPE_FILES[i] = (char *) malloc(37 * sizeof(char));

            // create a new UUID
            uuid_t temp_uuid;
            uuid_generate(temp_uuid);

            // store the UUID in the character pointer array.
            uuid_unparse_upper(temp_uuid, (char *) SEV_PIPE_FILES[i]);

            std::string in_file_name(std::string(sev_temp_dir) + "/" + std::string(SEV_PIPE_FILES[i]) + ".in");
            std::string out_file_name(std::string(sev_temp_dir) + "/" +  std::string(SEV_PIPE_FILES[i]) + ".out");

            if (mkfifo(in_file_name.c_str(), 0777) < 0)
            {
                if (errno == EEXIST)
                {
                    fprintf(stderr, "CRITICAL: SEV pipe input file collision.\n");
                }
                else
                {
                    fprintf(stderr, "Error: Unknown error with mkfifo occured.\n");
                }
                fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
                exit(1);
            }
            else if (mkfifo(out_file_name.c_str(), 0777) < 0)
            {
                if (errno == EEXIST)
                {
                    fprintf(stderr, "CRITICAL: SEV pipe output file collision.\n");
                }
                else
                {
                    fprintf(stderr, "Error: Unknown error with mkfifo occured.\n");
                }
                fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
                exit(1);
            }

            if (chmod(in_file_name.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) < 0)
            {
                fprintf(stderr, "CRITICAL: Unable to modify the file "
                        "permissions for the pipe files generated");
                fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
                exit(1);
            }

            if (chmod(out_file_name.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) < 0)
            {
                fprintf(stderr, "CRITICAL: Unable to modify the file "
                        "permissions for the pipe files generated");
                fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
                exit(1);
            }
        }
    }
}

/**
 *  Create the temp directory used for all SEV test files.
 */
void SEVDevice::create_sev_temp_dir(char ** sev_temp_file)
{
    char sev_file_template[] = "/tmp/SEVXXXXXX";
    *sev_temp_file = strdup(mkdtemp(sev_file_template));
    if (chmod(*sev_temp_file, S_IRWXU | S_IRWXG | S_IRWXO) < 0)
    {
        fprintf(stderr, "CRITICAL: Unable to modify the sev temporary directory");
        fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
        exit(1);
    }
}

/**
 *  Creates an OVMF Variable file for validation of OVMF
 */
void SEVDevice::create_ovmf_var_file(std::string ovmf_bin, char * sev_temp_dir,
                                     char ** ovmf_var_file)
{
    struct stat *ovmf_bin_details = new struct stat();
    struct stat *ovmf_var_details = new struct stat();
    uint64_t byte_count = 0;

    if (stat(ovmf_bin.c_str(), ovmf_bin_details) == 0)
    {
        if (ovmf_bin_details->st_size < 0x200000)
        {
            byte_count = 0x200000 - ovmf_bin_details->st_size;
        }
        else
        {
            byte_count = 0x400000 - ovmf_bin_details->st_size;
        }
    }

    std::string null_bytes(byte_count, '\0');
    strcpy(*ovmf_var_file, sev_temp_dir);
    strcat(*ovmf_var_file, "/OVMF-XXXXXX");

    if (mkstemp(*ovmf_var_file) > 0)
    {
        std::ofstream fout(*ovmf_var_file);
        fout << null_bytes;
        fout.close();
    }
    else
    {
        if (errno == EEXIST)
        {
            fprintf(stderr, "CRITICAL: OVMF variable file collision!\n");
            fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
        }
        else
        {
            fprintf(stderr, "CRITICAL: An unforseen error has occured: %d\n", errno);
            fprintf(stderr, "errno: %d - %s", errno, strerror(errno));
        }

        exit(1);
    }

    delete ovmf_bin_details;
    delete ovmf_var_details;
}

/**
 * Checks if the shell vm is currently running.
 */
bool SEVDevice::dom_state_up(virDomainPtr dom)
{
    return !this->dom_state_down(dom);
}

/**
 * Checks if the shell vm is currently listed as down or non-existent.
 */
bool SEVDevice::dom_state_down(virDomainPtr dom)
{
    virDomainInfo * dom_info = new virDomainInfo();
    bool ret_val = false;

    virDomainGetInfo(dom, dom_info);

    switch (dom_info->state)
    {
        case VIR_DOMAIN_NOSTATE:
        case VIR_DOMAIN_SHUTDOWN:
        case VIR_DOMAIN_SHUTOFF:
            ret_val = true;
            break;
        default:
            break;
    }

    delete dom_info;
    return ret_val;
}

virDomainPtr SEVDevice::start_new_domain(virConnectPtr con,
                                         std::string name,
                                         bool sev_enable,
                                         struct sev_dom_details dom_details,
                                         char * sev_temp_dir,
                                         char * ovmf_var_file)
{
    // OVMF is running successfully without SEV enabled.
    std::string shell_vm_name = "<name>" + name + "</name>";

    std::string sev_pipe_path = "<source path='" + std::string(sev_temp_dir) + "/" +
                                std::string(SEV_PIPE_FILES[sev_enable ? 1 : 0]) + "'/>";

    std::string sev_pipe = "<devices>"
                           "<serial type='pipe'>" +
                           sev_pipe_path +
                           "<target port='1'/>"
                           "</serial>"
                           "</devices>";

    std::string code_bin_path = "<os><loader readonly='yes'"
                                " type='pflash'>" +
                                dom_details.ovmf_bin_loc +
                                "</loader>";

    std::string var_bin_path  = "<nvram>" +
                                std::string(ovmf_var_file) +
                                "</nvram>"
                                "<type arch='x86_64'"
                                " machine='q35'>hvm"
                                "</type>"
                                "</os>";

    std::string SHELL_VM_SEV_ENABLE = "<launchSecurity type='sev'>"
                                      "<policy>0x0001</policy>"
                                      "<cbitpos>" +
                                      dom_details.c_bit_pos +
                                      "</cbitpos>"
                                      "<reducedPhysBits>" +
                                      dom_details.reduced_phys_bits +
                                      "</reducedPhysBits>"
                                      "</launchSecurity>";

    std::string FINAL_XML = SHELL_VM_XML_1  +
                            shell_vm_name   +
                            sev_pipe        +
                            code_bin_path   +
                            var_bin_path    +
                            (sev_enable ? SHELL_VM_SEV_ENABLE : "") +
                            SHELL_VM_XML_2;

    virDomainPtr dom = virDomainDefineXML(con, FINAL_XML.c_str());

    virDomainCreate(dom);

    return dom;
}

/**
 * Validates that OVMF is working properly with SEV by investigating memory
 * pages which are known to be zero, but now contain encrypted valus.
 */
bool SEVDevice::valid_ovmf(virDomainPtr dom, bool sev_enabled, char * sev_temp_dir)
{
    bool ret_val = false;
    uint8_t check = 0;

    std::string file_name(sev_temp_dir);
    file_name += "/";
    file_name += SEV_PIPE_FILES[(sev_enabled ? 1 : 0)];
    file_name += ".in";

    std::ofstream pipe_in(file_name);

    for (; check < 3; check++)
    {
        printf("Waiting for OVMF to come up...\n");
        sleep(3);
        if (this->dom_state_up(dom))
        {
            break;
        }
    }

    // Attempt to shutdown the machine via OVMF. This is a valid check because
    // instances of OVMF without proper code will fail to respond.
    pipe_in << "\rreset -s s\r";
    pipe_in.close();

    // Wait long enough for the VM to be shutdown.
    for (check = 0; check < 3; check++)
    {
        printf("Waiting for OVMF to shutdown...\n");
        if (this->dom_state_down(dom))
        {
            ret_val = true;
            break;
        }
        sleep(3);
    }

    if (!ret_val)
    {
        fprintf(stderr, "OVMF found running after OVMF reset given! Destroying transient VM!\n");
        virDomainDestroy(dom);
    }

    virDomainUndefineFlags(dom, VIR_DOMAIN_UNDEFINE_NVRAM);
    virDomainFree(dom);

    // Read the status of the domain.
    return ret_val;
}

/**
 * Attempts to verify all software components meet minimal requirements.
 *
 * Checks the following conditions respectively:
 *  - BIOS/UEFI support is enabled.
 *  - Kernel supports the device driver, and has loaded proper drivers.
 *  - KVM kernel supports device interaction, and module has been
 *    successfully enabled.
 *  - QEMU contains and has found expected functionality.
 *  - Libvirt supports, recognizes, and output the support level properly.
 *  - OVMF supports encryption, and is enabled.
 */
void SEVDevice::check_dependencies(void)
{
    // Default everything to unsupported.
    struct stat *file_details = new struct stat();
    int cmd_ret = SEV_RET_UNSUPPORTED;
    uint8_t *p_data = new uint8_t();

    if (stat(LINUX_SEV_FILE, file_details) == 0)
    {
        this->dep_bits.kernel = !!1;

        if (kvm_amd_sev_enabled())
        {

            this->dep_bits.kvm = !!1;

            if (this->sev_ioctl(SEV_PLATFORM_STATUS, p_data, &cmd_ret) != -1)
            {
                // Open a connection to the hypervisor using the default connection.
                virConnectPtr con = virConnectOpen(NULL);

                char *capabilities = virConnectGetDomainCapabilities(con,
                                                                     NULL,
                                                                     "x86_64",
                                                                     NULL,
                                                                     "kvm",
                                                                     0);

                struct sev_dom_details dom_details = {find_sev_ovmf_bin(capabilities),
                                                      find_sev_c_bit_pos(capabilities),
                                                      find_sev_reduced_phys_bits(capabilities)};

                if (! dom_details.ovmf_bin_loc.empty())
                {
                    // Create the pipe files to interact with the shell VM.
                    char *sev_temp_dir = (char *) malloc(sizeof("/tmp/SEVXXXXXX\0"));
                    char *ovmf_var_file = (char *) malloc(sizeof(char) * 64);

                    this->create_sev_temp_dir(&sev_temp_dir);
                    this->create_sev_pipe_files(sev_temp_dir);
                    this->create_ovmf_var_file(dom_details.ovmf_bin_loc, sev_temp_dir, &ovmf_var_file);

                    // Create a shell VM with the XML specified
                    // (destroyed upon completion of testing).
                    virDomainPtr dom = this->start_new_domain(con,
                                                              SHELL_VM_NAME_BASE + "1",
                                                              false,
                                                              dom_details,
                                                              sev_temp_dir,
                                                              ovmf_var_file);

                    if (valid_qemu(dom))
                    {
                        this->dep_bits.qemu = !!1;

                        // The libvirt check relies on QEMU to be successfully
                        // configured.
                        if (this->valid_libvirt(con))
                        {
                            this->dep_bits.libvirt = !!1;

                            printf("Verifying OVMF works with SEV disabled...\n");

                            if (this->valid_ovmf(dom, false, sev_temp_dir))
                            {
                                virDomainPtr sev_dom = start_new_domain(con,
                                                                        SHELL_VM_NAME_BASE + "2",
                                                                        true,
                                                                        dom_details,
                                                                        sev_temp_dir,
                                                                        ovmf_var_file);

                                printf("Verifying OVMF works with SEV enabled...\n");
                                if (this->valid_ovmf(sev_dom, true, sev_temp_dir))
                                {
                                    this->dep_bits.ovmf = !!1;
                                }
                            }
                        }
                    }

                    for (uint8_t i = 0; i < 2; i++)
                    {
                        remove(std::string(std::string(sev_temp_dir) + "/" + std::string(SEV_PIPE_FILES[i]) + ".in").c_str());
                        remove(std::string(std::string(sev_temp_dir) + "/" + std::string(SEV_PIPE_FILES[i]) + ".out").c_str());
                    }

                    remove(ovmf_var_file);
                    remove(sev_temp_dir);

                    free(ovmf_var_file);
                    free(sev_temp_dir);
                }

                // Cleanup
                virConnectClose(con);
            }
        }
    }

    // Clean up all memory.
    delete file_details;
    delete p_data;
}

std::string SEVDevice::format_software_support_text(void)
{
    std::string ret_val = "";

    switch (this->dep_bits.raw)
    {
        case 0x1F:
            ret_val = "  Kernel:  Supported\n"
                      "  KVM:     Supported\n"
                      "  QEMU:    Supported\n"
                      "  Libvirt: Supported\n"
                      "  OVMF:    Supported\n";
            break;
        case 0x0F:
            ret_val = "  Kernel:  Supported\n"
                      "  KVM:     Supported\n"
                      "  QEMU:    Supported\n"
                      "  Libvirt: Supported\n"
                      "  OVMF:    Unsupported\n";
            break;
        case 0x07:
            ret_val = "  Kernel:  Supported\n"
                      "  KVM:     Supported\n"
                      "  QEMU:    Supported\n"
                      "  Libvirt: Unsupported\n"
                      "  OVMF:    Undetermined\n";
            break;
        case 0x03:
            ret_val = "  Kernel:  Supported\n"
                      "  KVM:     Supported\n"
                      "  QEMU:    Unsupported\n"
                      "  Libvirt: Undetermined\n"
                      "  OVMF:    Undetermined\n";
            break;
        case 0x01:
            ret_val = "  Kernel:  Supported\n"
                      "  KVM:     Unsupported\n"
                      "  QEMU:    Undetermined\n"
                      "  Libvirt: Undetermined\n"
                      "  OVMF:    Undetermined\n";
            break;
        default:
            ret_val = "  Kernel:  Unsupported\n"
                      "  KVM:     Undetermined\n"
                      "  QEMU:    Undetermined\n"
                      "  Libvirt: Undetermined\n"
                      "  OVMF:    Undetermined\n";
            break;
    }

    return ret_val;
}

int SEVDevice::sys_info()
{
    int cmd_ret = SEV_RET_SUCCESS;
    std::string cmd = "";
    std::string output = "";
    uint32_t family = 0;
    uint32_t model = 0;

    printf("-------------------------System Info-------------------------");
    // Exec bash commands to get info on user's platform and append to the output string
    cmd = "echo -n 'Hostname: '; hostname";
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'BIOS Version: '; dmidecode -s bios-version";
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'BIOS Release Date: '; dmidecode -s bios-release-date";
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'SMT/Multi-Threading Status Per Socket: \n'; lscpu | grep -E \"^CPU\\(s\\):|Thread\\(s\\) per core|Core\\(s\\) per socket|Socket\\(s\\)\"";
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'Processor Frequency (all sockets): \n'; dmidecode -s processor-frequency";
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'Operating System: '; cat /etc/os-release | grep \"PRETTY_NAME=\" | sed 's/.*=//'";        // cat /etc/issue
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'Kernel Version: '; uname -r";
    sev::execute_system_command(cmd, &output);
    cmd = "echo -n 'Git Commit #: '; cat \"../.git/refs/heads/master\"";
    sev::execute_system_command(cmd, &output);

    // Print results of all execute_system_command calls
    printf("\n%s", output.c_str());

    std::string build_info = display_build_info();
    printf("Firmware Version: %s\n", build_info.c_str());

    sev::get_family_model(&family, &model);
    printf("Platform Family %02x, Model %02x\n", family, model);

    printf("\n");
    this->check_dependencies();

    printf("\nSoftware Support:\n");
    printf("%s", format_software_support_text().c_str());

    printf("-------------------------------------------------------------\n\n");

    return (int)cmd_ret;
}

/**
 * Note: You can not change the Platform Owner if Guests are running. That means
 *       the Platform cannot be in the WORKING state here. The ccp Kernel Driver
 *       will do its best to set the Platform state to whatever is required to
 *       run each command, but that does not include shutting down Guests to do so.
 */
int SEVDevice::set_self_owned()
{
    sev_user_data_status status_data;  // Platform Status
    int cmd_ret = SEV_RET_UNSUPPORTED;

    cmd_ret = platform_status((uint8_t *)&status_data);
    if (cmd_ret != SEV_RET_SUCCESS) {
        return cmd_ret;
    }

    if (get_platform_owner(&status_data) != PLATFORM_STATUS_OWNER_SELF) {
        switch (status_data.state) {
            case SEV_PLATFORM_WORKING:
                break;          // Can't Change Owner. Guests are running!
            case SEV_PLATFORM_UNINIT: {
                cmd_ret = factory_reset();  // Change owner from ext to self-owned
                if (cmd_ret != SEV_RET_SUCCESS) {
                    return cmd_ret;
                }
                break;
            }
            case SEV_PLATFORM_INIT: {
                cmd_ret = pek_gen();        // Self-owned to different self-owned
                if (cmd_ret != SEV_RET_SUCCESS) {
                    return cmd_ret;
                }
                break;
            }
            default:
                break;              // Unrecognized Platform state!
        }
    }

    return (int)cmd_ret;
}

/**
 * Note: You can not change the Platform Owner if Guests are running.
 *       That means the Platform cannot be in the WORKING state here.
 *       The ccp Kernel Driver will do its best to set the Platform state
 *       to whatever is required to run each command, but that does not
 *       include shutting down Guests to do so.
 */
int SEVDevice::set_externally_owned(const std::string oca_priv_key_file)
{
    sev_user_data_status platform_status_data;

    int cmd_ret = SEV_RET_UNSUPPORTED;
    sev_cert *PEKMem = new sev_cert_t;

    if (!PEKMem)
        return SEV_RET_HWSEV_RET_PLATFORM;

    do {
        // Send platform_status command to get ownership status
        cmd_ret = platform_status((uint8_t *)&platform_status_data);
        if (cmd_ret != SEV_RET_SUCCESS)
            break;

        // Check if we're already externally owned
        if (get_platform_owner(&platform_status_data) != PLATFORM_STATUS_OWNER_EXTERNAL) {
            // Get the CSR
            sev_user_data_pek_csr pek_csr_data;                  // pek_csr
            sev_cert PEKcsr;
            cmd_ret = pek_csr((uint8_t *)&pek_csr_data, PEKMem, &PEKcsr);
            if (cmd_ret != SEV_RET_SUCCESS)
                break;

            // Sign the CSR
            // Fetch the OCA certificate
            // Submit the signed cert to PEKCertImport
            sev_user_data_pek_cert_import pek_cert_import_data;
            cmd_ret = pek_cert_import((uint8_t *)&pek_cert_import_data, &PEKcsr,
                                      oca_priv_key_file);
            if (cmd_ret != SEV_RET_SUCCESS)
                break;

            // Send platform_status command to get new ownership status
            cmd_ret = platform_status((uint8_t *)&platform_status_data);
            if (cmd_ret != SEV_RET_SUCCESS)
                break;

            // Confirm that we are now ext owned
            if (get_platform_owner(&platform_status_data) != PLATFORM_STATUS_OWNER_EXTERNAL)
                cmd_ret = SEV_RET_HWSEV_RET_PLATFORM;
        }
    } while (0);

    // Free memory
    delete PEKMem;

    return (int)cmd_ret;
}

int SEVDevice::generate_cek_ask(const std::string output_folder,
                                const std::string cert_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_get_id id_buf;
    std::string cmd = "wget ";
    std::string output = "";
    std::string to_cert_w_path = output_folder + cert_file;

    // Set struct to 0
    memset(&id_buf, 0, sizeof(sev_user_data_get_id));

    do {
        cmd += "-P " + output_folder + " ";
        cmd += KDS_CEK;

        // Get the ID of the Platform
        // Send the command
        ioctl_ret = sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        // Note that Linux referrs to P0 and P1 as socket1 and socket2 (which is incorrect).
        //   So below, we are getting the ID for P0, which is the first socket
        char id0_buf[sizeof(id_buf.socket1)*2+1] = {0};  // 2 chars per byte +1 for null term
        for (uint8_t i = 0; i < sizeof(id_buf.socket1); i++)
        {
            sprintf(id0_buf+strlen(id0_buf), "%02x", id_buf.socket1[i]);
        }
        cmd += id0_buf;

        // Don't re-download the CEK from the KDS server if you already have it
        if (sev::get_file_size(to_cert_w_path) != 0) {
            // printf("CEK already exists, not re-downloading\n");
            cmd_ret = SEV_RET_SUCCESS;
            break;
        }

        // The AMD KDS server only accepts requests every 10 seconds
        std::string cert_w_path = output_folder + id0_buf;
        bool cert_found = false;
        int sec_to_sleep = 6;
        int retries = 0;
        int max_retries = (int)((10/sec_to_sleep)+2);
        while (!cert_found && retries <= max_retries) {
            if (!sev::execute_system_command(cmd, &output)) {
                printf("Error: pipe not opened for system command\n");
                cmd_ret = SEV_RET_UNSUPPORTED;
                break;
            }

            // Check if the file got downloaded
            if (sev::get_file_size(cert_w_path) != 0) {
                cert_found = true;
                break;
            }
            sleep(sec_to_sleep);
            printf("Trying again\n");
            retries++;
        }
        if (!cert_found) {
            printf("Error: command to get cek_ask cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Copy the file from (get_id) name to something known (cert_file)
        if (std::rename(cert_w_path.c_str(), to_cert_w_path.c_str()) != 0) {
            printf("Error: renaming cek cert file\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }
    } while (0);

    return cmd_ret;
}

int SEVDevice::generate_vcek_ask(const std::string output_folder,
                                 const std::string vcek_der_file,
                                 const std::string vcek_pem_file,
                                 const std::string tcb_version)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_get_id id_buf;
    std::string cmd = "wget ";
    std::string output = "";
    std::string der_cert_w_path = output_folder + vcek_der_file;
    std::string pem_cert_w_path = output_folder + vcek_pem_file;

    // Set struct to 0
    memset(&id_buf, 0, sizeof(sev_user_data_get_id));

    do {
        cmd += "-O " + der_cert_w_path;
        cmd += " \"";
        cmd += KDS_VCEK;
        cmd += "Milan/";

        // Get the ID of the Platform
        // Send the command
        ioctl_ret = sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        // Note that Linux referrs to P0 and P1 as socket1 and socket2 (which is incorrect).
        //   So below, we are getting the ID for P0, which is the first socket
        char id0_buf[sizeof(id_buf.socket1)*2+1] = {0};  // 2 chars per byte +1 for null term
        for (uint8_t i = 0; i < sizeof(id_buf.socket1); i++)
        {
            sprintf(id0_buf+strlen(id0_buf), "%02x", id_buf.socket1[i]);
        }
        cmd += id0_buf;

        // Get the TCB version of the Platform
        // (passed in right now, not getting it from SNPPlatformStatus here)

        // Convert the TCB buffer to decimal bytes
        std::string TCBStringArray[8];
        TCBStringArray[0] = "blSPL=";
        TCBStringArray[1] = "teeSPL=";
        TCBStringArray[2] = "reserved0SPL=";
        TCBStringArray[3] = "reserved1SPL=";
        TCBStringArray[4] = "reserved2SPL=";
        TCBStringArray[5] = "reserved3SPL=";
        TCBStringArray[6] = "snpSPL=";
        TCBStringArray[7] = "ucodeSPL=";
        for (uint8_t i = 0; i < sizeof(snp_tcb_version_t); i++) {
            TCBStringArray[i] += tcb_version[(i*2)];
            TCBStringArray[i] += tcb_version[(i*2)+1];
            printf("%d, %s\n", i, TCBStringArray[i].c_str());
        }

        cmd += "?";
        cmd += TCBStringArray[0] + "&" + TCBStringArray[1] + "&" +
            //    TCBStringArray[2] + "&" + TCBStringArray[3] + "&" +
            //    TCBStringArray[4] + "&" + TCBStringArray[5] + "&" +
               TCBStringArray[6] + "&" + TCBStringArray[7];
        cmd += "\"";

        // Don't re-download the VCEK from the KDS server if you already have it
        if (sev::get_file_size(pem_cert_w_path) != 0) {
            // printf("VCEK already exists, not re-downloading\n");
            cmd_ret = SEV_RET_SUCCESS;
            break;
        }

        // The AMD KDS server only accepts requests every 10 seconds
        bool cert_found = false;
        int sec_to_sleep = 6;
        int retries = 0;
        int max_retries = (int)((10/sec_to_sleep)+2);
        while (!cert_found && retries <= max_retries) {
            if (!sev::execute_system_command(cmd, &output)) {
                printf("Error: pipe not opened for system command\n");
                cmd_ret = SEV_RET_UNSUPPORTED;
                break;
            }

            // Check if the file got downloaded
            if (sev::get_file_size(der_cert_w_path) != 0) {
                cert_found = true;
                break;
            }
            sleep(sec_to_sleep);
            printf("Trying again\n");
            retries++;
        }
        if (!cert_found) {
            printf("Error: command to get vcek_ask cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Convert the file from a DER to a PEM file
        convert_der_to_pem(der_cert_w_path, pem_cert_w_path);
    } while (0);

    return cmd_ret;
}

#endif
