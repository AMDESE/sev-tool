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

#include "sevapi.h"
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
#include <memory>

// -------------- Global Functions that don't require ioctls -------------- //
void sev::get_family_model(uint32_t *family, uint32_t *model)
{
    std::string cmd = "";
    std::string fam_str = "";
    std::string model_str = "";

    cmd = "lscpu | grep -E \"^CPU family:\" | awk {'print $3'}";
    sev::execute_system_command(cmd, &fam_str);
    cmd = "lscpu | grep -E \"^Model:\" | awk {'print $2'}";
    sev::execute_system_command(cmd, &model_str);

    *family = std::stoi(fam_str, nullptr, 10);
    *model = std::stoi(model_str, nullptr, 10);
}

ePSP_DEVICE_TYPE sev::get_device_type()
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
    } while (false);

    return cmd_ret;
}

int sev::get_ask_ark_pem(const std::string output_folder, const std::string cert_chain_file,
                         const std::string ask_file, const std::string ark_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    struct stat file_details;
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

        // Create the required SEV assets directory if it doesn't exist.
        if (stat(SEV_DEFAULT_DIR, &file_details) == -1) {
            if (errno == ENOENT) {
                if (mkdir(SEV_DEFAULT_DIR, 0775) != -1) {
                    printf("Info: Created missing directory: %s\n", SEV_DEFAULT_DIR);
                } else {
                    fprintf(stderr, "Error: Unable to create required directory: %s\n", SEV_DEFAULT_DIR);
                }
            }
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
    } while (false);

    return cmd_ret;
}

int sev::zip_certs(const std::string output_folder, const std::string zip_name,
                   const std::string files_to_zip)
{
    int cmd_ret = SEV_RET_SUCCESS;
    std::string cmd = "";
    std::string output = "";
    std::string error = "zip error";

    cmd = "zip -j " + output_folder + zip_name + " " + files_to_zip;
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

SEVDevice& SEVDevice::get_sev_device()
{
    static SEVDevice m_sev_device;
    m_sev_device.mFd = open(DEFAULT_SEV_DEVICE.c_str(), O_RDWR);
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
            ioctl(get_fd(), SEV_ISSUE_CMD, &arg);
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


int SEVDevice::pek_csr(uint8_t *data, void *pek_mem, sev_cert *csr)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    auto *data_buf = (sev_user_data_pek_csr *)data;
    SEVCert csr_obj(csr);

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
        if (csr_obj.validate_pek_csr() != STATUS_SUCCESS) {
            cmd_ret = SEV_RET_INVALID_CERTIFICATE;
            break;
        }
    } while (false);

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

int SEVDevice::pdh_cert_export(uint8_t *data, sev_cert_t const *pdh_cert_mem,
                               sev_cert_chain_buf_t const *cert_chain_mem)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    auto *data_buf = (sev_user_data_pdh_cert_export *)data;

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

    } while (false);

    return (int)cmd_ret;
}

int SEVDevice::pek_cert_import(uint8_t *data, sev_cert *signed_pek_csr,
                               sev_cert *oca_cert)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    auto *data_buf = (sev_user_data_pek_cert_import *)data;
    memset(data_buf, 0, sizeof(sev_user_data_pek_cert_import));

    do {
        // Verify signed CSR complies to API specification
        SEVCert cert_obj(signed_pek_csr);
        if (cert_obj.verify_signed_pek_csr(oca_cert) != STATUS_SUCCESS) {
            cmd_ret = SEV_RET_INVALID_CERTIFICATE;
            break;
        }

        data_buf->pek_cert_address = (uint64_t)signed_pek_csr;
        data_buf->pek_cert_len = sizeof(sev_cert);
        data_buf->oca_cert_address = (uint64_t)oca_cert;
        data_buf->oca_cert_len = sizeof(sev_cert);

        // Send the command
        ioctl_ret = sev_ioctl(SEV_PEK_CERT_IMPORT, data_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

    } while (false);

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
    } while (false);

    // The other functions in this file can do a direct mapping of the Linux
    //   struct to the SEV API struct in sevapi.h, however, for this function,
    //   this Linux struct doesn't match (at all) the API
    // Hard coded hack mapping to sevapi.h. Don't want to include sevapi.h in this file
    ((uint64_t *)data)[0] = (uint64_t)id_mem;      // Set address of id_mem as 64 bit PAddr from sevapi.h
    ((uint32_t *)data)[2] = id_length;  // 3rd 32-bit chunk in the cmd_buf

    return (int)cmd_ret;
}

std::string SEVDevice::display_build_info()
{
    SEVDevice sev_device;
    sev_platform_status_cmd_buf status;
    int cmd_ret = -1;

    std::string api_major_ver = "API_Major: xxx";
    std::string api_minor_ver = "API_Minor: xxx";
    std::string build_id_ver  = "BuildID: xxx";

    cmd_ret = sev_device.platform_status(reinterpret_cast<uint8_t *>(&status));
    if (cmd_ret != 0)
        return "";

    std::array<char, 4> major_buf, minor_buf, build_id_buf;   // +1 for Null char
    sprintf(major_buf.data(), "%d", status.api_major);
    sprintf(minor_buf.data(), "%d", status.api_minor);
    sprintf(build_id_buf.data(), "%d", status.build_id);
    api_major_ver.replace(11, 3, major_buf.data());
    api_minor_ver.replace(11, 3, minor_buf.data());
    build_id_ver.replace(9, 3, build_id_buf.data());

    return api_major_ver + ", " + api_minor_ver + ", " + build_id_ver;
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
    printf("Platform Family 0x%02x, Model 0x%02x\n", family, model);

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
        std::array<char, sizeof(id_buf.socket1)*2+1> id0_buf{};  // 2 chars per byte +1 for null term
        for (uint8_t i = 0; i < sizeof(id_buf.socket1); i++)
        {
            sprintf(id0_buf.data()+2*i, "%02x", id_buf.socket1[i]);
        }
        cmd += id0_buf.data();

        // Don't re-download the CEK from the KDS server if you already have it
        if (sev::get_file_size(to_cert_w_path) != 0) {
            // printf("CEK already exists, not re-downloading\n");
            cmd_ret = SEV_RET_SUCCESS;
            break;
        }

        // The AMD KDS server only accepts requests every 10 seconds
        std::string cert_w_path = output_folder + id0_buf.data();
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
    } while (false);

    return cmd_ret;
}

int SEVDevice::generate_vcek_ask(const std::string output_folder,
                                 const std::string vcek_der_file,
                                 const std::string vcek_pem_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_get_id id_buf{};
    std::array<char, 235> cmd{};
    std::string fmt;
    std::string output = "";
    std::string der_cert_w_path = output_folder + vcek_der_file;
    std::string pem_cert_w_path = output_folder + vcek_pem_file;

    do {

        fmt = "wget -O %s \"%sMilan/%s?blSPL=%02d&teeSPL=%02d&snpSPL=%02d&ucodeSPL=%02d\"";

        // Get the ID of the Platform
        // Send the command
        ioctl_ret = sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if (ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        // Note that Linux referrs to P0 and P1 as socket1 and socket2 (which is incorrect).
        //   So below, we are getting the ID for P0, which is the first socket
        std::array<char, sizeof(id_buf.socket1)*2+1> id0_buf{};  // 2 chars per byte +1 for null term
        for (uint8_t i = 0; i < sizeof(id_buf.socket1); i++)
        {
            sprintf(id0_buf.data()+2*i, "%02x", id_buf.socket1[i]);
        }

        // Create a container to store the TCB Version in.
        snp_tcb_version tcb_data = {.val = 0};

        // Get the TCB version of the Platform
        request_tcb_data(tcb_data);

        // Build the URL string.
        sprintf(
            cmd.data(),
            fmt.c_str(),
            der_cert_w_path.c_str(),
            KDS_VCEK,
            id0_buf.data(),
            tcb_data.f.boot_loader,
            tcb_data.f.tee,
            tcb_data.f.snp,
            tcb_data.f.microcode
        );

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
            if (!sev::execute_system_command(cmd.data(), &output)) {
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
    } while (false);

    return cmd_ret;
}

int SEVDevice::request_platform_status(snp_platform_status_buffer *plat_status) {
    int cmd_ret = SEV_RET_UNSUPPORTED;

    memset(plat_status, 0, sizeof(snp_platform_status_buffer));

    sev_ioctl(SEV_SNP_PLATFORM_STATUS, plat_status, &cmd_ret);

    return cmd_ret;
}

void SEVDevice::request_tcb_data(snp_tcb_version &tcb_data) {
    snp_platform_status_buffer plat_status;
    int ioctl_return = request_platform_status(&plat_status);
    if (ioctl_return != 0) {
        fprintf(
            stderr,
            "Error: SNP_PLATFORM_STATUS failure: %s\n",
            std::strerror(ioctl_return)
        );
    } else {
        tcb_data.val = plat_status.tcb_version;
    }
}


#endif
