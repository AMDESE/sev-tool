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
#include "linux/psp-sev.h"
#include <sys/ioctl.h>      // for ioctl()
#include <sys/mman.h>       // for mmap() and friends
#include <cstdio>           // for std::rename
#include <errno.h>          // for errorno
#include <fcntl.h>          // for O_RDWR
#include <unistd.h>         // for close()
#include <stdexcept>        // for std::runtime_error()

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

    if(cmd == SEV_GET_ID) {
        /*
         * Note: There is a cache alignment bug in Naples SEV Firmware
         *       version < 0.17.19 where it will sometimes return the wrong
         *       value of P0. This happens when it's the first command run after
         *       a bootup or when it's run a few seconds after switching between
         *       self-owned and externally-owned (both directions).
         */
        sev_user_data_status status_data;  // Platform Status
        *cmd_ret = platform_status((uint8_t *)&status_data);
        if(*cmd_ret != 0)
            return ioctl_ret;

        if(status_data.api_major == 0 && status_data.api_minor <= 17 &&
           status_data.build < 19) {
            printf("Adding a 5 second delay to account for Naples GetID bug...\n");
            ioctl_ret = ioctl(get_fd(), SEV_ISSUE_CMD, &arg);
            usleep(5000000);    // 5 seconds
        }
    }

    ioctl_ret = ioctl(get_fd(), SEV_ISSUE_CMD, &arg);
    *cmd_ret = arg.error;
    // if(ioctl_ret != 0) {    // Sometimes you expect it to fail
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

int SEVDevice::get_platform_owner(void* data)
{
    return ((sev_user_data_status *)data)->flags & PLAT_STAT_OWNER_MASK;
}

int SEVDevice::get_platform_es(void* data)
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
    if(pek_csr->version       == 1                         &&
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
        if(ioctl_ret != -1)
            break;

        // Verify the results. Now the CSRLength will be updated to MinSize
        if(cmd_ret != SEV_RET_INVALID_LEN)
            break;

        // Send the command again with CSRLength=MinSize
        ioctl_ret = sev_ioctl(SEV_PEK_CSR, data_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Verify the CSR complies to API specification
        memcpy(csr, (sev_cert*)data_buf->address, sizeof(sev_cert));
        if(!validate_pek_csr(csr))
            break;

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

int SEVDevice::pdh_cert_export(uint8_t *data,
                               void *pdh_cert_mem,
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
        if(ioctl_ret != 0)
            break;

    } while (0);

    return (int)cmd_ret;
}

int SEVDevice::pek_cert_import(uint8_t *data,
                               sev_cert *pek_csr,
                               const std::string oca_priv_key_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pek_cert_import *data_buf = (sev_user_data_pek_cert_import *)data;
    sev_user_data_status status_data;  // Platform Status

    EVP_PKEY *oca_priv_key = NULL;
    sev_cert *oca_cert = new sev_cert_t;
    if(!oca_cert)
        return SEV_RET_HWSEV_RET_PLATFORM;

    // Submit the signed cert to PEKCertImport
    memset(data_buf, 0, sizeof(sev_user_data_pek_cert_import)); // Set struct to 0

    do {
        // Verify the CSR complies to API specification
        if(!validate_pek_csr(pek_csr))
            break;

        // Do a platform_status to get api_major and api_minor to create oca cert
        cmd_ret = platform_status((uint8_t *)&status_data);
        if(cmd_ret != 0)
            break;

        // Import the OCA pem file and turn it into an sev_cert
        SEVCert cert_obj(*(sev_cert *)oca_cert);
        if(!read_priv_key_pem_into_evpkey(oca_priv_key_file, &oca_priv_key))
            break;
        if(!cert_obj.create_oca_cert(&oca_priv_key, status_data.api_major, status_data.api_minor))
            break;
        memcpy(oca_cert, cert_obj.data(), sizeof(sev_cert)); // TODO, shouldn't need this?
        // print_sev_cert_readable((sev_cert *)oca_cert);

        // Sign the PEK CSR with the OCA private key
        SEVCert CSRCert(*pek_csr);
        CSRCert.sign_with_key(SEV_CERT_MAX_VERSION, SEV_USAGE_PEK, SEV_SIG_ALGO_ECDSA_SHA256,
                              &oca_priv_key, SEV_USAGE_OCA, SEV_SIG_ALGO_ECDSA_SHA256);

        data_buf->pek_cert_address = (uint64_t)CSRCert.data();
        data_buf->pek_cert_len = sizeof(sev_cert);
        data_buf->oca_cert_address = (uint64_t)oca_cert;
        data_buf->oca_cert_len = sizeof(sev_cert);

        // Send the command
        ioctl_ret = sev_ioctl(SEV_PEK_CERT_IMPORT, data_buf, &cmd_ret);
        if(ioctl_ret != 0)
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
        if(id_length != 128) {  // Linux is hard-coded to 128 bytes
            id_length = 64;        // PSP returns length of 1 ID, if length isn't correct
            cmd_ret = SEV_RET_INVALID_LEN;
            break;
        }

        // Send the command
        ioctl_ret = sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if(ioctl_ret != 0)
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

void SEVDevice::get_family_model(uint32_t *family, uint32_t *model)
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

    get_family_model(&family, &model);
    printf("Platform Family %02x, Model %02x\n", family, model);

    printf("-------------------------------------------------------------\n\n");

    return (int)cmd_ret;
}

/*
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
    if(cmd_ret != SEV_RET_SUCCESS) {
        return cmd_ret;
    }

    if (get_platform_owner(&status_data) != PLATFORM_STATUS_OWNER_SELF) {
        switch (status_data.state) {
            case PLATFORM_WORKING:
                break;          // Can't Change Owner. Guests are running!
            case PLATFORM_UNINIT: {
                cmd_ret = factory_reset();  // Change owner from ext to self-owned
                if(cmd_ret != SEV_RET_SUCCESS) {
                    return cmd_ret;
                }
                break;
            }
            case PLATFORM_INIT: {
                cmd_ret = pek_gen();        // Self-owned to different self-owned
                if(cmd_ret != SEV_RET_SUCCESS) {
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

    if(!PEKMem)
        return SEV_RET_HWSEV_RET_PLATFORM;

    do {
        // Send platform_status command to get ownership status
        cmd_ret = platform_status((uint8_t *)&platform_status_data);
        if(cmd_ret != SEV_RET_SUCCESS)
            break;

        // Check if we're already externally owned
        if (get_platform_owner(&platform_status_data) != PLATFORM_STATUS_OWNER_EXTERNAL) {
            // Get the CSR
            sev_user_data_pek_csr pek_csr_data;                  // pek_csr
            sev_cert PEKcsr;
            cmd_ret = pek_csr((uint8_t *)&pek_csr_data, PEKMem, &PEKcsr);
            if(cmd_ret != SEV_RET_SUCCESS)
                break;

            // Sign the CSR
            // Fetch the OCA certificate
            // Submit the signed cert to PEKCertImport
            sev_user_data_pek_cert_import pek_cert_import_data;
            cmd_ret = pek_cert_import((uint8_t *)&pek_cert_import_data, &PEKcsr,
                                      oca_priv_key_file);
            if(cmd_ret != SEV_RET_SUCCESS)
                break;

            // Send platform_status command to get new ownership status
            cmd_ret = platform_status((uint8_t *)&platform_status_data);
            if(cmd_ret != SEV_RET_SUCCESS)
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

    // Set struct to 0
    memset(&id_buf, 0, sizeof(sev_user_data_get_id));

    do {
        cmd += "-P " + output_folder + " ";
        cmd += KDS_CERT_SITE;

        // Get the ID of the Platform
        // Send the command
        ioctl_ret = sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        // Note that Linux referrs to P0 and P1 as socket1 and socket2 (which is incorrect).
        //   So below, we are getting the ID for P0, which is the first socket
        char id0_buf[sizeof(id_buf.socket1)*2+1] = {0};  // 2 chars per byte +1 for null term
        for(uint8_t i = 0; i < sizeof(id_buf.socket1); i++)
        {
            sprintf(id0_buf+strlen(id0_buf), "%02x", id_buf.socket1[i]);
        }
        cmd += id0_buf;

        // The AMD KDS server only accepts requests every 10 seconds
        std::string cert_w_path = output_folder + id0_buf;
        char tmp_buf[sizeof(id_buf.socket1)*2+1] = {0};  // 2 chars per byte +1 for null term
        bool cert_found = false;
        int sec_to_sleep = 4;
        int retries = 0;
        int max_retries = (int)((10/sec_to_sleep)+1);
        while(!cert_found && retries <= max_retries) {
            if(!sev::execute_system_command(cmd, &output)) {
                printf("Error: pipe not opened for system command\n");
                cmd_ret = SEV_RET_UNSUPPORTED;
                break;
            }

            // Check if the file got downloaded
            if(sev::read_file(cert_w_path, tmp_buf, sizeof(tmp_buf)) != 0) {
                cert_found = true;
                break;
            }
            sleep(sec_to_sleep);
            printf("Trying again\n");
            retries++;
        }
        if(!cert_found) {
            printf("Error: command to get cek_ask cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Copy the file from (get_id) name to something known (cert_file)
        std::string to_cert_w_path = output_folder + cert_file;
        if(std::rename(cert_w_path.c_str(), to_cert_w_path.c_str()) != 0) {
            printf("Error: renaming cek cert file\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }
    } while (0);

    return cmd_ret;
}

int SEVDevice::get_ask_ark(const std::string output_folder,
                           const std::string cert_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    std::string cmd = "wget ";
    std::string output = "";
    uint32_t family = 0;
    uint32_t model = 0;
    std::string cert_w_path = "";

    do {
        cmd += "-P " + output_folder + " ";
        cert_w_path = output_folder;

        get_family_model(&family, &model);
        if(family == NAPLES_FAMILY && model >= NAPLES_MODEL_LOW && model <= NAPLES_MODEL_HIGH) {
            cmd += ASK_ARK_NAPLES_SITE;
            cert_w_path += ASK_ARK_NAPLES_FILE;
        }
        else if(family == ROME_FAMILY && model >= ROME_MODEL_LOW && model <= ROME_MODEL_HIGH) {
            cmd += ASK_ARK_ROME_SITE;
            cert_w_path += ASK_ARK_ROME_FILE;
            // TODO take printf out when Rome cert comes out
            printf("Note: the Rome .cert is NOT publically available yet. "\
                        "Please email your AMD rep to get the cert\n");
        }
        else {
            printf("Error: Unable to determine Platform type. " \
                        "Detected Family %i, Model %i\n", family, model);
            break;
        }

        // Download the certificate from the AMD server
        if(!sev::execute_system_command(cmd, &output)) {
            printf("Error: pipe not opened for system command\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Check if the file got downloaded
        char tmp_buf[100] = {0};  // Just try to read some amount of chars
        if(sev::read_file(cert_w_path, tmp_buf, sizeof(tmp_buf)) == 0) {
            printf("Error: command to get ask_ark cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Rename the file (_PlatformType) to something known (cert_file)
        std::string to_cert_w_path = output_folder + cert_file;
        if(std::rename(cert_w_path.c_str(), to_cert_w_path.c_str()) != 0) {
            printf("Error: renaming ask_ark cert file\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }
        cmd_ret = SEV_RET_SUCCESS;
    } while (0);

    return cmd_ret;
}

int SEVDevice::zip_certs(const std::string output_folder,
                         const std::string zip_name,
                         const std::string files_to_zip)
{
    int cmd_ret = SEV_RET_SUCCESS;
    std::string cmd = "";
    std::string output = "";
    std::string error = "zip error";

    cmd = "zip " + output_folder + zip_name + " " + files_to_zip;
    sev::execute_system_command(cmd, &output);

    if(output.find(error) != std::string::npos) {
        printf("Error when zipping up files!");
        cmd_ret = -1;
    }

    return cmd_ret;
}

#endif
