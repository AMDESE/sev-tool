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

// The single instance of the SEVDevice class that everyone can
// access to get the mFd of the kernel driver.
SEVDevice gSEVDevice;

SEVDevice::SEVDevice()
{
    mFd = open(DEFAULT_SEV_DEVICE, O_RDWR);
    if (mFd < 0) {
        throw std::runtime_error("Can't open " DEFAULT_SEV_DEVICE "!\n");
    }
}

SEVDevice::~SEVDevice()
{
    if (mFd >= 0) {
        close(mFd);
    }
    mFd = -1;
}

int SEVDevice::sev_ioctl(int cmd, void *data, int *cmd_ret)
{
    int ioctl_ret = -1;
    sev_issue_cmd arg;

    arg.cmd = (uint32_t)cmd;
    arg.data = (uint64_t)data;

    ioctl_ret = ioctl(gSEVDevice.GetFD(), SEV_ISSUE_CMD, &arg);
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
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_FACTORY_RESET, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

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
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_status));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PLATFORM_STATUS, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return (int)cmd_ret;
}

int SEVDevice::pek_gen()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_GEN, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return (int)cmd_ret;
}

bool SEVDevice::validate_pek_csr(SEV_CERT *PEKcsr)
{
    if(PEKcsr->Version     == 1                     &&
       PEKcsr->PubkeyUsage == SEVUsagePEK           &&
       PEKcsr->PubkeyAlgo  == SEVSigAlgoECDSASHA256 &&
       PEKcsr->Sig1Usage   == SEVUsageInvalid       &&
       PEKcsr->Sig1Algo    == SEVSigAlgoInvalid     &&
       PEKcsr->Sig2Usage   == SEVUsageInvalid       &&
       PEKcsr->Sig2Algo    == SEVSigAlgoInvalid) {
        return true;
    }
    else {
        return false;
    }
}

int SEVDevice::pek_csr(uint8_t *data, void *PEKMem, SEV_CERT *PEKcsr)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pek_csr *data_buf = (sev_user_data_pek_csr *)data;

    // Set struct to 0
    memset(data_buf, 0, sizeof(sev_user_data_pek_csr));

    do {
        // Populate PEKCSR buffer with CSRLength = 0
        data_buf->address = (uint64_t)PEKMem;
        data_buf->length = 0;

        // Send the command. This is to get the MinSize length. If you
        // already know it, then you don't have to send the command twice
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_CSR, data_buf, &cmd_ret);
        if(ioctl_ret != -1)
            break;

        // Verify the results. Now the CSRLength will be updated to MinSize
        if(cmd_ret != SEV_RET_INVALID_LEN)
            break;

        // Send the command again with CSRLength=MinSize
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_CSR, data_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Verify the CSR complies to API specification
        memcpy(PEKcsr, (SEV_CERT*)data_buf->address, sizeof(SEV_CERT));
        if(!validate_pek_csr(PEKcsr))
            break;

    } while (0);

    return (int)cmd_ret;
}

int SEVDevice::pdh_gen()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PDH_GEN, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return (int)cmd_ret;
}

int SEVDevice::pdh_cert_export(uint8_t *data,
                               void *PDHCertMem, void *CertChainMem)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pdh_cert_export *data_buf = (sev_user_data_pdh_cert_export *)data;

    // Set struct to 0
    memset(data_buf, 0, sizeof(sev_user_data_pdh_cert_export));

    do {
        data_buf->pdh_cert_address = (uint64_t)PDHCertMem;
        data_buf->pdh_cert_len = sizeof(SEV_CERT);
        data_buf->cert_chain_address = (uint64_t)CertChainMem;
        data_buf->cert_chain_len = sizeof(SEV_CERT_CHAIN_BUF);

        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PDH_CERT_EXPORT, data_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return (int)cmd_ret;
}

// todo. dont want to be reading from a file. use openssl to generate
int SEVDevice::pek_cert_import(uint8_t *data,
                                          SEV_CERT *PEKcsr,
                                          std::string& oca_priv_key_file,
                                          std::string& oca_cert_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_pek_cert_import *data_buf = (sev_user_data_pek_cert_import *)data;

    void *OCACert = malloc(sizeof(SEV_CERT));

    if(!OCACert)
        return SEV_RET_HWSEV_RET_PLATFORM;

    // Submit the signed cert to PEKCertImport
    memset(data_buf, 0, sizeof(sev_user_data_pek_cert_import)); // Set struct to 0

    do {
        // Verify the CSR complies to API specification
        if(!validate_pek_csr(PEKcsr))
            break;

        // --------- Sign the CSR --------- //
        SEVCert CSRCert(*PEKcsr);
        CSRCert.SignWithKey(SEV_CERT_MAX_VERSION, SEVUsagePEK, SEVSigAlgoECDSASHA256,
                         oca_priv_key_file, SEVUsageOCA, SEVSigAlgoECDSASHA256);

        // Fetch the OCA certificate
        size_t OCACertLength = 0;
        OCACertLength = ReadFile(oca_cert_file, OCACert, sizeof(SEV_CERT));
        if(OCACertLength == 0) {
            printf("File not found: %s\n", oca_cert_file.c_str());
            break;
        }

        data_buf->pek_cert_address = (uint64_t)CSRCert.Data();
        data_buf->pek_cert_len = sizeof(SEV_CERT);
        data_buf->oca_cert_address = (uint64_t)OCACert;
        data_buf->oca_cert_len = sizeof(SEV_CERT);

        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_CERT_IMPORT, data_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    // Free memory
    free(OCACert);

    return (int)cmd_ret;
}

// Must always pass in 128 bytes array, because of how linux /dev/sev ioctl works
int SEVDevice::get_id(void *data, void *IDMem, uint32_t id_length)
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
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        memcpy(IDMem, &id_buf, id_length);
    } while (0);

    // The other functions in this file can do a direct mapping of the Linux
    //   struct to the SEV API struct in sevapi.h, however, for this function,
    //   this Linux struct doesn't match (at all) the API
    // Hard coded hack mapping to sevapi.h. Don't want to include sevapi.h in this file
    ((uint64_t *)data)[0] = (uint64_t)IDMem;      // Set address of IDMem as 64 bit PAddr from sevapi.h
    ((uint32_t *)data)[2] = id_length;  // 3rd 32-bit chunk in the cmd_buf

    return (int)cmd_ret;
}

static std::string DisplayBuildInfo()
{
    uint8_t status_data[sizeof(SEV_PLATFORM_STATUS_CMD_BUF)];
    SEV_PLATFORM_STATUS_CMD_BUF *status_data_buf = (SEV_PLATFORM_STATUS_CMD_BUF *)&status_data;
    int cmd_ret = -1;

    std::string api_major_ver = "API_Major: xxx";
    std::string api_minor_ver = "API_Minor: xxx";
    std::string build_id_ver  = "BuildID: xxx";

    cmd_ret = gSEVDevice.platform_status(status_data);
    if (cmd_ret != 0)
        return "";

    char MajorBuf[4], MinorBuf[4], BuildIDBuf[4];          // +1 for Null char
    sprintf(MajorBuf, "%d", status_data_buf->ApiMajor);
    sprintf(MinorBuf, "%d", status_data_buf->ApiMinor);
    sprintf(BuildIDBuf, "%d", status_data_buf->BuildID);
    api_major_ver.replace(11, 3, MajorBuf);
    api_minor_ver.replace(11, 3, MinorBuf);
    build_id_ver.replace(9, 3, BuildIDBuf);

    return api_major_ver + ", " + api_minor_ver + ", " + build_id_ver;
}

void SEVDevice::get_family_model(uint32_t *family, uint32_t *model)
{
    std::string cmd = "";
    std::string fam_str = "";
    std::string model_str = "";

    cmd = "lscpu | grep -E \"CPU family:\" | awk {'print $3'}";
    ExecuteSystemCommand(cmd, &fam_str);
    cmd = "lscpu | grep -E \"Model:\" | awk {'print $2'}";
    ExecuteSystemCommand(cmd, &model_str);

    *family = std::stoi(fam_str, NULL, 10);
    *model = std::stoi(model_str, NULL, 10);
}

int SEVDevice::sysinfo()
{
    int cmd_ret = SEV_RET_SUCCESS;
    std::string cmd = "";
    std::string output = "";
    uint32_t family = 0;
    uint32_t model = 0;

    printf("-------------------------System Info-------------------------");
    // Exec bash commands to get info on user's platform and append to the output string
    cmd = "echo -n 'Hostname: '; hostname";
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'BIOS Version: '; dmidecode -s bios-version";
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'BIOS Release Date: '; dmidecode -s bios-release-date";
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'SMT/Multi-Threading Status Per Socket: \n'; lscpu | grep -E \"^CPU\\(s\\):|Thread\\(s\\) per core|Core\\(s\\) per socket|Socket\\(s\\)\"";
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'Processor Frequency (all sockets): \n'; dmidecode -s processor-frequency";
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'Operating System: '; cat /etc/os-release | grep \"PRETTY_NAME=\" | sed 's/.*=//'";        // cat /etc/issue
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'Kernel Version: '; uname -r";
    ExecuteSystemCommand(cmd, &output);
    cmd = "echo -n 'Git Commit #: '; cat \"../.git/refs/heads/master\"";
    ExecuteSystemCommand(cmd, &output);

    // Print results of all ExecuteSystemCommand calls
    printf("\n%s", output.c_str());

    std::string BuildInfo = DisplayBuildInfo();
    printf("Firmware Version: %s\n", BuildInfo.c_str());

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

    do {
        cmd_ret = platform_status((uint8_t *)&status_data);
        if(cmd_ret != SEV_RET_SUCCESS) {
            break;
        }

        if (get_platform_owner(&status_data) != PLATFORM_STATUS_OWNER_SELF) {
            cmd_ret = pek_gen();
        }
    } while (0);

    return (int)cmd_ret;
}

/*
 * Note: You can not change the Platform Owner if Guests are running. That means
 *       the Platform cannot be in the WORKING state here. The ccp Kernel Driver
 *       will do its best to set the Platform state to whatever is required to
 *       run each command, but that does not include shutting down Guests to do so.
 */
int SEVDevice::set_externally_owned(std::string& oca_priv_key_file,
                                               std::string& oca_cert_file)
{
    sev_user_data_status status_data;  // Platform Status
    int cmd_ret = SEV_RET_UNSUPPORTED;
    void *PEKMem = malloc(sizeof(SEV_CERT));

    if(!PEKMem)
        return SEV_RET_HWSEV_RET_PLATFORM;

    do {
        cmd_ret = platform_status((uint8_t *)&status_data);
        if(cmd_ret != SEV_RET_SUCCESS)
            break;

        if (get_platform_owner(&status_data) != PLATFORM_STATUS_OWNER_EXTERNAL) {
            // Get the CSR
            sev_user_data_pek_csr pek_csr_data;                  // pek_csr
            SEV_CERT PEKcsr;
            cmd_ret = pek_csr((uint8_t *)&pek_csr_data, PEKMem, &PEKcsr);
            if(cmd_ret != SEV_RET_SUCCESS)
                break;

            // Sign the CSR
            // Fetch the OCA certificate
            // Submit the signed cert to PEKCertImport
            sev_user_data_pek_cert_import pek_cert_import_data;
            cmd_ret = pek_cert_import((uint8_t *)&pek_cert_import_data, &PEKcsr,
                                      oca_priv_key_file, oca_cert_file);
        }
    } while (0);

    // Free memory
    free(PEKMem);

    return (int)cmd_ret;
}

// TODO. Try to use curl as a git submodule
int SEVDevice::generate_cek_ask(std::string& output_folder, std::string& cert_file)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    int ioctl_ret = -1;
    sev_user_data_get_id id_buf;
    std::string cmd = "wget ";
    std::string output = "";

    // Set struct to 0
    memset(&id_buf, 0, sizeof(sev_user_data_get_id));

    do {
        // Prepare the cmd string
        if(output_folder == "") {
           output_folder = "./";
        }
        cmd += "-P " + output_folder + " ";
        cmd += KDS_CERT_SITE;

        // Get the ID of the Platform
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_GET_ID, &id_buf, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Copy the resulting IDs into the real buffer allocated for them
        char id1_buf[sizeof(id_buf.socket1)*2+1] = {0};  // 2 chars per byte +1 for null term
        for(uint8_t i = 0; i < sizeof(id_buf.socket1); i++)
        {
            sprintf(id1_buf+strlen(id1_buf), "%02x", id_buf.socket1[i]);
        }
        cmd += id1_buf;

        // Pass in the ID of Socket1 to the KDS server and download the certificate
        if(!ExecuteSystemCommand(cmd, &output)) {
            printf("Error: pipe not opened for system command\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Check if the file got downloaded
        std::string cert_w_path = output_folder + "/" + id1_buf;
        char tmp_buf[sizeof(id_buf.socket1)*2+1] = {0};  // 2 chars per byte +1 for null term
        if(ReadFile(cert_w_path, tmp_buf, sizeof(tmp_buf)) == 0) {
            printf("Error: command to get cek_ask cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Copy the file from (get_id) name to something known (cert_file)
        std::string to_cert_w_path = output_folder + "/" + cert_file;
        if(std::rename(cert_w_path.c_str(), to_cert_w_path.c_str()) != 0) {
            printf("Error: renaming cert file\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }
    } while (0);

    return cmd_ret;
}

// TODO. Try to use curl as a git submodule
int SEVDevice::get_ask_ark(std::string& output_folder)
{
    int cmd_ret = SEV_RET_UNSUPPORTED;
    std::string cmd = "wget ";
    std::string output = "";
    uint32_t family = 0;
    uint32_t model = 0;
    std::string cert_w_path = "";

    do {
        // Prepare the cmd string
        if(output_folder == "") {
           output_folder = "./";
        }
        cmd += "-P " + output_folder + " ";
        cert_w_path = output_folder + "/";

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
        if(!ExecuteSystemCommand(cmd, &output)) {
            printf("Error: pipe not opened for system command\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }

        // Check if the file got downloaded
        char tmp_buf[100] = {0};  // Just try to read some amount of chars
        if(ReadFile(cert_w_path, tmp_buf, sizeof(tmp_buf)) == 0) {
            printf("Error: command to get ask_ark cert failed\n");
            cmd_ret = SEV_RET_UNSUPPORTED;
            break;
        }
    } while (0);

    return cmd_ret;
}
#endif
