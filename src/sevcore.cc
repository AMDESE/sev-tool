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

#include "sevcert.h"
#include "sevcore.h"
#include "utilities.h"
#include <sys/ioctl.h>      // for ioctl()
#include <sys/mman.h>       // for mmap() and friends
#include <errno.h>          // for errorno
#include <fcntl.h>          // for O_RDWR
#include <unistd.h>         // for close()
#include <stdexcept>        // for std::runtime_error()

// The single instance of the SEVDevice class that everyone can
// access to get the mFd of the special SEV FW API test suite driver.
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

int SEVDevice::sev_ioctl(int cmd, void* data, int* sev_ret)
{
	int ioctl_ret = -1;
	sev_issue_cmd arg;

	arg.cmd = cmd;
	arg.data = (uint64_t)data;

	ioctl_ret = ioctl(gSEVDevice.GetFD(), SEV_ISSUE_CMD, &arg);
	*sev_ret = arg.error;
	if(ioctl_ret != 0) {    // Sometimes you expect it to fail
		// printf("Error: cmd %#x ioctl_ret=%d (%#x)\n", cmd, ioctl_ret, arg.error);
	}

	return ioctl_ret;
}

// Just believe it worked, for now. The flags parameter returned by
// platform_status doesn't exactly match the spec (should be Owner
// and Config as separate params), so I'm not exactly sure what it is.
// It can probably be used to see if the owner changed
int SEVDevice::SetSelfOwned()
{
    sev_user_data_status plat_stat_data;
    int cmd_ret = ERROR_UNSUPPORTED;

    do {
        cmd_ret = gSEVDevice.factory_reset();
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.pek_gen();
        if(cmd_ret != STATUS_SUCCESS)
            break;

        cmd_ret = gSEVDevice.platform_status(&plat_stat_data);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        // TODO verify that the platform is self-owned using
        // plat_stat_data's flag param
    } while (0);

    return cmd_ret;
}

// Just believe it worked, for now. The flags parameter returned by
// platform_status doesn't exactly match the spec (should be Owner
// and Config as separate params), so I'm not exactly sure what it is.
// It can probably be used to see if the owner changed
int SEVDevice::SetExternallyOwned()
{
    int cmd_ret = STATUS_SUCCESS;//ERROR_UNSUPPORTED;

    return cmd_ret;
}

int SEVDevice::factory_reset()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_FACTORY_RESET, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

int SEVDevice::platform_status(sev_user_data_status* data)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_status));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PLATFORM_STATUS, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

int SEVDevice::pek_gen()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_GEN, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
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

int SEVDevice::pek_csr(sev_user_data_pek_csr* data, void* PEKMem, SEV_CERT* PEKcsr)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_pek_csr));

    do {
        // Populate PEKCSR buffer with CSRLength = 0
        data->address = (uint64_t)PEKMem;
        data->length = 0;

        // Send the command. This is to get the MinSize length. If you
        // already know it, then you don't have to send the command twice
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_CSR, data, &cmd_ret);
        if(ioctl_ret != -1)
            break;

        // Verify the results. Now the CSRLength will be updated to MinSize
        if(cmd_ret != ERROR_INVALID_LENGTH)
            break;

        // Send the command again with CSRLength=MinSize
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_CSR, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Verify the CSR complies to API specification
        memcpy(PEKcsr, (SEV_CERT*)data->address, sizeof(SEV_CERT));
        if(!validate_pek_csr(PEKcsr))
            break;

    } while (0);

    return cmd_ret;
}

int SEVDevice::pdh_gen()
{
    uint32_t data;      // Can't pass null
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PDH_GEN, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

int SEVDevice::pdh_cert_export(sev_user_data_pdh_cert_export* data,
                               void* PDHCertMem,
                               void* CertChainMem)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_pdh_cert_export));

    do {
        data->pdh_cert_address = (uint64_t)PDHCertMem;
        data->pdh_cert_len = sizeof(SEV_CERT);
        data->cert_chain_address = (uint64_t)CertChainMem;
        data->cert_chain_len = sizeof(SEV_CERT_CHAIN_BUF);

        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PDH_CERT_EXPORT, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

// wip dont want to be reading from a file. use opeenssl to generate
#define SEV_DEFAULT_DIR "../psp-sev-assets/"
#define OCAPrivateKeyFile SEV_DEFAULT_DIR "oca_key.pem"
#define OCACertFile SEV_DEFAULT_DIR "oca.cert"
int SEVDevice::pek_cert_import(sev_user_data_pek_cert_import* data, SEV_CERT *PEKcsr)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    void* OCACert = malloc(sizeof(SEV_CERT));

    // Submit the signed cert to PEKCertImport
    memset(data, 0, sizeof(sev_user_data_pek_cert_import)); // Set struct to 0

    do {
        // Verify the CSR complies to API specification
        if(!validate_pek_csr(PEKcsr))
            break;

        // --------- Sign the CSR --------- //
        SEVCert CSRCert(*PEKcsr);
        CSRCert.SignWithKey(SEV_CERT_MAX_VERSION, SEVUsagePEK, SEVSigAlgoECDSASHA256,
                         OCAPrivateKeyFile, SEVUsageOCA, SEVSigAlgoECDSASHA256);

        // Fetch the OCA certificate
        size_t OCACertLength = 0;
        OCACertLength = ReadFile(OCACertFile, OCACert, sizeof(SEV_CERT));
        if(OCACertLength == 0) {
            printf("File not found: %s\n", OCACertFile);
            break;
        }

        data->pek_cert_address = (uint64_t)CSRCert.Data();
        data->pek_cert_len = sizeof(SEV_CERT);
        data->oca_cert_address = (uint64_t)OCACert;
        data->oca_cert_len = sizeof(SEV_CERT);

        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_PEK_CERT_IMPORT, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    // Free memory
    free(OCACert);

    return cmd_ret;
}

// Must always pass in 128 bytes array, because of how linux /dev/sev ioctl works
int SEVDevice::get_id(sev_user_data_get_id* data)
{
    int cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_get_id));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(SEV_GET_ID, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}