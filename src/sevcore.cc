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
#include <openssl/hmac.h>
#include <sys/ioctl.h>      // for ioctl()
#include <sys/mman.h>       // for mmap() and friends
#include <errno.h>          // for errorno
#include <fcntl.h>          // for O_RDWR
#include <unistd.h>         // for close()
#include <stdexcept>        // for std::runtime_error()

// The Linux Kernel's Platform Status command buffer is older/different than the
// current SEV API and has the Owner and ConfigES params as a single param called Flags
#define PLATFORM_STATUS_OWNER_OFFSET    0
#define PLATFORM_STATUS_CONFIGES_OFFSET 8
#define PLATFORM_OWNER_MASK (1UL << PLATFORM_STATUS_OWNER_OFFSET)
#define PLATFORM_ES_MASK    (1UL << PLATFORM_STATUS_CONFIGES_OFFSET)

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

int SEVDevice::sev_ioctl(COMMAND_CODE cmd, void *data, SEV_ERROR_CODE *cmd_ret)
{
    int ioctl_ret = -1;
    sev_issue_cmd arg;

    // Translate our COMMAND_CODEs to Linux ioctl commands
    switch(cmd) {
        case CMD_FACTORY_RESET: {
            arg.cmd = SEV_FACTORY_RESET;
            break;
        }
        case CMD_PLATFORM_STATUS: {
            arg.cmd = SEV_PLATFORM_STATUS;
            break;
        }
        case CMD_PEK_GEN: {
            arg.cmd = SEV_PEK_GEN;
            break;
        }
        case CMD_PEK_CSR: {
            arg.cmd = SEV_PEK_CSR;
            break;
        }
        case CMD_PDH_GEN: {
            arg.cmd = SEV_PDH_GEN;
            break;
        }
        case CMD_PDH_CERT_EXPORT: {
            arg.cmd = SEV_PDH_CERT_EXPORT;
            break;
        }
        case CMD_PEK_CERT_IMPORT: {
            arg.cmd = SEV_PEK_CERT_IMPORT;
            break;
        }
        case CMD_GET_ID: {
            arg.cmd = SEV_GET_ID;
            break;
        }
        case CMD_CALC_MEASUREMENT:
        case CMD_SET_SELF_OWNED:
        case CMD_SET_EXT_OWNED:
        default: {
            printf("Unexpected Command code! %02x\n", cmd);
            return ioctl_ret;
        }
    }

    arg.data = (uint64_t)data;

    ioctl_ret = ioctl(gSEVDevice.GetFD(), SEV_ISSUE_CMD, &arg);
    *cmd_ret = (SEV_ERROR_CODE)arg.error; // Convert Linux's sev_ret_code to our SEV_ERROR_CODE
    if(ioctl_ret != 0) {    // Sometimes you expect it to fail
        // printf("Error: cmd %#x ioctl_ret=%d (%#x)\n", cmd, ioctl_ret, arg.error);
    }

    return ioctl_ret;
}

SEV_ERROR_CODE SEVDevice::factory_reset()
{
    uint32_t data;      // Can't pass null
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_FACTORY_RESET, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

int SEVDevice::get_platform_owner(sev_user_data_status* data)
{
    return data->flags & PLATFORM_OWNER_MASK;
}

int SEVDevice::get_platform_es(sev_user_data_status* data)
{
    return data->flags & PLATFORM_ES_MASK;
}

SEV_ERROR_CODE SEVDevice::platform_status(sev_user_data_status *data)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_status));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PLATFORM_STATUS, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE SEVDevice::pek_gen()
{
    uint32_t data;      // Can't pass null
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PEK_GEN, &data, &cmd_ret);
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

SEV_ERROR_CODE SEVDevice::pek_csr(sev_user_data_pek_csr *data, void *PEKMem, SEV_CERT *PEKcsr)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_pek_csr));

    do {
        // Populate PEKCSR buffer with CSRLength = 0
        data->address = (uint64_t)PEKMem;
        data->length = 0;

        // Send the command. This is to get the MinSize length. If you
        // already know it, then you don't have to send the command twice
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PEK_CSR, data, &cmd_ret);
        if(ioctl_ret != -1)
            break;

        // Verify the results. Now the CSRLength will be updated to MinSize
        if(cmd_ret != ERROR_INVALID_LENGTH)
            break;

        // Send the command again with CSRLength=MinSize
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PEK_CSR, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

        // Verify the CSR complies to API specification
        memcpy(PEKcsr, (SEV_CERT*)data->address, sizeof(SEV_CERT));
        if(!validate_pek_csr(PEKcsr))
            break;

    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE SEVDevice::pdh_gen()
{
    uint32_t data;      // Can't pass null
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(&data, 0, sizeof(data));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PDH_GEN, &data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

SEV_ERROR_CODE SEVDevice::pdh_cert_export(sev_user_data_pdh_cert_export *data,
                               void *PDHCertMem, void *CertChainMem)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_pdh_cert_export));

    do {
        data->pdh_cert_address = (uint64_t)PDHCertMem;
        data->pdh_cert_len = sizeof(SEV_CERT);
        data->cert_chain_address = (uint64_t)CertChainMem;
        data->cert_chain_len = sizeof(SEV_CERT_CHAIN_BUF);

        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PDH_CERT_EXPORT, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

// wip dont want to be reading from a file. use opeenssl to generate
#define SEV_DEFAULT_DIR "../psp-sev-assets/"
#define OCAPrivateKeyFile SEV_DEFAULT_DIR "oca_key.pem"
#define OCACertFile SEV_DEFAULT_DIR "oca.cert"
SEV_ERROR_CODE SEVDevice::pek_cert_import(sev_user_data_pek_cert_import *data, SEV_CERT *PEKcsr)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    void *OCACert = malloc(sizeof(SEV_CERT));

    if(!OCACert)
        return ERROR_RESOURCE_LIMIT;

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
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_PEK_CERT_IMPORT, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    // Free memory
    free(OCACert);

    return cmd_ret;
}

// Must always pass in 128 bytes array, because of how linux /dev/sev ioctl works
SEV_ERROR_CODE SEVDevice::get_id(sev_user_data_get_id *data)
{
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    int ioctl_ret = -1;

    // Set struct to 0
    memset(data, 0, sizeof(sev_user_data_get_id));

    do {
        // Send the command
        ioctl_ret = gSEVDevice.sev_ioctl(CMD_GET_ID, data, &cmd_ret);
        if(ioctl_ret != 0)
            break;

    } while (0);

    return cmd_ret;
}

// We cannot call LaunchMeasure to get the MNonce because that command doesn't
// exist in this context, so we user the user input params for all of our data
// This function assumes the API version is at >= 0.17
SEV_ERROR_CODE SEVDevice::calc_measurement(measurement_t *user_data, HMACSHA256 *final_meas)
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
        if (HMAC_Update(ctx, (uint8_t*)&user_data->policy, sizeof(user_data->policy)) != 1)
            break;
        if (HMAC_Update(ctx, (uint8_t*)&user_data->digest, sizeof(user_data->digest)) != 1)
            break;
        // Use the same random MNonce as the FW in our validation calculations
        if (HMAC_Update(ctx, (uint8_t*)&user_data->mnonce, sizeof(user_data->mnonce)) != 1)
            break;
        if (HMAC_Final(ctx, (uint8_t*)final_meas, &MeasurementLength) != 1)  // size = 32
            break;

        cmd_ret = STATUS_SUCCESS;
    } while (0);

    HMAC_CTX_free(ctx);
    return cmd_ret;
}

/*
 * Note: You can not change the Platform Owner if Guests are running. That means
 *       the Platform cannot be in the WORKING state here. The ccp Kernel Driver
 *       will do its best to set the Platform state to whatever is required to
 *       run each command, but that does not include shutting down Guests to do so.
 */
SEV_ERROR_CODE SEVDevice::set_self_owned()
{
    sev_user_data_status status_data;  // Platform Status
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;

    do {
        cmd_ret = platform_status(&status_data);
        if(cmd_ret != STATUS_SUCCESS) {
            break;
        }

        if (get_platform_owner(&status_data) != PLATFORM_STATUS_OWNER_SELF) {
            cmd_ret = pek_gen();
        }
    } while (0);

    return cmd_ret;
}

/*
 * Note: You can not change the Platform Owner if Guests are running. That means
 *       the Platform cannot be in the WORKING state here. The ccp Kernel Driver
 *       will do its best to set the Platform state to whatever is required to
 *       run each command, but that does not include shutting down Guests to do so.
 */
SEV_ERROR_CODE SEVDevice::set_externally_owned()
{
    sev_user_data_status status_data;  // Platform Status
    SEV_ERROR_CODE cmd_ret = ERROR_UNSUPPORTED;
    void *PEKMem = malloc(sizeof(SEV_CERT));

    if(!PEKMem)
        return ERROR_RESOURCE_LIMIT;

    do {
        cmd_ret = platform_status(&status_data);
        if(cmd_ret != STATUS_SUCCESS)
            break;

        if (get_platform_owner(&status_data) != PLATFORM_STATUS_OWNER_EXTERNAL) {
            // Get the CSR
            sev_user_data_pek_csr pek_csr_data;                  // pek_csr
            SEV_CERT PEKcsr;
            cmd_ret = pek_csr(&pek_csr_data, PEKMem, &PEKcsr);
            if(cmd_ret != STATUS_SUCCESS)
                break;

            // Sign the CSR
            // Fetch the OCA certificate
            // Submit the signed cert to PEKCertImport
            sev_user_data_pek_cert_import pek_cert_import_data;
            cmd_ret = pek_cert_import(&pek_cert_import_data, &PEKcsr);
        }
    } while (0);

    // Free memory
    free(PEKMem);

    return cmd_ret;
}