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

#ifndef sevcore_h
#define sevcore_h

// This file abstracts sevapi.h in to C++ classes. The implementation is
// closely tied to the special SEV FW test driver. Hopefully, porting the
// entire tool to a new OS with a different driver requires only
// changing this file and the corresponding .cc file.

// Class SEVDevice is for the SEV "device", as manifested by the special
// SEV FW test driver. struct ioctl_cmd is also defined by that driver.

#include "sevapi.h"
#include "linux/psp-sev.h"
#include <openssl/sha.h>  // For SHA256_DIGEST_LENGTH
#include <cstddef>      // For size_t
#include <cstring>      // For memcmp
#include <stdio.h>

#define DEFAULT_SEV_DEVICE     "/dev/sev"

// A system physical address that should always be invalid.
// Used to test the SEV FW detects such invalid addresses and returns the
// correct error return value.
#define INVALID_ADDRESS ((void *)0xFD000000018)
#define BAD_ASID ((uint32_t)~0)
#define BAD_DEVICE_TYPE ((uint32_t)~0)
#define BAD_FAMILY_MODEL ((uint32_t)~0)

// Command list
typedef enum COMMAND_CODE {
    CMD_FACTORY_RESET    = 0x00,
    CMD_PLATFORM_STATUS  = 0x01,
    CMD_PEK_GEN          = 0x02,
    CMD_PEK_CSR          = 0x03,
    CMD_PDH_GEN          = 0x04,
    CMD_PDH_CERT_EXPORT  = 0x05,
    CMD_PEK_CERT_IMPORT  = 0x06,
    CMD_GET_ID           = 0x07,

    CMD_CALC_MEASUREMENT = 0x08,
    CMD_SET_SELF_OWNED   = 0x09,
    CMD_SET_EXT_OWNED    = 0x0A,

    CMD_MAX,
} COMMAND_CODE;

#define LAUNCH_MEASURE_CTX 0x4
struct measurement_t {
    uint8_t  meas_ctx;  // LAUNCH_MEASURE_CTX
    uint8_t  api_major;
    uint8_t  api_minor;
    uint8_t  build_id;
    uint32_t policy;    // SEV_POLICY
    uint8_t digest[SHA256_DIGEST_LENGTH];   // gctx_ld
    Nonce128 mnonce;
    AES128Key tik;
};


// Class to access the special SEV FW API test suite driver.
class SEVDevice {
private:
    int mFd;
    bool validate_pek_csr(SEV_CERT *csr);
    int get_platform_owner(sev_user_data_status* data);
    int get_platform_es(sev_user_data_status* data);

public:
    SEVDevice();
    ~SEVDevice();

    inline int GetFD(void) { return mFd; }
    int sev_ioctl(COMMAND_CODE cmd, void *data, SEV_ERROR_CODE *cmd_ret);

    SEV_ERROR_CODE factory_reset(void);
    SEV_ERROR_CODE platform_status(sev_user_data_status *data);
    SEV_ERROR_CODE pek_gen(void);
    SEV_ERROR_CODE pek_csr(sev_user_data_pek_csr *data, void *PEKMem, SEV_CERT *csr);
    SEV_ERROR_CODE pdh_gen(void);
    SEV_ERROR_CODE pdh_cert_export(sev_user_data_pdh_cert_export *data,
                                   void *PDHCertMem, void *CertChainMem);
    SEV_ERROR_CODE pek_cert_import(sev_user_data_pek_cert_import *data, SEV_CERT *csr);
    SEV_ERROR_CODE get_id(sev_user_data_get_id *data);

    SEV_ERROR_CODE calc_measurement(measurement_t *user_data, HMACSHA256 *final_meas);
    SEV_ERROR_CODE set_self_owned(void);
    SEV_ERROR_CODE set_externally_owned(void);
};


// We need precisely one instance of the SEVDevice class.
// Easiest to make it a global
extern SEVDevice gSEVDevice;

#endif /* sevcore_h */
