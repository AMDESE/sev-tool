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

// Class to access the special SEV FW API test suite driver.
class SEVDevice {
private:
    int mFd;
    bool validate_pek_csr(SEV_CERT *csr);

public:
    SEVDevice();
    ~SEVDevice();

    inline int GetFD(void) { return mFd; }
    int sev_ioctl(int cmd, void *data, SEV_ERROR_CODE *cmd_ret);

    SEV_ERROR_CODE SetSelfOwned(void);
    SEV_ERROR_CODE SetExternallyOwned(void);

    SEV_ERROR_CODE factory_reset(void);
    SEV_ERROR_CODE platform_status(sev_user_data_status* data);
    SEV_ERROR_CODE pek_gen(void);
    SEV_ERROR_CODE pek_csr(sev_user_data_pek_csr* data, void* PEKMem, SEV_CERT* csr);
    SEV_ERROR_CODE pdh_gen(void);
    SEV_ERROR_CODE pdh_cert_export(sev_user_data_pdh_cert_export* data,
                                   void* PDHCertMem, void* CertChainMem);
    SEV_ERROR_CODE pek_cert_import(sev_user_data_pek_cert_import* data, SEV_CERT *csr);
    SEV_ERROR_CODE get_id(sev_user_data_get_id* data);
};


// We need precisely one instance of the SEVDevice class.
// Easiest to make it a global
extern SEVDevice gSEVDevice;

#endif /* sevcore_h */
