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
// entire test suite to a new OS with a different driver requires only
// changing this file and the corresponding .cc file.

// Class SEVDevice is for the SEV "device", as manifested by the special
// SEV FW test driver. struct ioctl_cmd is also defined by that driver.
// Class SEVMem manages memory accessible by the SEV FW by using the
// special SEV FW test driver.
// Class SEVCommand is the base class of the classes defined for each of
// the SEV FW commands. It provides the Send() and CmdStat() methods to
// send an SEV FW command and get the status returned by the command.
// Macro BuildSEVCommandClass() defines a class based on the SEVCommand
// class for each of the SEV FW commands. Each command's class defines a
// public member variable "CmdBuf" that is the command's CommandBuffer as
// defined by the SEV FW API specification.

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
    int sev_ioctl(int cmd, void* data, int* sev_ret);

    int SetSelfOwned();
    int SetExternallyOwned();

    int factory_reset();
    int platform_status(sev_user_data_status* data);
    int pek_gen();
    int pek_csr(sev_user_data_pek_csr* data, void* PEKMem, SEV_CERT* csr);
    int pdh_gen();
    int pdh_cert_export(sev_user_data_pdh_cert_export* data,
                                   void* PDHCertMem,
                                void* CertChainMem);
    int pek_cert_import(sev_user_data_pek_cert_import* data, SEV_CERT *csr);
    int get_id(sev_user_data_get_id* data);
};


// We need precisely one instance of the SEVDevice class.
// The SEVMem class and the SEVCommand class both need it, so a
// global...
extern SEVDevice gSEVDevice;

#endif /* sevcore_h */
