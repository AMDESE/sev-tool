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

#ifndef sevcore_linux_h
#define sevcore_linux_h

// Class SEVDevice is for the SEV "device", as manifested by the special
// SEV FW test driver. struct ioctl_cmd is also defined by that driver.

#include "sevcert.h"
#include <cstddef>      // For size_t
#include <cstring>      // For memcmp
#include <stdio.h>
#include <string>

#define DEFAULT_SEV_DEVICE     "/dev/sev"

#define KDS_CERT_SITE           "https://kdsintfdev.amd.com/cek/id/"
#define AMD_SEV_DEVELOPER_SITE  "https://developer.amd.com/sev/"
#define ASK_ARK_PATH_SITE       "https://developer.amd.com/wp-content/resources/"
#define ASK_ARK_NAPLES_FILE     "ask_ark_naples.cert"
#define ASK_ARK_ROME_FILE       "ask_ark_rome.cert"
#define ASK_ARK_NAPLES_SITE      ASK_ARK_PATH_SITE ASK_ARK_NAPLES_FILE
#define ASK_ARK_ROME_SITE        ASK_ARK_PATH_SITE ASK_ARK_ROME_FILE

#define NAPLES_FAMILY       0x17UL      // 23
#define NAPLES_MODEL_LOW    0x00UL
#define NAPLES_MODEL_HIGH   0x0FUL
#define ROME_FAMILY         0x17UL      // 23
#define ROME_MODEL_LOW      0x30UL
#define ROME_MODEL_HIGH     0x3FUL

// A system physical address that should always be invalid.
// Used to test the SEV FW detects such invalid addresses and returns the
// correct error return value.
#define INVALID_ADDRESS ((void *)0xFD000000018)
#define BAD_ASID ((uint32_t)~0)
#define BAD_DEVICE_TYPE ((uint32_t)~0)
#define BAD_FAMILY_MODEL ((uint32_t)~0)

// Platform Status Buffer flags param was split up into owner/ES in API v0.17
#define PLAT_STAT_OWNER_OFFSET    0
#define PLAT_STAT_CONFIGES_OFFSET 8
#define PLAT_STAT_OWNER_MASK      (1U << PLAT_STAT_OWNER_OFFSET)
#define PLAT_STAT_ES_MASK         (1U << PLAT_STAT_CONFIGES_OFFSET)


// Class to access the special SEV FW API test suite driver.
class SEVDevice {
private:
    int mFd;
    int get_platform_owner(void* data);
    int get_platform_es(void* data);
    bool validate_pek_csr(SEV_CERT *PEKcsr);
    void get_family_model(uint32_t *family, uint32_t *model);

public:
    SEVDevice();
    ~SEVDevice();

    inline int GetFD(void) { return mFd; }
    int sev_ioctl(int cmd, void *data, int *cmd_ret);

    // Format for below input variables:
    // data is a uint8_t pointer to an empty buffer the size of the cmd_buffer
    // All other variables are specific input/output variables for that command
    // Each function sets the params in data to the input/output variables of the function
    int factory_reset(void);
    int platform_status(uint8_t *data);
    int pek_gen(void);
    int pek_csr(uint8_t *data, void *PEKMem, SEV_CERT *csr);
    int pdh_gen(void);
    int pdh_cert_export(uint8_t *data,
                                   void *PDHCertMem, void *CertChainMem);
    int pek_cert_import(uint8_t *data,
                                   SEV_CERT *csr,
                                   std::string& oca_priv_key_file,
                                   std::string& oca_cert_file);
    int get_id(void *data, void *IDMem, uint32_t id_length = 0);

    int sysinfo();
    int set_self_owned(void);
    int set_externally_owned(std::string& oca_priv_key_file,
                                        std::string& oca_cert_file);
    int generate_cek_ask(std::string& output_folder, std::string& cert_file);
    int get_ask_ark(std::string& output_folder, std::string& cert_file);
};


// We need precisely one instance of the SEVDevice class.
// Easiest to make it a global
extern SEVDevice gSEVDevice;

#endif /* sevcore_linux_h */
