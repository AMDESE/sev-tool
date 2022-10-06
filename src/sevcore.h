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

#ifndef SEVCORE_H
#define SEVCORE_H

#include "rmp.h"
#include "sevapi.h"
#include "sevcert.h"
#include <cstddef>
#include <cstring>
#include <sys/stat.h>
#include <fstream>
#include <cstdio>
#include <string>

const std::string DEFAULT_SEV_DEVICE     = "/dev/sev";

#define AMD_SEV_DEVELOPER_SITE    "https://developer.amd.com/sev/"
#define ASK_ARK_PATH_SITE         "https://developer.amd.com/wp-content/resources/"

const std::string ASK_ARK_NAPLES_FILE    = "ask_ark_naples.cert";
const std::string ASK_ARK_ROME_FILE      = "ask_ark_rome.cert";
const std::string ASK_ARK_MILAN_FILE     = "ask_ark_milan.cert";
const std::string ASK_ARK_NAPLES_SITE    = ASK_ARK_PATH_SITE + ASK_ARK_NAPLES_FILE;
const std::string ASK_ARK_ROME_SITE      = ASK_ARK_PATH_SITE + ASK_ARK_ROME_FILE;
const std::string ASK_ARK_MILAN_SITE     = ASK_ARK_PATH_SITE + ASK_ARK_MILAN_FILE;

constexpr uint32_t NAPLES_FAMILY     = 0x17UL;      // 23
constexpr uint32_t NAPLES_MODEL_LOW  = 0x00UL;
constexpr uint32_t NAPLES_MODEL_HIGH = 0x0FUL;
constexpr uint32_t ROME_FAMILY       = 0x17UL;      // 23
constexpr uint32_t ROME_MODEL_LOW    = 0x30UL;
constexpr uint32_t ROME_MODEL_HIGH   = 0x3FUL;
constexpr uint32_t MILAN_FAMILY      = 0x19UL;      // 25
constexpr uint32_t MILAN_MODEL_LOW   = 0x00UL;
constexpr uint32_t MILAN_MODEL_HIGH  = 0x0FUL;

enum __attribute__((mode(QI))) ePSP_DEVICE_TYPE {
    PSP_DEVICE_TYPE_INVALID = 0,
    PSP_DEVICE_TYPE_NAPLES  = 1,
    PSP_DEVICE_TYPE_ROME    = 2,
    PSP_DEVICE_TYPE_MILAN   = 3,
};

/**
 * A system physical address that should always be invalid.
 * Used to test the SEV FW detects such invalid addresses and returns the
 * correct error return value.
 */
constexpr uint64_t INVALID_ADDRESS  = (0xFFF00000018); // Needs to be bigger than 0xFFCFFFFFFFF (16TB memory)
constexpr uint32_t BAD_ASID         = ((uint32_t)~0);
constexpr uint32_t BAD_DEVICE_TYPE  = ((uint32_t)~0);
constexpr uint32_t BAD_FAMILY_MODEL = ((uint32_t)~0);

// Platform Status Buffer flags param was split up into owner/ES in API v0.17
constexpr uint8_t  PLAT_STAT_OWNER_OFFSET    = 0;
constexpr uint8_t  PLAT_STAT_CONFIGES_OFFSET = 8;
constexpr uint32_t PLAT_STAT_OWNER_MASK      = (1U << PLAT_STAT_OWNER_OFFSET);
constexpr uint32_t PLAT_STAT_ES_MASK         = (1U << PLAT_STAT_CONFIGES_OFFSET);

namespace sev
{
// Global Functions that don't require ioctls
void get_family_model(uint32_t *family, uint32_t *model);
ePSP_DEVICE_TYPE get_device_type();
bool min_api_version(unsigned platform_major, unsigned platform_minor,
                     unsigned api_major, unsigned api_minor);
int get_ask_ark(const std::string output_folder, const std::string cert_file);
int get_ask_ark_pem(const std::string output_folder, const std::string cert_chain_file,
                    const std::string ask_file, const std::string ark_file);
int zip_certs(const std::string output_folder, const std::string zip_name,
              const std::string files_to_zip);
} // namespace

// Class to access the special SEV FW API test suite driver.
class SEVDevice {
private:
    int mFd{-1};

    inline int get_fd() { return mFd; }
    int sev_ioctl(int cmd, void *data, int *cmd_ret);

    static std::string display_build_info();

    // Do NOT create ANY other constructors or destructors of any kind.
    SEVDevice()  = default;

    // Delete the copy and assignment operators which
    // may be automatically created by the compiler. The user
    // should not be able to modify the SEVDevice, as it is unique.
    SEVDevice(const SEVDevice&) = delete;
    SEVDevice& operator=(const SEVDevice&) = delete;

public:
    // Singleton Constructor - Threadsafe in C++ 11 and greater.
    static SEVDevice& get_sev_device();

    // Do NOT create ANY other constructors or destructors of any kind.
    ~SEVDevice();

    /*
     * Format for below input variables:
     * data is a uint8_t pointer to an empty buffer the size of the cmd_buffer
     * All other variables are specific input/output variables for that command
     * Each function sets the params in data to the input/output variables of
     *   the function
     */
    int factory_reset();
    int platform_status(uint8_t *data);
    int pek_gen();
    int pek_csr(uint8_t *data, void *pek_mem, sev_cert *csr);
    int pdh_gen();
    int pdh_cert_export(uint8_t *data, sev_cert_t const *pdh_cert_mem,
                               sev_cert_chain_buf_t const *cert_chain_mem);
    int pek_cert_import(uint8_t *data, sev_cert *pek_csr,
                        sev_cert *oca_cert);
    int get_id(void *data, void *id_mem, uint32_t id_length = 0);

    static int sys_info();
    int set_self_owned();
    static int get_platform_owner(void *data);
    static int get_platform_es(void *data);
    int generate_cek_ask(const std::string output_folder,
                         const std::string cert_file);
    int generate_vcek_ask(const std::string output_folder,
                          const std::string vcek_der_file,
                          const std::string vcek_pem_file);
    int request_platform_status(snp_platform_status_buffer *plat_status);
    void request_tcb_data(snp_tcb_version &tcb_data);
};

#endif /* SEVCORE_H */
