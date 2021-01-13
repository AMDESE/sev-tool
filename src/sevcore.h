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

#include "sevcert.h"
#include <cstddef>
#include <cstring>
#include <sys/stat.h>
#include <fstream>
#include <libvirt/libvirt.h>
#include <libvirt/libvirt-qemu.h>
#include <cstdio>
#include <string>

const std::string DEFAULT_SEV_DEVICE     = "/dev/sev";

#define AMD_SEV_DEVELOPER_SITE    "https://developer.amd.com/sev/"
#define ASK_ARK_PATH_SITE         "https://developer.amd.com/wp-content/resources/"

const std::string ASK_ARK_NAPLES_FILE    = "ask_ark_naples.cert";
const std::string ASK_ARK_ROME_FILE      = "ask_ark_rome.cert";
const std::string ASK_ARK_NAPLES_SITE    = ASK_ARK_PATH_SITE + ASK_ARK_NAPLES_FILE;
const std::string ASK_ARK_ROME_SITE      = ASK_ARK_PATH_SITE + ASK_ARK_ROME_FILE;

constexpr uint32_t NAPLES_FAMILY     = 0x17UL;      // 23
constexpr uint32_t NAPLES_MODEL_LOW  = 0x00UL;
constexpr uint32_t NAPLES_MODEL_HIGH = 0x0FUL;
constexpr uint32_t ROME_FAMILY       = 0x17UL;      // 23
constexpr uint32_t ROME_MODEL_LOW    = 0x30UL;
constexpr uint32_t ROME_MODEL_HIGH   = 0x3FUL;

enum __attribute__((mode(QI))) ePSP_DEVICE_TYPE {
    PSP_DEVICE_TYPE_INVALID = 0,
    PSP_DEVICE_TYPE_NAPLES  = 1,
    PSP_DEVICE_TYPE_ROME    = 2,
};

constexpr char LINUX_SEV_FILE[]         = "/dev/sev";
constexpr char QMP_SEV_CAPS_CMD[]       = "{\"execute\": \"query-sev-capabilities\"}";
constexpr char KVM_AND_SEV_PARAM[]      = "/sys/module/kvm_amd/parameters/sev";
constexpr char LIBVIRT_SEV_SUPPORTED[]  = "<sev supported='yes'>";
constexpr char COMMAND_NOT_FOUND[]      = "CommandNotFound";

// A system physical address that should always be invalid.
// Used to test the SEV FW detects such invalid addresses and returns the
// correct error return value.
constexpr uint64_t INVALID_ADDRESS  = (0xFD000000018);
constexpr uint32_t BAD_ASID         = ((uint32_t)~0);
constexpr uint32_t BAD_DEVICE_TYPE  = ((uint32_t)~0);
constexpr uint32_t BAD_FAMILY_MODEL = ((uint32_t)~0);

// Platform Status Buffer flags param was split up into owner/ES in API v0.17
constexpr uint8_t  PLAT_STAT_OWNER_OFFSET    = 0;
constexpr uint8_t  PLAT_STAT_CONFIGES_OFFSET = 8;
constexpr uint32_t PLAT_STAT_OWNER_MASK      = (1U << PLAT_STAT_OWNER_OFFSET);
constexpr uint32_t PLAT_STAT_ES_MASK         = (1U << PLAT_STAT_CONFIGES_OFFSET);

const std::string SHELL_VM_XML_1 = "<domain type='kvm'>"
                                   "<memory>256000</memory>"
                                   "<features>"
                                   "<acpi/>"
                                   "</features>";

const std::string SHELL_VM_XML_2 = "<memoryBacking>"
                                   "<locked/>"
                                   "</memoryBacking>"
                                   "</domain>";

const std::string SHELL_VM_NAME_BASE = "fceac9812431d";

struct sev_dom_details
{
    std::string ovmf_bin_loc;
    std::string c_bit_pos;
    std::string reduced_phys_bits;
};

typedef union
{
    struct
    {
        bool kernel  : 1;
        bool kvm     : 1;
        bool qemu    : 1;
        bool libvirt : 1;
        bool ovmf    : 1;
    };
    uint8_t raw;
} Deps;


namespace sev
{
// Global Functions that don't require ioctls
void get_family_model(uint32_t *family, uint32_t *model);
ePSP_DEVICE_TYPE get_device_type(void);
bool min_api_version(unsigned platform_major, unsigned platform_minor,
                     unsigned api_major, unsigned api_minor);
int get_ask_ark(const std::string output_folder, const std::string cert_file);
int zip_certs(const std::string output_folder, const std::string zip_name,
              const std::string files_to_zip);
} // namespace

// Class to access the special SEV FW API test suite driver.
class SEVDevice {
private:
    int mFd;
    Deps dep_bits;

    inline int get_fd(void) { return mFd; }
    int sev_ioctl(int cmd, void *data, int *cmd_ret);
    int pek_csr_sign(sev_cert *pek_csr, const std::string oca_priv_key_file,
                      sev_cert *oca_cert_out);

    std::string display_build_info(void);

    bool kvm_amd_sev_enabled(void);
    bool valid_qemu(virDomainPtr dom);
    bool valid_libvirt(virConnectPtr con);
    bool valid_ovmf(virDomainPtr dom, bool sev_enabled, char *sev_temp_dir);
    bool dom_state_up(virDomainPtr dom);
    bool dom_state_down(virDomainPtr dom);
    virDomainPtr start_new_domain(virConnectPtr con, std::string name,
                                  bool sev_enable, struct sev_dom_details dom_details,
                                  char *sev_temp_dir, char *ovmf_var_file);
    void create_sev_temp_dir(char **sev_temp_file);
    void create_sev_pipe_files(char *sev_temp_dir);
    void create_ovmf_var_file(std::string ovmf_bin, char *sev_temp_dir, char **ovmf_var_file);
    struct sev_dom_details find_sev_dom_details(virConnectPtr con);
    std::string find_sev_ovmf_bin(char *capabilities);
    std::string find_sev_c_bit_pos(char *capabilities);
    std::string find_sev_reduced_phys_bits(char *capabilities);
    std::string format_software_support_text(void);

    // Do NOT create ANY other constructors or destructors of any kind.
    SEVDevice(void)  = default;

    // Delete the copy and assignment operators which
    // may be automatically created by the compiler. The user
    // should not be able to modify the SEVDevice, as it is unique.
    SEVDevice(const SEVDevice&) = delete;
    SEVDevice& operator=(const SEVDevice&) = delete;

public:
    // Singleton Constructor - Threadsafe in C++ 11 and greater.
    static SEVDevice& get_sev_device(void);

    // Do NOT create ANY other constructors or destructors of any kind.
    ~SEVDevice(void);

    /*
     * Format for below input variables:
     * data is a uint8_t pointer to an empty buffer the size of the cmd_buffer
     * All other variables are specific input/output variables for that command
     * Each function sets the params in data to the input/output variables of
     *   the function
     */
    int factory_reset(void);
    int platform_status(uint8_t *data);
    int pek_gen(void);
    int pek_csr(uint8_t *data, void *pek_mem, sev_cert *csr);
    int pdh_gen(void);
    int pdh_cert_export(uint8_t *data, void *pdh_cert_mem,
                        void *cert_chain_mem);
    int pek_cert_import(uint8_t *data, sev_cert *signed_pek_csr,
                        sev_cert *oca_cert);
    int get_id(void *data, void *id_mem, uint32_t id_length = 0);

    void check_dependencies(void);

    int sys_info();
    int set_self_owned(void);
    int get_platform_owner(void *data);
    int get_platform_es(void *data);
    int set_externally_owned(const std::string oca_priv_key_file);
    int generate_cek_ask(const std::string output_folder,
                         const std::string cert_file);
};

#endif /* SEVCORE_H */
