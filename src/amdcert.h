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

#ifndef AMDCERT_H
#define AMDCERT_H

#include "sevapi.h"
#include "sevcore.h"    // for SEVDevice
#include <string>

constexpr uint32_t AMD_CERT_VERSION       = 0x01;
constexpr uint32_t AMD_CERT_ID_SIZE_BYTES = 16;      // sizeof(amd_cert:key_id_0 + amd_cert:key_id_1)
constexpr uint32_t AMD_CERT_KEY_BITS_2K   = 2048;
constexpr uint32_t AMD_CERT_KEY_BITS_4K   = 4096;
constexpr uint32_t AMD_CERT_KEY_BYTES_4K  = (AMD_CERT_KEY_BITS_4K/8);

static constexpr uint8_t amd_root_key_id_naples[AMD_CERT_ID_SIZE_BYTES] = {
        0x1b, 0xb9, 0x87, 0xc3, 0x59, 0x49, 0x46, 0x06,
        0xb1, 0x74, 0x94, 0x56, 0x01, 0xc9, 0xea, 0x5b,
};
static constexpr uint8_t amd_root_key_id_rome[AMD_CERT_ID_SIZE_BYTES] = {
        0xe6, 0x00, 0x21, 0x22, 0xfb, 0x58, 0x41, 0x93,
        0x99, 0xd1, 0x5f, 0xee, 0x7b, 0x13, 0x13, 0x51
};

// Public global functions
static std::string amd_empty = "NULL";
void print_amd_cert_readable(const amd_cert *cert, std::string &out_str = amd_empty);
void print_amd_cert_hex(const amd_cert *cert, std::string &out_str = amd_empty);

class AMDCert {
private:
    SEVDevice *m_sev_device;
    SEV_ERROR_CODE amd_cert_validate_sig(const amd_cert *cert,
                                         const amd_cert *parent,
                                         ePSP_DEVICE_TYPE device_type);
    SEV_ERROR_CODE amd_cert_validate_common(const amd_cert *cert);
    bool usage_is_valid(AMD_SIG_USAGE usage);
    SEV_ERROR_CODE amd_cert_validate(const amd_cert *cert,
                                     const amd_cert *parent,
                                     AMD_SIG_USAGE expected_usage,
                                     ePSP_DEVICE_TYPE device_type);
    SEV_ERROR_CODE amd_cert_public_key_hash(const amd_cert *cert,
                                            hmac_sha_256 *hash);
    // Retrieves information on device type (naples/rome) based on key id
    ePSP_DEVICE_TYPE get_device_type(const amd_cert *ark);
public:
    AMDCert() {}
    ~AMDCert() {};

    bool key_size_is_valid(size_t size);
    SEV_ERROR_CODE amd_cert_validate_ark(const amd_cert *ark);
    SEV_ERROR_CODE amd_cert_validate_ask(const amd_cert *ask,
                                         const amd_cert *ark);
    size_t amd_cert_get_size(const amd_cert *cert);
    SEV_ERROR_CODE amd_cert_export_pub_key(const amd_cert *cert,
                                           sev_cert *pub_key_cert);
    SEV_ERROR_CODE amd_cert_init(amd_cert *cert, const uint8_t *buffer);
};

#endif /* AMDCERT_H */
