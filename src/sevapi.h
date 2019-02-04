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

#ifndef sevapi_h
#define sevapi_h

// This file puts in to C/C++ form the definitions from the SEV FW spec.
// It should remain usable purely from C

#include <stdint.h>

typedef enum SEV_API_COMMANDS
{
    NO_COMMAND          = 0x0,
    INIT                = 0x1,
    SHUTDOWN            = 0x2,
    PLATFORM_RESET      = 0x3,
    PLATFORM_STATUS     = 0x4,
    PEK_GEN             = 0x5,
    PEK_CSR             = 0x6,
    PEK_CERT_IMPORT     = 0x7,
    PDH_CERT_EXPORT     = 0x8,
    PDH_GEN             = 0x9,
    DF_FLUSH            = 0xA,
    DOWNLOAD_FIRMWARE   = 0xB,
    GET_ID              = 0xC,
    DECOMMISSION        = 0x20,
    ACTIVATE            = 0x21,
    DEACTIVATE          = 0x22,
    GUEST_STATUS        = 0x23,
    COPY                = 0x24,
    ACTIVATE_EX         = 0x25,
    LAUNCH_START        = 0x30,
    LAUNCH_UPDATE_DATA  = 0x31,
    LAUNCH_UPDATE_VMSA  = 0x32,
    LAUNCH_MEASURE      = 0x33,
    LAUNCH_SECRET       = 0x34,
    LAUNCH_FINISH       = 0x35,
    SEND_START          = 0x40,
    SEND_UPDATE_DATA    = 0x41,
    SEND_UPDATE_VMSA    = 0x42,
    SEND_FINISH         = 0x43,
    RECEIVE_START       = 0x50,
    RECEIVE_UPDATE_DATA = 0x51,
    RECEIVE_UPDATE_VMSA = 0x52,
    RECEIVE_FINISH      = 0x53,
    DBG_DECRYPT         = 0x60,
    DBG_ENCRYPT         = 0x61,
} SEV_API_COMMAND_CODE;

typedef enum SEV_PLATFORM_STATE
{
    PLATFORM_UNINIT     = 0,
    PLATFORM_INIT       = 1,
    PLATFORM_WORKING    = 2,
} SEV_PLATFORM_STATE;

typedef enum SEV_GUEST_STATE
{
    GUEST_UNINIT        = 0,
    GUEST_LUPDATE       = 1,
    GUEST_LSECRET       = 2,
    GUEST_RUNNING       = 3,
    GUEST_SUPDATE       = 4,
    GUEST_RUPDATE       = 5,
} SEV_GUEST_STATE;

typedef enum SEV_ERROR_CODE
{
    STATUS_SUCCESS                  = 0x00,
    ERROR_INVALID_PLATFORM_STATE    = 0x01,
    ERROR_INVALID_GUEST_STATE       = 0x02,
    ERROR_INVALID_CONFIG            = 0x03,
    ERROR_INVALID_LENGTH            = 0x04,
    ERROR_ALREADY_OWNED             = 0x05,
    ERROR_INVALID_CERTIFICATE       = 0x06,
    ERROR_POLICY_FAILURE            = 0x07,
    ERROR_INACTIVE                  = 0x08,
    ERROR_INVALID_ADDRESS           = 0x09,
    ERROR_BAD_SIGNATURE             = 0x0A,
    ERROR_BAD_MEASUREMENT           = 0x0B,
    ERROR_ASID_OWNED                = 0x0C,
    ERROR_INVALID_ASID              = 0x0D,
    ERROR_WBINVD_REQUIRED           = 0x0E,
    ERROR_DFFLUSH_REQUIRED          = 0x0F,
    ERROR_INVALID_GUEST             = 0x10,
    ERROR_INVALID_COMMAND           = 0x11,
    ERROR_ACTIVE                    = 0x12,
    ERROR_HWERROR_PLATFORM          = 0x13,
    ERROR_HWERROR_UNSAFE            = 0x14,
    ERROR_UNSUPPORTED               = 0x15,
} SEV_ERROR_CODE;

// Definition of API-defined Encryption and HMAC values
typedef uint8_t AES128Key[128/8];
typedef uint8_t HMACKey128[128/8];
typedef uint8_t HMACSHA256[256/8];
typedef uint8_t HMACSHA512[512/8];
typedef uint8_t Nonce128[128/8];
typedef uint8_t IV128[128/8];

// Definition of API-defined PKI structures

#define SEV_RSA_PUBKEY_MAX_BITS     4096
#define SEV_ECDSA_PUBKEY_MAX_BITS   576
#define SEV_ECDH_PUBKEY_MAX_BITS    576
#define SEV_PUBKEY_SIZE             (SEV_RSA_PUBKEY_MAX_BITS/8)

typedef struct __attribute__ ((__packed__)) SEV_RSA_PUBKEY
{
    uint32_t    ModulusSize;
    uint8_t     PubExp[SEV_RSA_PUBKEY_MAX_BITS/8];
    uint8_t     Modulus[SEV_RSA_PUBKEY_MAX_BITS/8];
} SEV_RSA_PUBKEY;

typedef enum SEV_EC {
    SEVECInvalid = 0,
    SEVECP256    = 1,
    SEVECP384    = 2,
} SEV_EC;

typedef struct __attribute__ ((__packed__)) SEV_ECDSA_PUBKEY
{
    uint32_t    Curve;      // SEV_EC
    uint8_t     QX[SEV_ECDSA_PUBKEY_MAX_BITS/8];
    uint8_t     QY[SEV_ECDSA_PUBKEY_MAX_BITS/8];
    uint8_t     RMBZ[SEV_PUBKEY_SIZE-2*SEV_ECDSA_PUBKEY_MAX_BITS/8-sizeof(uint32_t)];
} SEV_ECDSA_PUBKEY;

typedef struct __attribute__ ((__packed__)) SEV_ECDH_PUBKEY
{
    uint32_t    Curve;      // SEV_EC
    uint8_t     QX[SEV_ECDH_PUBKEY_MAX_BITS/8];
    uint8_t     QY[SEV_ECDH_PUBKEY_MAX_BITS/8];
    uint8_t     RMBZ[SEV_PUBKEY_SIZE-2*SEV_ECDH_PUBKEY_MAX_BITS/8-sizeof(uint32_t)];
} SEV_ECDH_PUBKEY;

typedef union
{
    SEV_RSA_PUBKEY      RSA;
    SEV_ECDSA_PUBKEY    ECDSA;
    SEV_ECDH_PUBKEY     ECDH;
} SEV_PUBKEY;

#define SEV_RSA_SIG_MAX_BITS        4096
#define SEV_ECDSA_SIG_COMP_MAX_BITS 576
#define SEV_SIG_SIZE                (SEV_RSA_SIG_MAX_BITS/8)

typedef struct __attribute__ ((__packed__)) SEV_RSA_SIG
{
    uint8_t     S[SEV_RSA_SIG_MAX_BITS/8];
} SEV_RSA_SIG;

typedef struct __attribute__ ((__packed__)) SEV_ECDSA_SIG
{
    uint8_t     R[SEV_ECDSA_SIG_COMP_MAX_BITS/8];
    uint8_t     S[SEV_ECDSA_SIG_COMP_MAX_BITS/8];
    uint8_t     RMBZ[SEV_SIG_SIZE-2*SEV_ECDSA_SIG_COMP_MAX_BITS/8];
} SEV_ECDSA_SIG;

typedef union
{
    SEV_RSA_SIG     RSA;
    SEV_ECDSA_SIG   ECDSA;
} SEV_SIG;

typedef enum SEV_USAGE {
    SEVUsageARK     = 0,
    SEVUsageASK     = 0x13,
    SEVUsageInvalid = 0x1000,
    SEVUsageOCA     = 0x1001,
    SEVUsagePEK     = 0x1002,
    SEVUsagePDH     = 0x1003,
    SEVUsageCEK     = 0x1004,
} SEV_USAGE;

typedef enum SEV_SIG_ALGO {
    SEVSigAlgoInvalid       = 0x0,
    SEVSigAlgoRSASHA256     = 0x1,
    SEVSigAlgoECDSASHA256   = 0x2,
    SEVSigAlgoECDHSHA256    = 0x3,
    SEVSigAlgoRSASHA384     = 0x101,
    SEVSigAlgoECDSASHA384   = 0x102,
    SEVSigAlgoECDHSHA384    = 0x103,
} SEV_SIG_ALGO;

#define SEV_CERT_MAX_VERSION    1       // Max supported version
#define SEV_CERT_MAX_SIGNATURES 2       // Max number of sig's

typedef struct __attribute__ ((__packed__)) SEV_CERT
{
    uint32_t    Version;        // Certificate Version. Should be 1.
    uint8_t     ApiMajor;       // Version of API generating the
    uint8_t     ApiMinor;       // certificate. Unused during validation.
    uint8_t     Reserved0;
    uint8_t     Reserved1;
    uint32_t    PubkeyUsage;    // SEV_SIG_USAGE
    uint32_t    PubkeyAlgo;     // SEV_SIG_ALGO
    SEV_PUBKEY  Pubkey;
    uint32_t    Sig1Usage;      // SEV_SIG_USAGE
    uint32_t    Sig1Algo;       // SEV_SIG_ALGO
    SEV_SIG     Sig1;
    uint32_t    Sig2Usage;      // SEV_SIG_USAGE
    uint32_t    Sig2Algo;       // SEV_SIG_ALGO
    SEV_SIG     Sig2;
} SEV_CERT;

typedef struct __attribute__ ((__packed__)) SEV_CERT_CHAIN_BUF
{
    SEV_CERT    PEKCert;
    SEV_CERT    OCACert;
    SEV_CERT    CEKCert;
} SEV_CERT_CHAIN_BUF;

// Macros used for comparing individual certificates from chain
#define PEKinCertChain(x) (&((SEV_CERT_CHAIN_BUF *)x)->PEKCert)
#define OCAinCertChain(x) (&((SEV_CERT_CHAIN_BUF *)x)->OCACert)
#define CEKinCertChain(x) (&((SEV_CERT_CHAIN_BUF *)x)->CEKCert)

// Definition of buffers referred to by the command buffers of SEV API commands.

// Values passed in INIT command Options field.
enum SEV_OPTIONS {
    // Bit 0 is the SEV-ES bit
    SEV_OPTION_SEV_ES = 1 << 0,
};

enum SEV_CONFIG {
    // Bit 0 is the SEV-ES bit
    SEV_CONFIG_SEV_ES = 1 << 0,
};

// Guest policy bits. LAUNCH_START and GUEST_STATUS
enum SEV_POLICY : uint32_t {
    SEV_POLICY_NODBG     = 1 << 0,      // 1 disables DBG commands
    SEV_POLICY_NOKS      = 1 << 1,      // 1 disables key sharing
    SEV_POLICY_ES        = 1 << 2,      // 1 designates and SEV-ES guest
    SEV_POLICY_NOSEND    = 1 << 3,      // 1 disables all SEND operations
    SEV_POLICY_DOMAIN    = 1 << 4,      // 1 SEND only to machine with same OCA
    SEV_POLICY_SEV       = 1 << 5,      // 1 SEND only to AMD machine
    SEV_POLICY_API_MAJOR = (uint32_t)0xff << 16,  // API Major bits
    SEV_POLICY_API_MINOR = (uint32_t)0xff << 24,  // API Minor bits
};

// Maximally restrictive guest policy
#define SEV_POLICY_MAX ((SEV_POLICY)(SEV_POLICY_NODBG|SEV_POLICY_NOKS| \
    SEV_POLICY_ES|SEV_POLICY_NOSEND))
// Minimally restrictive guest policy
#define SEV_POLICY_MIN ((SEV_POLICY)(0))
// Recommended normal guest policy
#define SEV_POLICY_NORM ((SEV_POLICY)(SEV_POLICY_NODBG|SEV_POLICY_NOKS| \
    SEV_POLICY_ES|SEV_POLICY_DOMAIN|SEV_POLICY_SEV))
// Recommended guest policy for debugging
// Allows DBG ops, examination of guest state (ie, no SEV-ES)
#define SEV_POLICY_DEBUG ((SEV_POLICY)(SEV_POLICY_NOKS|SEV_POLICY_DOMAIN| \
    SEV_POLICY_SEV))

enum SEV_PLATFORM_STATUS_OWNER {
    // Bit 0 is the owner, self or external..
    PLATFORM_STATUS_OWNER_SELF = 0 << 0,
    PLATFORM_STATUS_OWNER_EXTERNAL = 1 << 0,
};

typedef struct __attribute__ ((__packed__)) TEKTIK
{
    AES128Key   TEK;
    AES128Key   TIK;
} TEKTIK;

typedef struct __attribute__ ((__packed__)) SEV_SESSION_BUF
{
    Nonce128    Nonce;
    TEKTIK      WrapTK;
    IV128       WrapIV;
    HMACSHA256  WrapMAC;
    HMACSHA256  PolicyMAC;
} SEV_SESSION_BUF;

typedef struct __attribute__ ((__packed__)) SEV_MEASURE_BUF
{
    HMACSHA256  Measurement;
    Nonce128    MNonce;
} SEV_MEASURE_BUF;

typedef struct __attribute__ ((__packed__)) SEV_HDR_BUF
{
    uint32_t    Flags;
    IV128       IV;
    HMACSHA256  MAC;
} SEV_HDR_BUF;

// Definition of the command buffers for each of the SEV API commands.

typedef struct __attribute__ ((__packed__)) SEV_INIT_CMD_BUF
{
    uint32_t    Options;        // enum SEV_OPTIONS
    uint32_t    Reserved;
    uint64_t    TMRPhysAddr;    // 1MB aligned. Ignored if CONFIG_ES is 0
    uint32_t    TMRLength;      // Ignored if CONFIG_ES is 0
} SEV_INIT_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_SHUTDOWN_CMD_BUF
{
} SEV_SHUTDOWN_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PLATFORM_RESET_CMD_BUF
{
} SEV_PLATFORM_RESET_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PLATFORM_STATUS_CMD_BUF
{
    uint8_t     ApiMajor;
    uint8_t     ApiMinor;
    uint8_t     CurrentPlatformState;   // SEV_PLATFORM_STATE
    uint8_t     Owner;
    uint16_t    Config;        // enum SEV_CONFIG
    uint8_t     Reserved;
    uint8_t     BuildID;
    uint32_t    GuestCount;
} SEV_PLATFORM_STATUS_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PEK_GEN_CMD_BUF
{
} SEV_PEK_GEN_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PEK_CSR_CMD_BUF
{
    uint64_t    CSRPAddr;
    uint32_t    CSRLength;
} SEV_PEK_CSR_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PEK_CERT_IMPORT_CMD_BUF
{
    uint64_t    PEKCertPAddr;
    uint32_t    PEKCertLength;
    uint32_t    Reserved;
    uint64_t    OCACertPAddr;
    uint32_t    OCACertLength;
} SEV_PEK_CERT_IMPORT_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PDH_GEN_CMD_BUF
{
} SEV_PDH_GEN_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PDH_CERT_EXPORT_CMD_BUF
{
    uint64_t    PDHCertPAddr;   // SEV_CERT
    uint32_t    PDHCertLength;
    uint32_t    Reserved;
    uint64_t    CertsPAddr;     // SEV_CERT_CHAIN_BUF
    uint32_t    CertsLength;
} SEV_PDH_CERT_EXPORT_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_DOWNLOAD_FIRMWARE_CMD_BUF
{
    uint64_t    FWPAddr;
    uint32_t    FWLength;
} SEV_DOWNLOAD_FIRMWARE_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_GET_ID_CMD_BUF
{
    uint64_t    IDPAddr;
    uint32_t    IDLength;
} SEV_GET_ID_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_LAUNCH_START_CMD_BUF
{
    uint32_t    Handle;
    SEV_POLICY  Policy;         // SEV_POLICY
    uint64_t    GDHCertPAddr;   // SEV_CERT
    uint32_t    GDHCertLen;
    uint32_t    Reserved;
    uint64_t    SessionPAddr;   // SEV_SESSION_BUF
    uint32_t    SessionLen;
} SEV_LAUNCH_START_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_LAUNCH_UPDATE_DATA_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved;
    uint64_t    DataPAddr;
    uint32_t    DataLen;
} SEV_LAUNCH_UPDATE_DATA_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_LAUNCH_UPDATE_VMSA_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved;
    uint64_t    VMSAPAddr;
    uint32_t    VMSALen;
} SEV_LAUNCH_UPDATE_VMSA_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_LAUNCH_MEASURE_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved;
    uint64_t    MeasurePAddr;
    uint32_t    MeasureLen;
} SEV_LAUNCH_MEASURE_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_LAUNCH_SECRET_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    HdrPAddr;       // SEV_HDR_BUF
    uint32_t    HdrLen;
    uint32_t    Reserved1;
    uint64_t    GuestPAddr;
    uint32_t    GuestLen;
    uint32_t    Reserved2;
    uint64_t    TransPAddr;
    uint32_t    TransLen;
} SEV_LAUNCH_SECRET_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_LAUNCH_FINISH_CMD_BUF
{
    uint32_t    Handle;
} SEV_LAUNCH_FINISH_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_SEND_START_CMD_BUF
{
    uint32_t    Handle;
    SEV_POLICY  Policy;
    uint64_t    PDHCertPAddr;   // SEV_CERT
    uint32_t    PDHCertLen;
    uint32_t    Reserved0;
    uint64_t    PlatCertPAddr;  // SEV_CERT_CHAIN_BUF
    uint32_t    PlatCertLen;
    uint32_t    Reserved1;
    uint64_t    AMDCertPAddr;
    uint32_t    AMDCertLen;
    uint32_t    Reserved2;
    uint64_t    SessionPAddr;   // SEV_SESSION_BUF
    uint32_t    SessionLen;
} SEV_SEND_START_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_SEND_UPDATE_DATA_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    HdrPAddr;       // SEV_HDR_BUF
    uint32_t    HdrLen;
    uint32_t    Reserved1;
    uint64_t    GuestPAddr;
    uint32_t    GuestLen;
    uint32_t    Reserved2;
    uint64_t    TransPAddr;
    uint32_t    TransLen;
} SEV_SEND_UPDATE_DATA_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_SEND_UPDATE_VMSA_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    HdrPAddr;       // SEV_HDR_BUF
    uint32_t    HdrLen;
    uint32_t    Reserved1;
    uint64_t    GuestPAddr;
    uint32_t    GuestLen;
    uint32_t    Reserved2;
    uint64_t    TransPAddr;
    uint32_t    TransLen;
} SEV_SEND_UPDATE_VMSA_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_SEND_FINISH_CMD_BUF
{
    uint32_t    Handle;
} SEV_SEND_FINISH_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_RECEIVE_START_CMD_BUF
{
    uint32_t    Handle;
    SEV_POLICY  Policy;
    uint64_t    PDHCertPAddr;   // SEV_CERT
    uint32_t    PDHCertLen;
    uint32_t    Reserved;
    uint64_t    SessionPAddr;   // SEV_SESSION_BUF
    uint32_t    SessionLen;
} SEV_RECEIVE_START_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_RECEIVE_UPDATE_DATA_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    HdrPAddr;       // SEV_HDR_BUF
    uint32_t    HdrLen;
    uint32_t    Reserved1;
    uint64_t    GuestPAddr;
    uint32_t    GuestLen;
    uint32_t    Reserved2;
    uint64_t    TransPAddr;
    uint32_t    TransLen;
} SEV_RECEIVE_UPDATE_DATA_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_RECEIVE_UPDATE_VMSA_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    HdrPAddr;       // SEV_HDR_BUF
    uint32_t    HdrLen;
    uint32_t    Reserved1;
    uint64_t    GuestPAddr;
    uint32_t    GuestLen;
    uint32_t    Reserved2;
    uint64_t    TransPAddr;
    uint32_t    TransLen;
} SEV_RECEIVE_UPDATE_VMSA_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_RECEIVE_FINISH_CMD_BUF
{
    uint32_t    Handle;
} SEV_RECEIVE_FINISH_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_GUEST_STATUS_CMD_BUF
{
    uint32_t    Handle;
    SEV_POLICY  Policy;         // SEV_POLICY
    uint32_t    ASID;
    uint8_t     State;          // SEV_GUEST_STATE
} SEV_GUEST_STATUS_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_ACTIVATE_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    ASID;
} SEV_ACTIVATE_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_ACTIVATE_EX_CMD_BUF
{
    uint32_t    EXLen;
    uint32_t    Handle;
    uint32_t    ASID;
    uint32_t    Reserved0;
    uint64_t    CCXs;
} SEV_ACTIVATE_EX_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_DEACTIVATE_CMD_BUF
{
    uint32_t    Handle;
} SEV_DEACTIVATE_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_DF_FLUSH_CMD_BUF
{
} SEV_DF_FLUSH_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_DECOMMISSION_CMD_BUF
{
    uint32_t    Handle;
} SEV_DECOMMISSION_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_COPY_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Length;
    uint64_t    SrcPAddr;
    uint64_t    DstPAddr;
} SEV_COPY_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_DBG_DECRYPT_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    SrcPAddr;
    uint64_t    DstPAddr;
    uint32_t    Length;
} SEV_DBG_DECRYPT_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_DBG_ENCRYPT_CMD_BUF
{
    uint32_t    Handle;
    uint32_t    Reserved0;
    uint64_t    SrcPAddr;
    uint64_t    DstPAddr;
    uint32_t    Length;
} SEV_DBG_ENCRYPT_CMD_BUF;


// ------------------------------- //
// --- Miscellaneous constants --- //
// ------------------------------- //

// Maximum size of firmware image
#define FW_MAX_SIZE 65536

// TMR (Trusted Memory Region) size required for INIT with SEV-ES enabled
#define SEV_TMR_SIZE (1024*1024)

// Invalid guest handle.
#define INVALID_GUEST_HANDLE    0

#define INVALID_ASID    0

#endif /* sevapi_h */
