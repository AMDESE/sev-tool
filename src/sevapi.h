//-----------------------------------------------------------------------------
// Copyright 2018 by AMD Inc.  All rights reserved.
//
// This document contains proprietary, confidential information that
// may be used, copied and/or disclosed only as authorized by a
// valid licensing agreement with AMD Inc. This copyright
// notice must be retained on all authorized copies.
//
// This code is provided "as is".  AMD Inc. makes, and
// the end user receives, no warranties or conditions, express,
// implied, statutory or otherwise, and AMD Inc.
// specifically disclaims any implied warranties of merchantability,
// non-infringement, or fitness for a particular purpose.
//
//-----------------------------------------------------------------------------

#ifndef sevapi_h
#define sevapi_h

// This file puts in to C/C++ form the definitions from the SEV FW spec.
// It should remain usable purely from C
// All SEV API indices are based off of SEV API v0.17

#include <stdint.h>

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


// Chapter 4.3 - Command Identifiers
/**
 * SEV commands (each entry stored in a byte).
 */
typedef enum __attribute__((mode(QI))) SEV_API_COMMANDS
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
    INIT_EX             = 0xD,
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

// Chapter 5.1.2 - Platform State Machine
/**
 * SEV Platform state (each entry stored in a byte).
 *
 * @UNINIT  - The platform is uninitialized.
 * @INIT    - The platform is initialized, but not currently managed by any
 *            guests.
 * @WORKING - The platform is initialized, and currently managing guests.
 *
 * Allowed Platform Commands:
 * @UNINIT  - INIT, PLATFORM_RESET, PLATFORM_STATUS, DOWNLOAD_FIRMWARE, GET_ID
 * @INIT    - SHUTDOWN, PLATFORM_STATUS, PEK_GEN, PEK_CSR, PEK_CERT_IMPORT,
 *            PDH_GEN, PDH_CERT_EXPORT, DF_FLUSH, GET_ID
 * @WORKING - SHUTDOWN, PLATFORM_STATUS, PDH_GEN, PDH_CERT_EXPORT, DF_FLUSH,
 *            GET_ID
 */
typedef enum __attribute__((mode(QI))) SEV_PLATFORM_STATE
{
    PLATFORM_UNINIT     = 0,
    PLATFORM_INIT       = 1,
    PLATFORM_WORKING    = 2,
} SEV_PLATFORM_STATE;

// Chapter 6.1.1 - GSTATE Finite State Machine
/**
 * GSTATE Finite State machine status'
 *
 * Description:
 * @UNINIT  - The guest is uninitialized.
 * @LUPDATE - The guest is currently being launched and plaintext data and VMCB
 *            save areas are being imported.
 * @LSECRET - The guest is currently being launched and ciphertext data are
 *            is being imported.
 * @RUNNING - The guest is fully launched or migrated in, and not being
 *            migrated out to another machine.
 * @SUPDATE - The guest is currently being migrated out to another machine.
 * @RUPDATE - The guest is currently being migrated from another machine.
 *
 * Allowed Guest Commands:
 * @UNINIT  - LAUNCH_START, RECEIVE_START
 * @LUPDATE - LAUNCH_UPDATE_DATA, LAUNCH_UPDATE_VMSA, LAUNCH_MEASURE, ACTIVATE,
 *            DEACTIVATE, DECOMMISSION, GUEST_STATUS
 * @LSECRET - LAUNCH_SECRET, LAUNCH_FINISH, ACTIVATE, DEACTIVATE, DECOMMISSION,
 *            GUEST_STATUS
 * @RUNNING - ACTIVATE, DEACTIVATE, DECOMMISSION, SEND_START, GUEST_STATUS
 * @SUPDATE - SEND_UPDATE_DATA, SEND_UPDATE_VMSA, SEND_FINISH, ACTIVATE,
 *            DEACTIVATE, DECOMMISSION, GUEST_STATUS
 * @RUPDATE - RECEIVE_UDPATE_DATA, RECEIVE_UDPATE_VMSA, RECEIVE_FINISH,
 *            ACTIVATE, DEACTIVATE, DECOMMISSION, GUEST_STATUS
 */
typedef enum __attribute__((mode(QI))) SEV_GUEST_STATE
{
    GUEST_UNINIT     = 0,
    GUEST_LUPDATE    = 1,
    GUEST_LSECRET    = 2,
    GUEST_RUNNING    = 3,
    GUEST_SUPDATE    = 4,
    GUEST_RUPDATE    = 5,
} SEV_GUEST_STATE;

// Chapter 4.4 - Status Codes
/**
 * SEV Error Codes (each entry stored in a byte).
 */
typedef enum __attribute__((mode(QI))) SEV_ERROR_CODE
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
    ERROR_INVALID_PARAM             = 0x16,
    ERROR_RESOURCE_LIMIT            = 0x17,
} SEV_ERROR_CODE;

// ------------------------------------------------------------ //
// --- Definition of API-defined Encryption and HMAC values --- //
// ------------------------------------------------------------ //

// Chapter 2 - Summary of Keys
typedef uint8_t AES128Key[128/8];
typedef uint8_t HMACKey128[128/8];
typedef uint8_t HMACSHA256[256/8];
typedef uint8_t HMACSHA512[512/8];
typedef uint8_t Nonce128[128/8];
typedef uint8_t IV128[128/8];

// -------------------------------------------------------------------------- //
// -- Definition of API-defined Public Key Infrastructure (PKI) structures -- //
// -------------------------------------------------------------------------- //

// Appendix C.3: SEV Certificates
#define SEV_RSA_PUBKEY_MAX_BITS     4096
#define SEV_ECDSA_PUBKEY_MAX_BITS   576
#define SEV_ECDH_PUBKEY_MAX_BITS    576
#define SEV_PUBKEY_SIZE             (SEV_RSA_PUBKEY_MAX_BITS/8)

// Appendix C.3.1 Public Key Formats - RSA Public Key
/**
 * SEV RSA Public key information.
 *
 * @ModulusSize - Size of modulus in bits.
 * @PubExp      - The public exponent of the public key.
 * @Modulus     - The modulus of the public key.
 */
typedef struct __attribute__ ((__packed__)) SEV_RSA_PUBKEY
{
    uint32_t    ModulusSize;
    uint8_t     PubExp[SEV_RSA_PUBKEY_MAX_BITS/8];
    uint8_t     Modulus[SEV_RSA_PUBKEY_MAX_BITS/8];
} SEV_RSA_PUBKEY;

/**
 * SEV Elliptical Curve algorithm details.
 *
 * @SEVECInvalid - Invalid cipher size selected.
 * @SEVECP256    - 256 bit elliptical curve cipher.
 * @SEVECP384    - 384 bit elliptical curve cipher.
 */
typedef enum __attribute__((mode(QI))) SEV_EC
{
    SEVECInvalid = 0,
    SEVECP256    = 1,
    SEVECP384    = 2,
} SEV_EC;

// Appendix C.3.2: Public Key Formats - ECDSA Public Key
/**
 * SEV Elliptical Curve DSA algorithm details.
 *
 * @Curve - The SEV Elliptical curve ID.
 * @QX    - x component of the public point Q.
 * @QY    - y component of the public point Q.
 * @RMBZ  - RESERVED. Must be zero!
 */
typedef struct __attribute__ ((__packed__)) SEV_ECDSA_PUBKEY
{
    uint32_t    Curve;      // SEV_EC as a uint32_t
    uint8_t     QX[SEV_ECDSA_PUBKEY_MAX_BITS/8];
    uint8_t     QY[SEV_ECDSA_PUBKEY_MAX_BITS/8];
    uint8_t     RMBZ[SEV_PUBKEY_SIZE-2*SEV_ECDSA_PUBKEY_MAX_BITS/8-sizeof(uint32_t)];
} SEV_ECDSA_PUBKEY;

// Appendix C.3.3: Public Key Formats - ECDH Public Key
/**
 * SEV Elliptical Curve Diffie Hellman Public Key details.
 *
 * @Curve - The SEV Elliptical curve ID.
 * @QX    - x component of the public point Q.
 * @QY    - y component of the public point Q.
 * @RMBZ  - RESERVED. Must be zero!
 */
typedef struct __attribute__ ((__packed__)) SEV_ECDH_PUBKEY
{
    uint32_t    Curve;      // SEV_EC as a uint32_t
    uint8_t     QX[SEV_ECDH_PUBKEY_MAX_BITS/8];
    uint8_t     QY[SEV_ECDH_PUBKEY_MAX_BITS/8];
    uint8_t     RMBZ[SEV_PUBKEY_SIZE-2*SEV_ECDH_PUBKEY_MAX_BITS/8-sizeof(uint32_t)];
} SEV_ECDH_PUBKEY;

// Appendix C.4: Public Key Formats
/**
 * The SEV Public Key memory slot may hold RSA, ECDSA, or ECDH.
 */
typedef union
{
    SEV_RSA_PUBKEY      RSA;
    SEV_ECDSA_PUBKEY    ECDSA;
    SEV_ECDH_PUBKEY     ECDH;
} SEV_PUBKEY;

// Appendix C.4: Signature Formats
/**
 * SEV Signature may be RSA or ECDSA.
 */
#define SEV_RSA_SIG_MAX_BITS        4096
#define SEV_ECDSA_SIG_COMP_MAX_BITS 576
#define SEV_SIG_SIZE                (SEV_RSA_SIG_MAX_BITS/8)

// Appendix C.4.1: RSA Signature
/**
 * SEV RSA Signature data.
 *
 * @S - Signature bits.
 */
typedef struct __attribute__ ((__packed__)) SEV_RSA_SIG
{
    uint8_t     S[SEV_RSA_SIG_MAX_BITS/8];
} SEV_RSA_SIG;

// Appendix C.4.2: ECDSA Signature
/**
 * SEV Elliptical Curve Signature data.
 *
 * @R    - R component of the signature.
 * @S    - S component of the signature.
 * @RMBZ - RESERVED. Must be zero!
 */
typedef struct __attribute__ ((__packed__)) SEV_ECDSA_SIG
{
    uint8_t     R[SEV_ECDSA_SIG_COMP_MAX_BITS/8];
    uint8_t     S[SEV_ECDSA_SIG_COMP_MAX_BITS/8];
    uint8_t     RMBZ[SEV_SIG_SIZE-2*SEV_ECDSA_SIG_COMP_MAX_BITS/8];
} SEV_ECDSA_SIG;

/**
 * SEV Signature may be RSA or ECDSA.
 */
typedef union
{
    SEV_RSA_SIG     RSA;
    SEV_ECDSA_SIG   ECDSA;
} SEV_SIG;

// Appendix C.1: USAGE Enumeration
/**
 * SEV Usage codes.
 */
typedef enum __attribute__((mode(HI))) SEV_USAGE
{
    SEVUsageARK     = 0x0,
    SEVUsageASK     = 0x13,
    SEVUsageInvalid = 0x1000,
    SEVUsageOCA     = 0x1001,
    SEVUsagePEK     = 0x1002,
    SEVUsagePDH     = 0x1003,
    SEVUsageCEK     = 0x1004,
} SEV_USAGE;

// Appendix C.1: ALGO Enumeration
/**
 * SEV Algorithm cipher codes.
 */
typedef enum __attribute__((mode(HI))) SEV_SIG_ALGO
{
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

// Appendix C.1: SEV Certificate Format
/**
 * SEV Certificate format.
 *
 * @Version     - Certificate version, set to 01h.
 * @ApiMajor    - If PEK, set to API major version, otherwise zero.
 * @ApiMinor    - If PEK, set to API minor version, otherwise zero.
 * @Reserved0   - RESERVED, Must be zero!
 * @Reserved1   - RESERVED, Must be zero!
 * @PubkeyUsage - Public key usage              (SEV_SIG_USAGE).
 * @PubkeyAlgo  - Public key algorithm          (SEV_SIG_ALGO).
 * @Pubkey      - Public Key.
 * @Sig1Usage   - Key usage of SIG1 signing key (SEV_SIG_USAGE).
 * @Sig1Algo    - First signature algorithm     (SEV_SIG_ALGO).
 * @Sig1        - First signature.
 * @Sig2Usage   - Key usage of SIG2 signing key (SEV_SIG_USAGE).
 * @Sig2Algo    - Second signature algorithm    (SEV_SIG_ALGO).
 * @Sig2        - Second signature
 */
typedef struct __attribute__ ((__packed__)) SEV_CERT
{
    uint32_t    Version;        // Certificate Version. Should be 1.
    uint8_t     ApiMajor;       // Version of API generating the
    uint8_t     ApiMinor;       // certificate. Unused during validation.
    uint8_t     Reserved0;
    uint8_t     Reserved1;
    uint32_t    PubkeyUsage;    // SEV_USAGE
    uint32_t    PubkeyAlgo;     // SEV_SIG_ALGO
    SEV_PUBKEY  Pubkey;
    uint32_t    Sig1Usage;      // SEV_USAGE
    uint32_t    Sig1Algo;       // SEV_SIG_ALGO
    SEV_SIG     Sig1;
    uint32_t    Sig2Usage;      // SEV_USAGE
    uint32_t    Sig2Algo;       // SEV_SIG_ALGO
    SEV_SIG     Sig2;
} SEV_CERT;

// Macros used for comparing individual certificates from chain
#define PEKinCertChain(x) (&((SEV_CERT_CHAIN_BUF *)x)->PEKCert)
#define OCAinCertChain(x) (&((SEV_CERT_CHAIN_BUF *)x)->OCACert)
#define CEKinCertChain(x) (&((SEV_CERT_CHAIN_BUF *)x)->CEKCert)


// Appendix B.1: Certificate Format
typedef union
{
    uint8_t     Short[2048/8];
    uint8_t     Long[4096/8];
} AMD_CERT_PUBEXP;

typedef union
{
    uint8_t     Short[2048/8];
    uint8_t     Long[4096/8];
} AMD_CERT_MOD;

typedef union
{
    uint8_t     Short[2048/8];
    uint8_t     Long[4096/8];
} AMD_CERT_SIG;

typedef enum __attribute__((mode(QI))) AMD_SIG_USAGE
{
    AMDUsageARK     = 0x00,
    AMDUsageASK     = 0x13,
} AMD_SIG_USAGE;

// Appendix B.1: AMD Signing Key Certificate Format
typedef struct __attribute__ ((__packed__)) AMD_CERT
{
    uint32_t    Version;        // Certificate Version. Should be 1.
    uint64_t    KeyID0;         // The unique ID for this key
    uint64_t    KeyID1;
    uint64_t    CertifyingID0;  // The unique ID for the key that signed this cert.
    uint64_t    CertifyingID1;  // If this cert is self-signed, then equals KEY_ID field.
    uint32_t    KeyUsage;       // AMD_SIG_USAGE
    uint64_t    Reserved0;
    uint64_t    Reserved1;
    uint32_t    PubExpSize;     // Size of public exponent in bits. Must be 2048/4096.
    uint32_t    ModulusSize;    // Size of modulus in bits. Must be 2048/4096.
    AMD_CERT_PUBEXP PubExp;     // Public exponent of this key. Size is PubExpSize.
    AMD_CERT_MOD    Modulus;    // Public modulus of this key. Size is ModulusSize.
    AMD_CERT_SIG    Sig;        // Public signature of this key. Size is ModulusSize.
} AMD_CERT;


// -------------------------------------------------------------------------- //
// Definition of buffers referred to by the command buffers of SEV API commands
// -------------------------------------------------------------------------- //
// Values passed into INIT command Options field
enum __attribute__((mode(SI))) SEV_OPTIONS
{
    // Bit 0 is the SEV-ES bit
    SEV_OPTION_SEV_ES = 1 << 0,
};

// Values returned from PLATFORM_STATUS Config.ES field
enum __attribute__((mode(SI))) SEV_CONFIG
{
    // Bit 0 is the SEV-ES bit
    SEV_CONFIG_NON_ES = 0 << 0,
    SEV_CONFIG_ES     = 1 << 0,
};


// Guest policy bits. Used in LAUNCH_START and GUEST_STATUS
// Chapter 3: Guest Policy Structure
/**
 * SEV Guest Policy bits (stored as a bit field struct).
 *
 * @nodbg     - Debugging of the guest is disallowed
 * @noks      - Sharing keys with other guests is disallowed
 * @es        - SEV-ES is required
 * @nosend    - Disallow sending of guest to another platform
 * @domain    - Guest must not be transmitted to another platform
 *              outside the domain
 * @sev       - The guest must not be transmitted to another platform
 *              that is not SEV capable
 * @api_major - The guest must not be transmitted to another platform
 *              lower than the specified major version
 * @api_minor - The guest must not be transmitted to another platform
 *              lower than the specified minor version
 * @raw       - The raw unsigned 32 bit value stored in memory at the
 *              specified location.
 */
enum SEV_POLICY : uint32_t
{
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

/**
 * PLATFORM_STATUS Command Sub-Buffer
 * Status of the owner of the platform (each entry stored in one byte).
 */
enum SEV_PLATFORM_STATUS_OWNER
{
    // Bit 0 is the owner, self or external..
    PLATFORM_STATUS_OWNER_SELF     = 0 << 0,
    PLATFORM_STATUS_OWNER_EXTERNAL = 1 << 0,
};

/**
 * Transport encryption and integrity keys
 * (See SEV_SESSION_BUF)
 *
 * @TEK - Transport Encryption Key.
 * @TIK - Transport Integrity Key.
 */
typedef struct __attribute__ ((__packed__)) TEKTIK
{
    AES128Key   TEK;
    AES128Key   TIK;
} TEKTIK;

/**
 * LAUNCH_START/SEND_START/RECEIVE_START Session Data Buffer
 *
 * @Nonce     - An arbitrary 128 bit number.
 * @WrapTK    - The SEV transport encryption and integrity keys.
 * @WrapIV    - 128 bit initializer vector.
 * @WrapMAC   - Session hash message authentication code.
 * @PolicyMAC - Policy hash message authentication code.
 */
typedef struct __attribute__ ((__packed__)) SEV_SESSION_BUF
{
    Nonce128    Nonce;
    TEKTIK      WrapTK;
    IV128       WrapIV;
    HMACSHA256  WrapMAC;
    HMACSHA256  PolicyMAC;
} SEV_SESSION_BUF;

/**
 * LAUNCH_MEASURE Measurement buffer.
 *
 * @Measurement - 256 bit hash message authentication code.
 * @MNonce      - An arbitrary 128 bit number.
 */
typedef struct __attribute__ ((__packed__)) SEV_MEASURE_BUF
{
    HMACSHA256  Measurement;
    Nonce128    MNonce;
} SEV_MEASURE_BUF;

/**
 * LAUNCH_SECRET, SEND_UPDATE_DATA/VMSA, RECEIVE_UPDATE_DATA/VMSA
 * HDR Buffer
 */
typedef struct __attribute__ ((__packed__)) SEV_HDR_BUF
{
    uint32_t    Flags;
    IV128       IV;
    HMACSHA256  MAC;
} SEV_HDR_BUF;

/**
 * PDH_CERT_EXPORT/SEND_START Platform Certificate(s) Chain Buffer
 *
 * @PEKCert - Platform Endorsement Key certificate.
 * @OCACert - Owner Certificate Authority certificate.
 * @CEKCert - Chip Endorsement Key certificate.
 */
typedef struct __attribute__ ((__packed__)) SEV_CERT_CHAIN_BUF
{
    SEV_CERT    PEKCert;
    SEV_CERT    OCACert;
    SEV_CERT    CEKCert;
} SEV_CERT_CHAIN_BUF;

// SEND_START AMD Certificates Buffer
typedef struct __attribute__ ((__packed__)) AMD_CERT_CHAIN_BUF
{
    AMD_CERT    ASKCert;
    AMD_CERT    ARKCert;
} AMD_CERT_CHAIN_BUF;

// -------------------------------------------------------------------------- //
// --- Definition of the command buffers for each of the SEV API commands --- //
// -------------------------------------------------------------------------- //

// Chapter 5: Platform Mamanagement API
/**
 * SEV initialization command buffer
 *
 * @Options     - An SEV_OPTIONS enum value
 * @Reserved    - Reserved. Must be 0.
 * @TMRPhysAddr - System physical address to memory region donated by
 *                Hypervisor for SEV-ES operations. Ignored if SEV-ES
 *                is disabled.
 * @TMRLength   - Length of the memory. Ignored if SEV-ES disabled.
 */
typedef struct __attribute__ ((__packed__)) SEV_INIT_CMD_BUF
{
    uint32_t    Options;        // enum SEV_OPTIONS
    uint32_t    Reserved;
    uint64_t    TMRPhysAddr;    // 1MB alligned. Ignored if CONFIG_ES is 0
    uint32_t    TMRLength;      // Ignored if CONFIG_ES is 0
} SEV_INIT_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_SHUTDOWN_CMD_BUF
{
} SEV_SHUTDOWN_CMD_BUF;

typedef struct __attribute__ ((__packed__)) SEV_PLATFORM_RESET_CMD_BUF
{
} SEV_PLATFORM_RESET_CMD_BUF;

/**
 * SEV Platform Status command buffer.
 *
 * @ApiMajor             - Major API version
 * @ApiMinor             - Minor API version
 * @CurrentPlatformState - Current platform state (SEV_PLATFORM_STATE)
 * @Owner                - Defines the owner: 0=Self-owned; 1=Externally owned
 * @Config               - SEV-ES is initialized for the platform when set.
 *                         Disabled for all guests when not set.
 * @Reserved             - Reserved. Set to zero.
 * @BuildID              - Firmware Build ID for this API version.
 * @GuestCount           - Number of valid guests maintained by the firmware.
 */
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

typedef struct __attribute__ ((__packed__)) SEV_INIT_EX_CMD_BUF
{
    uint32_t    Length;         // Must be 0x24
    uint32_t    Options;        // enum SEV_OPTIONS
    uint64_t    TMRPhysAddr;    // 1MB alligned. Ignored if CONFIG_ES is 0
    uint32_t    TMRLength;      // Ignored if CONFIG_ES is 0
    uint32_t    Reserved;
    uint64_t    NVPhysAddr;
    uint32_t    NVLength;       // Must be 32KB
} SEV_INIT_EX_CMD_BUF;

// Chapter 6: Guest Management API
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
    uint32_t    NumIDs;
    uint64_t    IDsPaddr;
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

// Chapter: Debugging API
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

#endif /* sevapi_h */
