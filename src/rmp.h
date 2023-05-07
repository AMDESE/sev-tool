/**************************************************************************
 * Copyright 2019-2021 Advanced Micro Devices, Inc.
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

#ifndef RMP_H
#define RMP_H

#include "sevapi.h"
#include <cstdint>
#include <cstddef>      // For size_t

enum DRAM_PAGE_SIZE : uint32_t
{
    DRAM_PAGE_SIZE_4K = 0 << 0,
    DRAM_PAGE_SIZE_2M = 1 << 0,

    DRAM_PAGE_SIZE_LIMIT = 2 << 0,
};

#define RMP_NUM_ASID_COUNTERS   2048
/**
 *  RMP Table Struture:
 *      16Kbytes total (rmp_asid_counters)
 *      rmp_entry tables ()
 */
typedef struct rmp_asid_counters
{
    uint64_t counters[RMP_NUM_ASID_COUNTERS];
} rmp_asid_counters_t;

#define VMPL_DISABLED   0
#define VMPL_ENABLED    1

#define MIN_VMPL_PERM 0x00
#define MAX_VMPL_PERM 0x0F

// Define the location of the GPA in RMP entry, bit 12 to bit 50
#define RMP_ENTRY_GPA_SHIFT (12ULL)

typedef struct rmp_fields   // TODO look into using uin32_t for some, question about packing
{
    uint64_t assigned      : 1;
    uint64_t page_size     : 1;
    uint64_t immutable     : 1;
    uint64_t subpage_count : 9;
    uint64_t gpa           : 39;
    uint64_t asid          : 10;
    uint64_t vmsa          : 1;
    uint64_t validated     : 1;
    uint64_t lock          : 1;
} rmp_fields_t;

typedef union rmp_entry
{
    rmp_fields_t f;
    uint64_t     val;
} rmp_entry_t;
static_assert(sizeof(rmp_entry_t) == sizeof(uint64_t), "Error, static assertion failed");

// 6.1 Page Security Attributes
typedef union vmpl_perm_mask
{
    struct
    {
        uint32_t read            : 1;   // If page is readable by the VMPL
        uint32_t write           : 1;   // If page is writable by the VMPL
        uint32_t exec_user       : 1;   // If page is executable by the VMPL at CPL3
        uint32_t exec_supervisor : 1;   // If page is executable by the VMPL at CPL0, CPL1, or CPL2.
        uint32_t reserved        : 4;
    } __attribute__((packed)) f;
    uint8_t val;
} __attribute__((packed)) vmpl_perm_mask_t;
static_assert(sizeof(vmpl_perm_mask_t) == sizeof(uint8_t), "Error, static assertion failed");

typedef union vmpl_entry
{
    struct
    {
        vmpl_perm_mask_t vmpl0;
        vmpl_perm_mask_t vmpl1;
        vmpl_perm_mask_t vmpl2;
        vmpl_perm_mask_t vmpl3;
        uint8_t reserved[4];
    } __attribute__((packed)) f;
    uint64_t val;
} vmpl_entry_t;
static_assert(sizeof(vmpl_entry_t) == sizeof(uint64_t), "Error, static assertion failed");

typedef struct rmp_vmpl_entry
{
    rmp_entry_t  rmp;
    vmpl_entry_t vmpl;
} rmp_vmpl_entry_t;
static_assert(sizeof(rmp_vmpl_entry_t) == 2*sizeof(uint64_t), "Error, static assertion failed");

/**
 * 3.1 Metadata Entries (MDATA)
 * Metadata entry within a metadata page. Each entry is 64 bytes, a page is 4k
 * Not bit-for-bit compatible
 */
typedef struct mdata_perm_mask
{
    // uint64_t of the following
    uint32_t    valid          : 1;  // bit 0
    uint32_t    page_validated : 1;  // bit 1
    uint32_t    vmsa           : 1;  // bit 2
    uint32_t    metadata       : 1;  // bit 3
    uint32_t    page_size      : 1;  // 0 = 4k, 1 = 2MB, bit 4
    uint32_t    reserved1      : 7;  // bits 5 to 11 reserved
    uint64_t    gpa            : 52; // bits 12 to 63
} mdata_perm_mask_t;
static_assert(sizeof(mdata_perm_mask_t) == sizeof(uint64_t), "Error, static assertion failed");

typedef union snp_metadata_entry
{
    mdata_perm_mask_t   f;
    uint64_t            val;
} snp_metadata_entry_t;
static_assert(sizeof(snp_metadata_entry_t) == sizeof(uint64_t), "Error, static assertion failed");

typedef struct snp_metadata_page    // MDATA
{
    uint64_t            software_data;  // 00h
    uint64_t            iv;             // 08h
    uint8_t             auth_tag[16];   // 10h
    snp_metadata_entry_t mdata_entry;   // 20h
    vmpl_entry_t        vmpl;           // 28h
    uint64_t            reserved2;      // 30h
    uint64_t            reserved3;      // 38h
} snp_metadata_page_t;
static_assert(sizeof(snp_metadata_page_t) == 8*sizeof(uint64_t), "Error, static assertion failed");

#define RMP_ASID_COUNTERS_SIZE      (sizeof(rmp_asid_counters_t))
#define RMP_ENTRY_SIZE              (sizeof(rmp_entry_t))           // 64 bits, 8 bytes
#define VMPL_ENTRY_SIZE             (sizeof(vmpl_entry_t))          // 64 bits, 8 bytes
#define RMP_VMPL_ENTRY_SIZE         (sizeof(rmp_vmpl_entry_t))
#define SNP_METADATA_ENTRY_SIZE     (sizeof(snp_metadata_page_t))   // 64 bytes

/**
 * 3.2 TCB Version
 * A version string that represents the version of the firmware
 */
typedef union snp_tcb_version    // TCB
{
    struct
    {
        uint8_t boot_loader;    // SVN of PSP bootloader
        uint8_t tee;            // SVN of PSP operating system
        uint8_t reserved[4];
        uint8_t snp;            // SVN of SNP firmware
        uint8_t microcode;      // Lowest current patch level of all the cores
    } __attribute__((packed)) f;
    uint64_t val;
} __attribute__((packed)) snp_tcb_version_t;
static_assert(sizeof(snp_tcb_version_t) == sizeof(uint64_t), "Error, static assertion failed");

// 6.2 Page States
typedef enum snp_page_state
{                        // Controlled by:   SW       HW        SW   SW        HW   SW  HW
    // Page State                            Assigned Validated ASID Immutable Lock GPA VMSA
    SNP_PAGE_STATE_INVALID        = 0x0,
    SNP_PAGE_STATE_DEFAULT        = 0x1,
    SNP_PAGE_STATE_HYPERVISOR     = 0x2,  // 0        0         0    0         -    -   -
    SNP_PAGE_STATE_FIRMWARE       = 0x3,  // 1        0         0    1         -    0   0
    SNP_PAGE_STATE_RECLAIM        = 0x4,  // 1        0         0    0         0    -   -
    SNP_PAGE_STATE_CONTEXT        = 0x5,  // 1        0         0    1         -    0   1
    SNP_PAGE_STATE_METADATA       = 0x6,  // 1        0         0    1         -    >0  -
    SNP_PAGE_STATE_PRE_GUEST      = 0x7,  // 1        0         >0   1         -    -   -
    SNP_PAGE_STATE_PRE_SWAP       = 0x8,  // 1        1         >0   1         -    -   -
    SNP_PAGE_STATE_GUEST_INVALID  = 0x9,  // 1        0         >0   0         -    -   -
    SNP_PAGE_STATE_GUEST_VALID    = 0xA,  // 1        1         >0   0         -    -   -

    SNP_PAGE_STATE_LIMIT,
} snp_page_state_t;

#define SNP_GMSG_MAX_HDR_VERSION                    1
#define SNP_GMSG_MAX_MSG_VERSION_CPUID_REQ          1
#define SNP_GMSG_MAX_MSG_VERSION_CPUID_RSP          1
#define SNP_GMSG_MAX_MSG_VERSION_KEY_REQ            1
#define SNP_GMSG_MAX_MSG_VERSION_KEY_RSP            1
#define SNP_GMSG_MAX_MSG_VERSION_REPORT_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_REPORT_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_EXPORT_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_EXPORT_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_IMPORT_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_IMPORT_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_REQ         1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_RSP         1
#define SNP_GMSG_MAX_MSG_VERSION_VMRK_REQ           1
#define SNP_GMSG_MAX_MSG_VERSION_VMRK_RSP           1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_NOMA_REQ    1
#define SNP_GMSG_MAX_MSG_VERSION_ABSORB_NOMA_RSP    1
typedef struct snp_guest_message_header      // GMSG
{
    uint8_t  auth_tag[32];
    uint64_t msg_seqno;     // Message sequence number
    uint8_t  reserved[8];
    uint8_t  algo;          // The AEAD used to encrypt this message
    uint8_t  hdr_version;
    uint32_t hdr_size : 16;
    uint8_t  msg_type;
    uint8_t  msg_version;
    uint32_t msg_size : 16;
    uint32_t reserved2;
    uint8_t  msg_vmpck;     // The ID of the VMPCK used to protect this message
    uint8_t  reserved3;
    uint8_t  reserved4[2];
    uint8_t  reserved5[0x60-0x40];
    uint8_t  payload;       // Start of payload. Need to fill in an SEVMem page with this structure
} __attribute__((packed)) snp_guest_message_header_t;
static_assert(sizeof(snp_guest_message_header_t) == 0x61, "Error, static assertion failed");

#define SNP_GMSG_HDR_AAD_SIZE  (offsetof(snp_guest_message_header_t, payload)-offsetof(snp_guest_message_header_t, algo))
static_assert(SNP_GMSG_HDR_AAD_SIZE == (0x60-0x30), "Error, static assertion failed");

// AEAD Algorithm Encodings
enum
{
    AEAD_ALGO_INVALID     = 0,
    AEAD_ALGO_AES_256_GCM = 1,
};

// 8.1 CPUID Reporting
// Request page is the same as launch update cpuid page
typedef struct snp_launch_update_cpuid_page_t snp_msg_cpuid_req_t;

typedef struct snp_msg_cpuid_rsp
{
    uint32_t status;
    uint32_t count;
    uint64_t reserved;
    snp_cpuid_function_t cpuid_function[SNP_CPUID_COUNT_MAX];
} snp_msg_cpuid_rsp_t;

// 8.2 Key Derivation
typedef struct snp_msg_key_req
{
    uint32_t root_key_select : 1;
    uint32_t reserved        : 31;
    uint32_t reserved2;
    uint64_t guest_field_select;
    uint32_t vmpl;
    uint32_t guest_svn;
    snp_tcb_version_t tcb_version;
} snp_msg_key_req_t;

#define KEY_REQ_LABEL "gmsg-keyreq"

typedef struct snp_mix_data
{
    uint32_t root_key_select    : 1;    // bit 0
    uint32_t idblock_key_select : 2;    // bits 1 to 2
    uint32_t reserved           : 29;   // bits 3 to 31
    uint32_t reserved2;
    uint64_t gfs;
    uint32_t vmpl;
    uint32_t guest_svn;
    snp_tcb_version_t tcb_version;
    uint64_t guest_policy;
    uint8_t image_id[16];
    uint8_t family_id[16];
    uint8_t measurement[32];
    uint8_t host_data[32];
    uint8_t idblock_key[32];
} __attribute__((packed)) snp_mix_data_t;

// GUEST_FIELD_SELECT fields
#define SNP_GUEST_FIELD_GUEST_POLICY_FLAG  (1<<0)   // The guest policy will be mixed into the key
#define SNP_GUEST_FIELD_IMAGE_ID_FLAG      (1<<1)   // The image ID of the guest will be mixed into the key
#define SNP_GUEST_FIELD_FAMILY_ID_FLAG     (1<<2)   // The family ID of the guest will be mixed into the key
#define SNP_GUEST_FIELD_MEASUREMENT_FLAG   (1<<3)   // The measurement of the guest during launch will be mixed into the key
#define SNP_GUEST_FIELD_GUEST_SVN_FLAG     (1<<4)   // The guest-provided SVN will be mixed into the key
#define SNP_GUEST_FIELD_TCB_VERSION_FLAG   (1<<5)   // The guest-provided TCB version string will be mixed into the key

typedef struct snp_msg_key_rsp
{
    uint32_t status;                // 0x0 Success, 0x16 Invalid parameters
    uint8_t reserved[0x20-0x4];
    uint8_t derived_key[32];        // The requested derived key if STATUS is 0h
} snp_msg_key_rsp_t;

// 7.3 Attestation
typedef struct snp_msg_report_req
{
    uint8_t report_data[64];    // Guest-provided data for the attestation report
    uint32_t vmpl;              // The VMPL to put into the attestation report
    uint8_t reserved[0x60-0x44];
} snp_msg_report_req_t;

typedef struct snp_attestation_report_platform_info
{
    uint32_t smt_en   : 1;
    uint64_t reserved : 63;
} __attribute__((packed)) snp_platform_info_t;
static_assert(sizeof(snp_platform_info_t) == sizeof(uint64_t), "Error, static assertion failed");

#define SNP_GMSG_MAX_REPORT_VERSION 1
typedef struct snp_attestation_report
{
    uint32_t version;               /* 0h */
    uint32_t guest_svn;             /* 4h */
    uint64_t policy;                /* 8h */
    uint8_t family_id[16];          /* 10h */
    uint8_t image_id[16];           /* 20h */
    uint32_t vmpl;                  /* 30h */
    uint32_t signature_algo;        /* 34h */
    snp_tcb_version_t tcb_version;  /* 38h */
    snp_platform_info_t platform_info; /* 40h */
    uint32_t author_key_en : 1;     /* 48h */
    uint32_t reserved      : 31;
    uint32_t reserved2;             /* 4C */
    uint8_t report_data[64];        /* 50h */
    uint8_t measurement[48];        /* 90h */
    uint8_t host_data[32];          /* C0h */
    uint8_t id_key_digest[48];      /* E0h */
    uint8_t author_key_digest[48];  /* 110h */
    uint8_t report_id[32];          /* 140h */
    uint8_t report_id_ma[32];       /* 160h */
    snp_tcb_version_t reported_tcb; /* 180h */
    uint8_t reserved3[0x1A0-0x188]; /* 188h-19Fh */
    uint8_t chip_id[64];            /* 1A0h */
    uint64_t committed_tcb;         /* 1E0h */
    uint8_t current_build;          /* 1E8h */
    uint8_t current_minor;          /* 1E9h */
    uint8_t current_major;          /* 1EAh */
    uint8_t reserved4;              /* 1EBh */
    uint8_t committed_build;         /* 1ECh */
    uint8_t committed_minor;         /* 1EDh */
    uint8_t committed_major;         /* 1EEh */
    uint8_t reserved5;              /* 1EFh */
    uint64_t launch_tcb;            /* 1F0h */
    uint8_t reserved6[0x2A0-0x1F8];  /* 1F8h-29Fh */
    uint8_t signature[0x4A0-0x2A0]; /* 2A0h-49Fh */
} __attribute__((packed)) snp_attestation_report_t;
static_assert(sizeof(snp_attestation_report_t) == 0x4A0, "Error, static assertion failed");

typedef struct snp_msg_report_rsp
{
    uint32_t status;
    uint32_t report_size;
    uint8_t reserved[0x20-0x08];
    snp_attestation_report_t report;
} __attribute__((packed)) snp_msg_report_rsp_t;

// 7.4 VM Export
#define SNP_GMSG_MAX_XPORT_GCTX_VERSION 2   // Export, Import,  Absorb, Absorb_NoMA
typedef struct snp_msg_export_req
{
    uint64_t gctx_paddr;
    uint32_t imi_en   : 1;
    uint32_t reserved : 31;
    uint32_t reserved2;
} snp_msg_export_req_t;

typedef struct snp_msg_gctx
{
    uint8_t ld[48];
    uint8_t oek[32];
    uint8_t vmpck0[32];
    uint8_t vmpck1[32];
    uint8_t vmpck2[32];
    uint8_t vmpck3[32];
    uint8_t vmrk[32];
    uint8_t host_data[32];
    uint8_t id_key_digest[48];
    uint8_t author_key_digest[48];
    uint8_t report_id[32];
    uint8_t imd[48];
    uint64_t msg_count0;
    uint64_t msg_count1;
    uint64_t msg_count2;
    uint64_t msg_count3;
    snp_metadata_page_t root_md_entry;
    uint32_t author_key_en : 1;  /* bit 0 */
    uint32_t id_block_en   : 1;  /* bit 1 */
    uint64_t reserved      : 60; /* bits 61:2 */
    uint64_t policy;
    uint8_t state;
    uint64_t oek_iv_count;
    snp_launch_finish_id_block id_block;
    uint8_t gosvw[16];
    uint8_t reserved2[0x300-0x2B0];
} snp_msg_gctx_t;
static_assert(sizeof(snp_msg_gctx_t) == 0x300, "Error, static assertion failed");

typedef struct snp_msg_export_rsp
{
    uint32_t status;
    uint32_t gctx_size;
    uint32_t gctx_version;
    uint8_t reserved[0x20-0x0C];
    snp_msg_gctx_t gctx;
} snp_msg_export_rsp_t;

// 7.5 VM Import
typedef struct snp_msg_import_req
{
    uint64_t gctx_paddr;
    uint32_t in_gctx_size;
    uint32_t in_gctx_version;
    uint8_t reserved[0x20-0x10];
    snp_msg_gctx_t incoming_gctx;
} snp_msg_import_req_t;

typedef struct snp_msg_import_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_import_rsp_t;

// 7.6 VM Absorb
typedef struct snp_msg_absorb_req
{
    uint64_t gctx_paddr;
    uint32_t in_gctx_size;
    uint32_t in_gctx_version;
    uint8_t reserved[0x20-0x10];
    snp_msg_gctx_t incoming_gctx;
} snp_msg_absorb_req_t;

typedef struct snp_msg_absorb_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_absorb_rsp_t;

// 7.7 VM Absorb - No MA
typedef struct snp_msg_absorb_noma_req
{
    uint64_t reserved;
    uint32_t in_gctx_size;
    uint32_t in_gctx_version;
    uint8_t reserved2[0x20-0x10];
    snp_msg_gctx_t incoming_gctx;
} snp_msg_absorb_noma_req_t;

typedef struct snp_msg_absorb_noma_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_absorb_noma_rsp_t;

// 7.8 VMRK Message
typedef struct snp_msg_vmrk_req
{
    uint64_t gctx_paddr;
    uint8_t reserved[0x20-0x08];
    uint8_t vmrk[32];
} snp_msg_vmrk_req_t;

typedef struct snp_msg_vmrk_rsp
{
    uint32_t status;
    uint8_t reserved[0x10-0x4];
} snp_msg_vmrk_rsp_t;

// 9.21 Data Structores and Encodings
// typedef enum snp_guest_message
// {
//     SNP_MSG_INVALID         = 0x0,
//     SNP_MSG_CPUID_REQ       = 0x1,
//     SNP_MSG_CPUID_RSP       = 0x2,
//     SNP_MSG_KEY_REQ         = 0x3,
//     SNP_MSG_KEY_RSP         = 0x4,
//     SNP_MSG_REPORT_REQ      = 0x5,
//     SNP_MSG_REPORT_RSP      = 0x6,
//     SNP_MSG_EXPORT_REQ      = 0x7,
//     SNP_MSG_EXPORT_RSP      = 0x8,
//     SNP_MSG_IMPORT_REQ      = 0x9,
//     SNP_MSG_IMPORT_RSP      = 0xA,
//     SNP_MSG_ABSORB_REQ      = 0xB,
//     SNP_MSG_ABSORB_RSP      = 0xC,
//     SNP_MSG_VMRK_REQ        = 0xD,
//     SNP_MSG_VMRK_RSP        = 0xE,
//     SNP_MSG_ABSORB_NOMA_REQ = 0xF,
//     SNP_MSG_ABSORB_NOMA_RSP = 0x10,

//     SNP_MSG_LIMIT,
// } snp_guest_message_t;

#define PADDR_INVALID  ~(0x0ull)            /* -1 */

#endif /* RMP_H */
