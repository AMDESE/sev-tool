/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Userspace interface for AMD Secure Encrypted Virtualization (SEV)
 * platform management commands.
 *
 * Copyright (C) 2016-2017 Advanced Micro Devices, Inc.
 *
 * Author: Brijesh Singh <brijesh.singh@amd.com>
 *
 * SEV API specification is available at: https://developer.amd.com/sev/
 */

#ifndef __PSP_SEV_USER_H__
#define __PSP_SEV_USER_H__

#include <linux/types.h>
#include <cinttypes>

static_assert(sizeof(void*) == sizeof(uint64_t), "This code requires 64-bit pointers to work");

/**
 * SEV platform commands
 */
enum {
    SEV_FACTORY_RESET = 0,
    SEV_PLATFORM_STATUS,   // 0x1
    SEV_PEK_GEN,           // 0x2
    SEV_PEK_CSR,           // 0x3
    SEV_PDH_GEN,           // 0x4
    SEV_PDH_CERT_EXPORT,   // 0x5
    SEV_PEK_CERT_IMPORT,   // 0x6
    SEV_GET_ID,    /* This command is deprecated, use SEV_GET_ID2 */
    SEV_GET_ID2,           // 0x8

    // Subject to change. Current info based on the sev-snp-part2 branch AMDESE/Linux fork.
    // https://github.com/AMDESE/linux/blob/sev-snp-part2-v6/include/uapi/linux/psp-sev.h
    SEV_SNP_PLATFORM_STATUS,   // 0x9
    SEV_SNP_SET_EXT_CONFIG,    // 0xA
    SEV_SNP_GET_EXT_CONFIG,    // 0xB

    SEV_MAX,
};

/**
 * SEV Firmware status code
 */
typedef enum {
    SEV_RET_SUCCESS = 0,
    SEV_RET_INVALID_PLATFORM_STATE,
    SEV_RET_INVALID_GUEST_STATE,
    SEV_RET_INAVLID_CONFIG,
    SEV_RET_INVALID_LEN,
    SEV_RET_ALREADY_OWNED,
    SEV_RET_INVALID_CERTIFICATE,
    SEV_RET_POLICY_FAILURE,
    SEV_RET_INACTIVE,
    SEV_RET_INVALID_ADDRESS,
    SEV_RET_BAD_SIGNATURE,
    SEV_RET_BAD_MEASUREMENT,
    SEV_RET_ASID_OWNED,
    SEV_RET_INVALID_ASID,
    SEV_RET_WBINVD_REQUIRED,
    SEV_RET_DFFLUSH_REQUIRED,
    SEV_RET_INVALID_GUEST,
    SEV_RET_INVALID_COMMAND,
    SEV_RET_ACTIVE,
    SEV_RET_HWSEV_RET_PLATFORM,
    SEV_RET_HWSEV_RET_UNSAFE,
    SEV_RET_UNSUPPORTED,
    SEV_RET_MAX,
} sev_ret_code;

/**
 * struct sev_user_data_status - PLATFORM_STATUS command parameters
 *
 * @major: major API version
 * @minor: minor API version
 * @state: platform state
 * @flags: platform config flags
 * @build: firmware build id for API version
 * @guest_count: number of active guests
 */
struct sev_user_data_status {
    __u8 api_major;                /* Out */
    __u8 api_minor;                /* Out */
    __u8 state;                    /* Out */
    __u32 flags;                   /* Out */
    __u8 build;                    /* Out */
    __u32 guest_count;             /* Out */
} __attribute__((packed));

/**
 * struct sev_user_data_pek_csr - PEK_CSR command parameters
 *
 * @address: PEK certificate chain
 * @length: length of certificate
 */
struct sev_user_data_pek_csr {
    void const *address;                 /* In */
    __u32 length;                  /* In/Out */
} __attribute__((packed));

/**
 * struct sev_user_data_cert_import - PEK_CERT_IMPORT command parameters
 *
 * @pek_address: PEK certificate chain
 * @pek_len: length of PEK certificate
 * @oca_address: OCA certificate chain
 * @oca_len: length of OCA certificate
 */
struct sev_user_data_pek_cert_import {
    void const *pek_cert_address;        /* In */
    __u32 pek_cert_len;            /* In */
    void const *oca_cert_address;        /* In */
    __u32 oca_cert_len;            /* In */
} __attribute__((packed));

/**
 * struct sev_user_data_pdh_cert_export - PDH_CERT_EXPORT command parameters
 *
 * @pdh_address: PDH certificate address
 * @pdh_len: length of PDH certificate
 * @cert_chain_address: PDH certificate chain
 * @cert_chain_len: length of PDH certificate chain
 */
struct sev_user_data_pdh_cert_export {
    void const *pdh_cert_address;        /* In */
    __u32 pdh_cert_len;            /* In/Out */
    void const *cert_chain_address;      /* In */
    __u32 cert_chain_len;          /* In/Out */
} __attribute__((packed));

/**
 * struct sev_user_data_get_id - GET_ID command parameters (deprecated)
 *
 * @socket1: Buffer to pass unique ID of first socket
 * @socket2: Buffer to pass unique ID of second socket
 */
struct sev_user_data_get_id {
    __u8 socket1[64];              /* Out */
    __u8 socket2[64];              /* Out */
} __attribute__((packed));

/**
 * struct sev_user_data_get_id2 - GET_ID command parameters
 * @address: Buffer to store unique ID
 * @length: length of the unique ID
 */
struct sev_user_data_get_id2 {
    void const *address;                /* In */
    __u32 length;                /* In/Out */
} __attribute__((packed));

/**
 * struct sev_issue_cmd - SEV ioctl parameters
 *
 * @cmd: SEV commands to execute
 * @opaque: pointer to the command structure
 * @error: SEV FW return code on failure
 */
struct sev_issue_cmd {
    __u32 cmd;                     /* In */
    void const *data;                    /* In */
    __u32 error;                   /* Out */
} __attribute__((packed));

#define SEV_IOC_TYPE     'S'
#define SEV_ISSUE_CMD    _IOWR(SEV_IOC_TYPE, 0x0, struct sev_issue_cmd)

#endif /* __PSP_USER_SEV_H */
