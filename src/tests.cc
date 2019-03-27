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

//TODO check if these are needed
#include "amdcert.h"
#include "commands.h"
#include "sevapi.h"
#include "sevcert.h"
#include "tests.h"
#include "utilities.h"  // for WriteToFile
#include <cstring>      // For memcmp
#include <stdio.h>      // prboolf
#include <stdlib.h>     // malloc

bool Tests::clear_output_folder()
{
    std::string cmd = "rm -rf " + m_output_folder + "*";
    std::string output = "";
    if(!ExecuteSystemCommand(cmd, &output))
        return false;
    return true;
}

/**
 * The only way to change from externally-owned to self-owned is through a
 * factory reset. So, the best way to test that a factory reset actually worked
 * is by checking if the Platform ownership goes back from externally-owned to
 * self-owned after sending the factory_reset command.
 */
bool Tests::test_factory_reset()
{
    bool ret = false;
    Command cmd;
    SEV_CERT dummy;
    SEVCert cert(dummy);

    do {
        printf("*Starting factory_reset tests\n");

        // Generate a new random ECDH keypair
        EVP_PKEY *oca_keypair = NULL;
        if(!cert.generate_ecdh_keypair(&oca_keypair))
            break;

        // Export the priv key to a pem file
        std::string oca_priv_key_pem = m_output_folder + "oca_priv_key.pem";
        write_privkey_pem(oca_priv_key_pem, oca_keypair);

        // The only way to go from externally owned to self-owned is to do a
        // factory reset, so that's the best way to tell factory_reset working
        if(cmd.set_externally_owned(oca_priv_key_pem) != STATUS_SUCCESS) {
            printf("Error: Set Platform externally owned, failed\n");
            break;
        }

        // Confirm we're externally owned
        if(cmd.get_platform_owner() != PLATFORM_STATUS_OWNER_EXTERNAL) {
            printf("Error: Platform not externally-owned after pek_cert_import\n");
            break;
        }

        // Could call set_self_owned here, but there's a separate test for that
        if(cmd.factory_reset() != STATUS_SUCCESS) {
            printf("Error: Factory reset, failed\n");
            break;
        }

        // Confirm we're self owned
        if(cmd.get_platform_owner() != PLATFORM_STATUS_OWNER_SELF) {
            printf("Error: Platform not self-owned after factory_reset\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Just check that the command succeeds
 */
bool Tests::test_platform_status()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting platform_status tests\n");

        if(cmd.platform_status() != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

/**
 * Compare PEK and PDH certs before and after calling pek_gen, they should both
 * be new.
 */
bool Tests::test_pek_gen()
{
    bool ret = false;
    Command cmd;
    std::string cert_chain_full = m_output_folder + CERT_CHAIN_HEX_FILENAME;
    std::string pdh_cert_full = m_output_folder + PDH_FILENAME;
    SEV_CERT_CHAIN_BUF cert_chain_orig;
    SEV_CERT_CHAIN_BUF cert_chain_new;
    SEV_CERT pdh_orig;
    SEV_CERT pdh_new;

    do {
        printf("*Starting pek_gen tests\n");

        // Export the original PEK/PDH certs from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export original PEK/PDH certificates\n");
            break;
        }

        // Read in the original PEK/PDH certs
        if(ReadFile(cert_chain_full, &cert_chain_orig, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh_orig, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Call pek_gen to generate a new PEK, which also generates a new PDH
        if(cmd.pek_gen() != STATUS_SUCCESS) {
            printf("Error: Failure in pek_gen command\n");
            break;
        }

        // Export the new PEK/PDH certs from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export new PEK/PDH certificates\n");
            break;
        }

        // Read in the new PEK/PDH certs
        if(ReadFile(cert_chain_full, &cert_chain_new, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh_new, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Make sure the original and new certs are different
        if(memcmp(PEKinCertChain(&cert_chain_new), PEKinCertChain(&cert_chain_orig), sizeof(SEV_CERT)) == 0) {
            printf("Error: PEK cert did not change after pek_gen\n");
            break;
        }
        if(memcmp(&pdh_new, &pdh_orig, sizeof(SEV_CERT)) == 0) {
            printf("Error: PDH cert did not change after pek_gen\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Call the command to generate the CSR, do basic validation on the CSR.
 */
bool Tests::test_pek_csr()
{
    bool ret = false;
    Command cmd;
    std::string pekcsr_full = m_output_folder + PEK_CSR_HEX_FILENAME;
    SEV_CERT pekcsr;

    do {
        printf("*Starting pek_csr tests\n");

        if(cmd.pek_csr(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        // Read in the CSR
        if(ReadFile(pekcsr_full, &pekcsr, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Check the usage of the CSR
        if(pekcsr.PubkeyUsage != SEVUsagePEK) {
            printf("Error: PEKCsr certificate Usage did not match expected value\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Compare PEK and PDH certs before and after calling pek_gen, PEK certs should
 * be the same and PDH cert should be new.
 */
bool Tests::test_pdh_gen()
{
    bool ret = false;
    Command cmd;
    std::string cert_chain_full = m_output_folder + CERT_CHAIN_HEX_FILENAME;
    std::string pdh_cert_full = m_output_folder + PDH_FILENAME;
    SEV_CERT_CHAIN_BUF cert_chain_orig;
    SEV_CERT_CHAIN_BUF cert_chain_new;
    SEV_CERT pdh_orig;
    SEV_CERT pdh_new;

    do {
        printf("*Starting pek_gen tests\n");

        // Export the original PEK/PDH certs from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export original PEK/PDH certificates\n");
            break;
        }

        // Read in the original PEK/PDH certs
        if(ReadFile(cert_chain_full, &cert_chain_orig, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh_orig, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Call pek_gen to generate a new PEK, which also generates a new PDH
        if(cmd.pdh_gen() != STATUS_SUCCESS) {
            printf("Error: Failure in pek_gen command\n");
            break;
        }

        // Export the new PEK/PDH certs from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export new PEK/PDH certificates\n");
            break;
        }

        // Read in the new PEK/PDH certs
        if(ReadFile(cert_chain_full, &cert_chain_new, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh_new, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Make sure the PEK certs are the same and PDH certs are different
        if(memcmp(PEKinCertChain(&cert_chain_new), PEKinCertChain(&cert_chain_orig), sizeof(SEV_CERT)) != 0) {
            printf("Error: PEK cert changed after pek_gen\n");
            break;
        }
        if(memcmp(&pdh_new, &pdh_orig, sizeof(SEV_CERT)) == 0) {
            printf("Error: PDH cert did not change after pek_gen\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Run the test_pdh_cert_export command, read in the PDH cert and cert chain,
 * and check the usages of all the certs. Not much else we can test, really.
 */
bool Tests::test_pdh_cert_export()
{
    bool ret = false;
    Command cmd;
    std::string cert_chain_full = m_output_folder + CERT_CHAIN_HEX_FILENAME;
    std::string pdh_cert_full = m_output_folder + PDH_FILENAME;
    SEV_CERT_CHAIN_BUF cert_chain;
    SEV_CERT pdh;

    do {
        printf("*Starting pdh_cert_export tests\n");

        // Export the PDH cert and cert chain from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export PDH certificate/cert chain\n");
            break;
        }

        // Read in the PDH and cert chain
        if(ReadFile(cert_chain_full, &cert_chain, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Check the usage of all certs
        if(pdh.PubkeyUsage != SEVUsagePDH ||
           ((SEV_CERT *)PEKinCertChain(&cert_chain))->PubkeyUsage != SEVUsagePEK ||
           ((SEV_CERT *)OCAinCertChain(&cert_chain))->PubkeyUsage != SEVUsageOCA ||
           ((SEV_CERT *)CEKinCertChain(&cert_chain))->PubkeyUsage != SEVUsageCEK) {
            printf("Error: Certificate Usage did not match expected value\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Compare PEK and PDH certs before and after calling test_pek_cert_import, they
 * should both be new.
 */
bool Tests::test_pek_cert_import()
{
    bool ret = false;
    Command cmd;
    std::string cert_chain_full = m_output_folder + CERT_CHAIN_HEX_FILENAME;
    std::string pdh_cert_full = m_output_folder + PDH_FILENAME;
    SEV_CERT_CHAIN_BUF cert_chain_orig;
    SEV_CERT_CHAIN_BUF cert_chain_new;
    SEV_CERT pdh_orig;
    SEV_CERT pdh_new;
    SEV_CERT dummy;
    SEVCert cert(dummy);

    do {
        printf("*Starting pek_cert_import tests\n");

        // Set Platform to self-owned
        if(cmd.set_self_owned() != STATUS_SUCCESS) {
            printf("Error: Failed to set Platform to self-owned\n");
            break;
        }

        // Export the original PEK/PDH certs from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export original PEK/PDH certificates\n");
            break;
        }

        // Read in the original PEK/PDH certs
        if(ReadFile(cert_chain_full, &cert_chain_orig, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh_orig, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Generate a new random ECDH keypair
        EVP_PKEY *oca_keypair = NULL;
        if(!cert.generate_ecdh_keypair(&oca_keypair))
            break;

        // Export the priv key to a pem file
        std::string oca_priv_key_pem = m_output_folder + "oca_priv_key.pem";
        write_privkey_pem(oca_priv_key_pem, oca_keypair);

        // Call pek_cert_import and pass in the pem file's location
        if(cmd.pek_cert_import(oca_priv_key_pem) != STATUS_SUCCESS)
            break;

        // Export the new PEK/PDH certs from the Platform
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS) {
            printf("Error: Failed to export new PEK/PDH certificates\n");
            break;
        }

        // Read in the new PEK/PDH certs
        if(ReadFile(cert_chain_full, &cert_chain_new, sizeof(SEV_CERT_CHAIN_BUF)) != sizeof(SEV_CERT_CHAIN_BUF))
            break;
        if(ReadFile(pdh_cert_full, &pdh_new, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Make sure the original and new certs are different
        if(memcmp(PEKinCertChain(&cert_chain_new), PEKinCertChain(&cert_chain_orig), sizeof(SEV_CERT)) == 0) {
            printf("Error: PEK cert did not change after pek_gen\n");
            break;
        }
        if(memcmp(&pdh_new, &pdh_orig, sizeof(SEV_CERT)) == 0) {
            printf("Error: PDH cert did not change after pek_gen\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Not really much we can test here except check if the command succeeds.
 * Development parts all have the same ID, so can't even check to make sure the
 * ID's are different
 */
bool Tests::test_get_id()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting get_id tests\n");

        if(cmd.get_id(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

/**
 * Set platform to externally owned, and then call set_self_owned
 * Same test as platform_reset except are calling set_self_owned instead of
 *   platform_reset at the end. set_self_owned calls platform_reset, so it's
 *   really still the same test.
 */
bool Tests::test_set_self_owned()
{
    bool ret = false;
    Command cmd;
    SEV_CERT dummy;
    SEVCert cert(dummy);

    do {
        printf("*Starting factory_reset tests\n");

        // Generate a new random ECDH keypair
        EVP_PKEY *oca_keypair = NULL;
        if(!cert.generate_ecdh_keypair(&oca_keypair))
            break;

        // Export the priv key to a pem file
        std::string oca_priv_key_pem = m_output_folder + "oca_priv_key.pem";
        write_privkey_pem(oca_priv_key_pem, oca_keypair);

        // The only way to go from externally owned to self-owned is to do a
        // factory reset, so that's the best way to tell factory_reset working
        if(cmd.set_externally_owned(oca_priv_key_pem) != STATUS_SUCCESS) {
            printf("Error: Set Platform externally owned, failed\n");
            break;
        }

        // Confirm we're externally owned
        if(cmd.get_platform_owner() != PLATFORM_STATUS_OWNER_EXTERNAL) {
            printf("Error: Platform not externally-owned after pek_cert_import\n");
            break;
        }

        // Could call set_self_owned here, but there's a separate test for that
        if(cmd.set_self_owned() != STATUS_SUCCESS) {
            printf("Error: Factory reset, failed\n");
            break;
        }

        // Confirm we're self owned
        if(cmd.get_platform_owner() != PLATFORM_STATUS_OWNER_SELF) {
            printf("Error: Platform not self-owned after factory_reset\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Call factory_reset to set Platform to self-owned, then call set_externally_owned
 */
bool Tests::test_set_externally_owned()
{
    bool ret = false;
    Command cmd;
    SEV_CERT dummy;
    SEVCert cert(dummy);

    do {
        printf("*Starting set_externally_owned tests\n");

        // Set Platform to self-owned
        if(cmd.factory_reset() != STATUS_SUCCESS) {
            printf("Error: Factory reset, failed\n");
            break;
        }

        // Generate a new random ECDH keypair
        EVP_PKEY *oca_keypair = NULL;
        if(!cert.generate_ecdh_keypair(&oca_keypair))
            break;

        //  Export the priv key to a pem file
        std::string oca_priv_key_pem = m_output_folder + "oca_priv_key.pem";
        write_privkey_pem(oca_priv_key_pem, oca_keypair);

        // Call set_externally_owned which calls pek_cert_import (which needs
        //  the oca private key's pem file's location)
        if(cmd.set_externally_owned(oca_priv_key_pem) != STATUS_SUCCESS)
            break;

        // Confirm we're externally-owned
        if(cmd.get_platform_owner() != PLATFORM_STATUS_OWNER_EXTERNAL) {
            printf("Error: Platform not externally-owned after pek_cert_import\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Call function, read in cert, and check usage
 */
bool Tests::test_generate_cek_ask()
{
    bool ret = false;
    Command cmd;
    std::string cek_full = m_output_folder + CEK_FILENAME;
    SEV_CERT cek;

    do {
        printf("*Starting generate_cek_ask tests\n");

        if(cmd.generate_cek_ask(m_output_folder) != STATUS_SUCCESS)
            break;

        // Read in the CEK
        if(ReadFile(cek_full, &cek, sizeof(SEV_CERT)) != sizeof(SEV_CERT))
            break;

        // Check the usage of the CEK
        if(cek.PubkeyUsage != SEVUsageCEK) {
            printf("Error: CEK certificate Usage did not match expected value\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

/**
 * Call the command to pull the cert from the server. Read in the ask_ark and
 * split it up in separate ask and ark certs. Then, check the certs to make sure
 * they have the correct Usage.
 */
bool Tests::test_get_ask_ark()
{
    bool ret = false;
    Command cmd;
    std::string ask_ark_full = m_output_folder + ASK_ARK_FILENAME;
    AMD_CERT ask;
    AMD_CERT ark;
    AMDCert tmp_amd;

    do {
        printf("*Starting get_ask_ark tests\n");

        if(cmd.get_ask_ark(m_output_folder) != STATUS_SUCCESS)
            break;

        // Read in the ask_ark so we can split it into 2 separate cert files
        uint8_t ask_ark_buf[sizeof(AMD_CERT)*2] = {0};
        if(ReadFile(ask_ark_full, ask_ark_buf, sizeof(ask_ark_buf)) == 0) {
            printf("Error: Unable to read in ASK_ARK certificate\n");
            break;
        }

        // Initialize the ASK
        if (tmp_amd.amd_cert_init(&ask, ask_ark_buf) != STATUS_SUCCESS) {
            printf("Error: Failed to initialize ASK certificate\n");
            break;
        }
        // print_amd_cert_readable(&ask);

        // Initialize the ARK
        size_t ask_size = tmp_amd.amd_cert_get_size(&ask);
        if (tmp_amd.amd_cert_init(&ark, (uint8_t *)(ask_ark_buf + ask_size)) != STATUS_SUCCESS) {
            printf("Error: Failed to initialize ARK certificate\n");
            break;
        }
        // print_amd_cert_readable(&ark);

        // Check the usage of the ASK and ARK
        if(ask.KeyUsage != AMDUsageASK || ark.KeyUsage != AMDUsageARK ) {
            printf("Error: Certificate Usage did not match expected value\n");
            break;
        }

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_export_cert_chain()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting export_cert_chain tests\n");

        if(cmd.export_cert_chain(m_output_folder) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

/**
 *  Pass in known input and check against expected output
 */
bool Tests::test_calc_measurement()
{
    bool ret = false;
    Command cmd;

    measurement_t data;
    data.meas_ctx  = 0x04;
    data.api_major = 0x00;
    data.api_minor = 0x12;
    data.build_id  = 0x0f;
    data.policy    = 0x00;
    StrToArray("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", (uint8_t *)&data.digest, sizeof(data.digest));
    StrToArray("4fbe0bedbad6c86ae8f68971d103e554", (uint8_t *)&data.mnonce, sizeof(data.mnonce));
    StrToArray("66320db73158a35a255d051758e95ed4", (uint8_t *)&data.tik, sizeof(data.tik));

    std::string expected_output = "6faab2daae389bcd3405a05d6cafe33c0414f7bedd0bae19ba5f38b7fd1664ea";

    do {
        printf("*Starting calc_measurement tests\n");

        if(cmd.calc_measurement(m_output_folder, m_verbose_flag, &data) != STATUS_SUCCESS)
            break;

        // Read in the actual output
        uint8_t actual_output[2*sizeof(HMACSHA256)];  // 2 chars per byte +1 for null term
        std::string meas_out_full = m_output_folder + CALC_MEASUREMENT_FILENAME;
        if(ReadFile(meas_out_full, actual_output, sizeof(actual_output)) != sizeof(actual_output))
            break;

        // Make sure the actual output is equal to the expected
        printf("Expected: %s\nActual  : %s\n", expected_output.c_str(), actual_output);
        if(memcmp(expected_output.c_str(), actual_output, sizeof(HMACSHA256)) != 0)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_validate_cert_chain()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting validate_cert_chain tests\n");

        if(cmd.validate_cert_chain(m_output_folder) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_generate_launch_blob()
{
    bool ret = false;
    Command cmd;

    uint32_t policy = SEV_POLICY_MIN;

    do {
        printf("*Starting generate_launch_blob tests\n");

        if(cmd.generate_launch_blob(m_output_folder, m_verbose_flag, policy) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_package_secret()
{
    bool ret = false;
    Command cmd;
    uint32_t policy = 0;
    std::string sys_cmd = "";
    std::string output = "";

    do {
        printf("*Starting package_secret tests\n");

        // Export the PDH cert to be read in during package_secret
        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        // Generate the launch start blob to be read in during package_secret
        if(cmd.generate_launch_blob(m_output_folder, m_verbose_flag, policy) != STATUS_SUCCESS)
            break;

        // Export a 'calculated measurement' that package_secret can read in for the header
        sys_cmd = "echo 6faab2daae389bcd3405a05d6cafe33c0414f7bedd0bae19ba5f38b7fd1664ea > " + m_output_folder + CALC_MEASUREMENT_FILENAME;
        if(!ExecuteSystemCommand(sys_cmd, &output))
            return false;

        // FAILURE test: Try a secrets file that's less than 8 bytes
        sys_cmd = "echo HELLO > " + m_output_folder + SECRET_FILENAME;
        if(!ExecuteSystemCommand(sys_cmd, &output))
            return false;
        if(cmd.package_secret(m_output_folder, m_verbose_flag) == STATUS_SUCCESS)   // fail
            break;

        // Try a secrets file of 8 bytes
        sys_cmd = "echo HELLOooo > " + m_output_folder + SECRET_FILENAME;
        if(!ExecuteSystemCommand(sys_cmd, &output))
            return false;
        if(cmd.package_secret(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        // Try a longer secrets file (use the readable cert_chain file from pdh_cert_export)
        sys_cmd = "cp " + m_output_folder + CERT_CHAIN_READABLE_FILENAME + " " + m_output_folder + SECRET_FILENAME;
        if(!ExecuteSystemCommand(sys_cmd, &output))
            return false;
        if(cmd.package_secret(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_all(std::string& output_folder, int verbose_flag)
{
    bool ret = false;

    m_output_folder = output_folder;
    m_verbose_flag = verbose_flag;

    do {
        clear_output_folder();

        if(!test_factory_reset())
            break;

        if(!test_platform_status())
            break;

        if(!test_pek_gen())
            break;

        if(!test_pek_csr())
            break;

        if(!test_pdh_gen())
            break;

        if(!test_pdh_cert_export())
            break;

        if(!test_pek_cert_import())
            break;

        if(!test_get_id())
            break;

        if(!test_set_self_owned())
            break;

        if(!test_set_externally_owned())
            break;

        if(!test_generate_cek_ask())
            break;

        if(!test_get_ask_ark())
            break;

        if(!test_export_cert_chain())
            break;

        if(!test_calc_measurement())
            break;

        // if(!test_validate_cert_chain())
        //     break;

        if(!test_generate_launch_blob())
            break;

        if(!test_package_secret())
            break;

        ret = true;
    } while (0);

    return ret;
}