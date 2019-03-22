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

bool Tests::test_factory_reset()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting factory_reset tests\n");

        if(cmd.factory_reset() != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

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

bool Tests::test_pek_gen()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting pek_gen tests\n");

        if(cmd.pek_gen() != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_pek_csr()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting pek_csr tests\n");

        if(cmd.pek_csr(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_pdh_gen()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting pdh_gen tests\n");

        if(cmd.pdh_gen() != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_pdh_cert_export()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting pdh_cert_export tests\n");

        if(cmd.pdh_cert_export(m_output_folder, m_verbose_flag) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_pek_cert_import()
{
    bool ret = false;
    Command cmd;
    SEV_CERT dummy;
    SEVCert cert(dummy);

    do {
        printf("*Starting pek_cert_import tests\n");

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

        ret = true;
    } while (0);

    return ret;
}

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

bool Tests::test_set_self_owned()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting set_self_owned tests\n");

        if(cmd.set_self_owned() != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_set_externally_owned()
{
    bool ret = false;
    Command cmd;
    SEV_CERT dummy;
    SEVCert cert(dummy);

    do {
        printf("*Starting set_externally_owned tests\n");

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

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_generate_cek_ask()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting generate_cek_ask tests\n");

        if(cmd.generate_cek_ask(m_output_folder) != STATUS_SUCCESS)
            break;

        ret = true;
    } while (0);

    return ret;
}

bool Tests::test_get_ask_ark()
{
    bool ret = false;
    Command cmd;

    do {
        printf("*Starting get_ask_ark tests\n");

        if(cmd.get_ask_ark(m_output_folder) != STATUS_SUCCESS)
            break;

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