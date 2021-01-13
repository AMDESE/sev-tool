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

#ifndef TESTS_H
#define TESTS_H

class Tests {
private:
    std::string m_output_folder = "";
    int m_verbose_flag = 0;

    bool clear_output_folder();

public:
    Tests(std::string output_folder, int verbose_flag);
    ~Tests() {};

    bool test_factory_reset(void);
    bool test_platform_status(void);
    bool test_pek_gen(void);
    bool test_pek_csr(void);
    bool test_sign_pek_csr(void);
    bool test_pdh_gen(void);
    bool test_pdh_cert_export(void);
    bool test_pek_cert_import(void);
    bool test_get_id(void);
    bool test_set_self_owned(void);
    bool test_set_externally_owned(void);
    bool test_generate_cek_ask(void);
    bool test_get_ask_ark(void);
    bool test_export_cert_chain(void);
    bool test_calc_measurement(void);
    bool test_validate_cert_chain(void);
    bool test_generate_launch_blob(void);
    bool test_package_secret(void);
    bool test_all();
};

#endif /* TESTS_H */
