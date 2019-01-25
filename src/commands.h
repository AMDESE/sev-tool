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

#ifndef commands_h
#define commands_h

#include "sevapi.h"
#include "sevcore.h"
#include "x509cert.h"
#include "linux/psp-sev.h"

class Command {

public:
    Command() {};
    ~Command() {};

    SEV_ERROR_CODE factory_reset(void);
    SEV_ERROR_CODE platform_status(void);
    SEV_ERROR_CODE pek_gen(void);
    SEV_ERROR_CODE pek_csr(void);
    SEV_ERROR_CODE pdh_gen(void);
    SEV_ERROR_CODE pdh_cert_export(void);
    SEV_ERROR_CODE pek_cert_import(void);
    SEV_ERROR_CODE get_id(void);

    SEV_ERROR_CODE calc_measurement(measurement_t *user_data);
    SEV_ERROR_CODE set_self_owned(void);
    SEV_ERROR_CODE set_externally_owned(void);
};

#endif /* sevcert_h */
