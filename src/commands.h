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

#include "x509cert.h"
#include "linux/psp-sev.h"

class Command {
private:


public:
    Command() {};
    ~Command() {};

    int factory_reset();
    int platform_status();
    int pek_gen();
    int pek_csr();
    int pdh_gen();
    int pdh_cert_export();
    int pek_cert_import();
    int get_id();
};

#endif /* sevcert_h */
