/**************************************************************************
 * Copyright 2020 Advanced Micro Devices, Inc.
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

#ifndef X509CERT_H
#define X509CERT_H

#include "sevapi.h"
#include <string>

// Public global functions
void convert_txt_to_der(const std::string in_file_name, const std::string out_file_name);
void convert_der_to_pem(const std::string in_file_name, const std::string out_file_name);
bool read_pem_into_x509(const std::string file_name, X509 **x509_cert);
bool write_x509_pem(const std::string file_name, X509 *x509_cert);
bool x509_validate_signature(X509 *child_cert, X509 *intermediate_cert, X509 *parent_cert);

#endif /* X509CERT_H */
