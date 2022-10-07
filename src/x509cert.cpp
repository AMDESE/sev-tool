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

#include "utilities.h"
#include "x509cert.h"
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <cstring>  // memset
#include <fstream>
#include <cstdio>
#include <stdexcept>
#include <memory>

// Print a certificate
// openssl x509 -in certificate.crt -text -noout

// OpenSSL verify
// openssl verify -trusted ark.pem -untrusted ask.pem vcek.pem

void convert_txt_to_der(const std::string in_file_name, const std::string out_file_name)
{
    std::string cmd = "openssl x509 -outform der -in " + in_file_name + " -out " + out_file_name;
    std::string output;

    sev::execute_system_command(cmd, &output);
}

void convert_der_to_pem(const std::string in_file_name, const std::string out_file_name)
{
    std::string cmd = "openssl x509 -inform der -in " + in_file_name + " -out " + out_file_name;
    std::string output;

    sev::execute_system_command(cmd, &output);
}

std::unique_ptr<X509, decltype(&X509_free)> read_pem_into_x509(const std::string file_name)
{
    std::unique_ptr<X509, decltype(&X509_free)> result{nullptr, &X509_free};
    std::unique_ptr<FILE, decltype(&fclose)> pFile{nullptr, &fclose};
    pFile.reset(fopen(file_name.c_str(), "re"));
    if (!pFile)
        return result;

    // printf("Reading from file: %s\n", file_name.c_str());
    result.reset(PEM_read_X509(pFile.get(), nullptr, nullptr, nullptr));
    if (!result) {
        printf("Error reading x509 from file: %s\n", file_name.c_str());
    }
    return result;
}

bool write_x509_pem(const std::string file_name, X509 *x509_cert)
{
    std::unique_ptr<FILE, decltype(&fclose)> pFile{nullptr, &fclose};
    pFile.reset(fopen(file_name.c_str(), "wt"));
    if (!pFile)
        return false;

    // printf("Writing to file: %s\n", file_name.c_str());
    if (PEM_write_X509(pFile.get(), x509_cert) != 1) {
        printf("Error writing x509 to file: %s\n", file_name.c_str());
        return false;
    }
    return true;
}

bool x509_validate_signature(X509 *child_cert, X509 *intermediate_cert, X509 *parent_cert)
{
    bool ret = false;

    do {
        // Create the store
        std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store{nullptr, &X509_STORE_free};
        store.reset(X509_STORE_new());
        if (!store)
            break;

        // Add the parent cert to the store
        if (X509_STORE_add_cert(store.get(), parent_cert) != 1) {
            printf("Error adding parent_cert to x509_store\n");
            break;
        }

        // Add the intermediate cert to the store
        if (intermediate_cert) {
            if (X509_STORE_add_cert(store.get(), intermediate_cert) != 1) {
                printf("Error adding intermediate_cert to x509_store\n");
                break;
            }
        }

        // Create the store context
        std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> store_ctx{nullptr, &X509_STORE_CTX_free};
        store_ctx.reset(X509_STORE_CTX_new());
        if (!store_ctx) {
            printf("Error creating x509_store_context\n");
            break;
        }

        // Pass the store (parent and intermediate cert) and child cert (that we want to verify) into the store context
        if (X509_STORE_CTX_init(store_ctx.get(), store.get(), child_cert, nullptr) != 1) {
            printf("Error initializing 509_store_context\n");
            break;
        }

        // Specify which cert to validate
        X509_STORE_CTX_set_cert(store_ctx.get(), child_cert);

        // Verify the certificate
        ret = X509_verify_cert(store_ctx.get());

        // Print out error code
        if (ret == 0)
            printf("Error verifying cert: %s\n", X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx.get())));

        if (ret != 1)
            break;

        ret = true;
    } while (false);

    return ret;
}
