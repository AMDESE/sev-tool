/**************************************************************************
 * Copyright 2018-2021 Advanced Micro Devices, Inc.
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

#ifndef UTILITIES_H
#define UTILITIES_H

#include <string>
#include <vector>

namespace sev
{
    #define SEV_DEFAULT_DIR       "/usr/psp-sev-assets/"
    #define KDS_CERT_SITE         "https://kdsintf.amd.com"
    #define KDS_DEV_CERT_SITE     "https://kdsintfdev.amd.com"
    #define KDS_CEK               KDS_CERT_SITE "/cek/id/"
    #define KDS_VCEK              KDS_CERT_SITE "/vcek/v1/"   // KDS_VCEK/{product_name}/{hwid}?{tcb parameter list}
    #define KDS_VCEK_CERT_CHAIN   "cert_chain"                // KDS_VCEK/{product_name}/cert_chain
    #define KDS_VCEK_CRL          "crl"                       // KDS_VCEK/{product_name}/crl"

    #define PAGE_SIZE               4096        // Todo remove this one?
    #define PAGE_SIZE_4K            4096
    #define PAGE_SIZE_2M            (512*PAGE_SIZE_4K)

    #define IS_ALIGNED(e, x)            (0==(((uintptr_t)(e))%(x)))
    #define IS_ALIGNED_TO_16_BYTES(e)   IS_ALIGNED((e), 16)         // 4 bits
    #define IS_ALIGNED_TO_32_BYTES(e)   IS_ALIGNED((e), 32)         // 5 bits
    #define IS_ALIGNED_TO_64_BYTES(e)   IS_ALIGNED((e), 64)         // 6 bits
    #define IS_ALIGNED_TO_128_BYTES(e)  IS_ALIGNED((e), 128)        // 7 bits
    #define IS_ALIGNED_TO_4KB(e)        IS_ALIGNED((e), 4096)       // 12 bits
    #define IS_ALIGNED_TO_1MB(e)        IS_ALIGNED((e), 0x100000)   // 20 bits
    #define IS_ALIGNED_TO_2MB(e)        IS_ALIGNED((e), 0x200000)   // 21 bits

    #define ALIGN_TO_16_BYTES(e)        ((((uintptr_t)(e))+0xF)&(~(uintptr_t)0xF))
    #define ALIGN_TO_32_BYTES(e)        ((((uintptr_t)(e))+0x1F)&(~(uintptr_t)0x1F))
    #define ALIGN_TO_64_BYTES(e)        ((((uintptr_t)(e))+0x3F)&(~(uintptr_t)0x3F))

    #define BITS_PER_BYTE    8

    static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                    unsigned int *ecx, unsigned int *edx)
    {
        // ecx is often an input as well as an output.
        asm volatile("cpuid"
            : "=a" (*eax),
              "=b" (*ebx),
              "=c" (*ecx),
              "=d" (*edx)
            : "0" (*eax), "2" (*ecx));
    }

    static inline unsigned int cpuid_ebx(unsigned int op)
    {
        unsigned int eax = op, ebx = 0, ecx = 0, edx = 0;

        native_cpuid(&eax, &ebx, &ecx, &edx);
        return ebx;
    }

    /**
     * Executes a bash command and returns results as a string
     */
    bool execute_system_command(const std::string cmd, std::string *log);

    /**
     * Read an entire file in to a buffer, or as much as will fit.
     * Return length of file or of buffer, whichever is smaller.
     */
    size_t read_file(const std::string file_name, void *buffer, size_t len);

    /**
     * Truncate and write (not append) a file from the beginning
     * Returns number of bytes written
     */
    size_t write_file(const std::string file_name, const void *buffer, size_t len);

    /**
     * Returns the file size in number of bytes
     * May be used to tell if a file exists
     */
    size_t get_file_size(const std::string file_name);

    /**
     * Generate some random bytes
     */
    void gen_random_bytes(void *bytes, size_t num_bytes);

    /**
     * Verify read/write access to an area of memory.
     * Used to confirm TMR (trusted memory region) release.
     */
    bool verify_access(uint8_t *buf, size_t len);

    /**
     * Converts a string of ascii-encoded hex bytes into a Hex array
     * Ex. To generate the string, do printf("%02x", myArray) will generate
     *     "0123456ACF" and this function will put it back into an array
     * This function is expecting the input string to be an even number of
     *      elements not including the null terminator
     */
    bool str_to_array(const std::string in_string, uint8_t *array, uint32_t array_size);

    /**
     * If you have a buffer (or read in input file) that's in AsciiHexBytes,
     * such as the getid output files, this will read it back into a buffer
     */
    std::vector<uint8_t> ascii_hex_bytes_to_binary(const char *in_bytes, size_t len);

    /**
     * Reverses bytes in a section of memory. Used in validating cert signatures
     */
    bool reverse_bytes(uint8_t *bytes, size_t size);

    /**
     * Checks if memory is 0. Similar to memcmp but doesn't require a second object
     */
    bool is_zero(const uint8_t *ptr, size_t bytes);
} // namespace

#endif /* UTILITIES_H */
