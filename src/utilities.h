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

#ifndef utilities_h
#define utilities_h

#include <string>

static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx)
{
    /* ecx is often an input as well as an output. */
    asm volatile("cpuid"
        : "=a" (*eax),
          "=b" (*ebx),
          "=c" (*ecx),
          "=d" (*edx)
        : "0" (*eax), "2" (*ecx));
}

static inline unsigned int cpuid_ebx(unsigned int op)
{
    unsigned int eax = op, ebx, ecx = 0, edx;

    native_cpuid(&eax, &ebx, &ecx, &edx);
    return ebx;
}

// Executes a bash command and returns results as a string
bool ExecuteSystemCommand(const std::string cmd, std::string *log);

// Read an entire file in to a buffer, or as much as will fit. Return length
// of file or of buffer, whichever is smaller.
size_t ReadFile(const std::string& filename, void *buffer, size_t len);

// Truncate and write (not append) a file from the beginning
// Returns number of bytes written
size_t WriteFile(const std::string& filename, const void *buffer, size_t len);

// Returns the file size in number of bytes
size_t GetFileSize(const std::string& filename);

// Generate some random bytes
void GenRandomBytes( void *bytes, size_t numBytes );

// Verify read/write access to an area of memory. Used to confirm TMR release.
bool VerifyAccess( uint8_t *buf, size_t len );

// Converts a string of ascii-encoded hex bytes into a Hex array
// Ex. To generate the string, do printf("%02x", myArray) will generate
//     "0123456ACF" and this function will put it back into an array
// This function is expecting the input string to be an even number of elements
//      not including the null terminator
bool StrToArray(std::string in_string, uint8_t *array, uint32_t array_size);

// If you have a buffer (or read in input file) that's in AsciiHexBytes,
// such as the getid output files, this will read it back into a buffer
void AsciiHexBytesToBinary(void *out, const char *in_bytes, size_t len);

// Reverses bytes in a section of memory. Used in validating a cert signature
bool ReverseBytes(uint8_t *bytes, size_t size);

#endif /* utilities_h */
