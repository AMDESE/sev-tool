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

// Generate some random bytes
void GenRandomBytes( void *bytes, size_t numBytes );

// Verify read/write access to an area of memory. Used to confirm TMR release.
bool VerifyAccess( uint8_t *buf, size_t len );


#endif /* utilities_h */
