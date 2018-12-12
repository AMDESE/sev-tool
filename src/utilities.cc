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

#include "sevapi.h"
#include "utilities.h"
#include <climits>
#include <fstream>
#include <stdio.h>
#include <cstring>      // memcpy

bool ExecuteSystemCommand(const std::string cmd, std::string *log)
{
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        return false;
    }

    while (!feof(pipe)) {
        char output[4096];
        size_t count;
        if ((count = fread(output, 1, sizeof(output), pipe)) > 0) {
            if (log) {
                log->append(output, count);
            }
        }
    }

    pclose(pipe);

    return true;
}

// Read up to len bytes from the beginning of a file
// Returns number of bytes read, or 0 if the file couldn't be opened.
size_t ReadFile(const std::string& filename, void *buffer, size_t len)
{
    std::ifstream file(filename, std::ios::binary);
    if (len > INT_MAX)
        return 0;
    std::streamsize slen = (std::streamsize)len;

    if (!file.is_open())
        return 0;

    file.read((char *)buffer, slen);
    return (size_t)file.gcount();
}

void GenRandomBytes( void *bytes, size_t numBytes )
{
    uint8_t *addr = (uint8_t *)bytes;
    while (numBytes--) {
        *addr++ = (uint8_t)(rand() & 0xff);
    }
}

bool VerifyAccess( uint8_t *buf, size_t len )
{
    uint8_t *master = new uint8_t[len];
    GenRandomBytes(master, len);
    memcpy(buf, master, len);
    bool ret = memcmp(buf, master, len) == 0;
    delete[] master;
    return ret;
}
