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

#include "utilities.h"
#include <climits>
#include <fstream>
#include <stdio.h>
#include <cstring>      // memcpy

bool ExecuteSystemCommand(const std::string cmd, std::string *log)
{
    FILE *pipe = popen(cmd.c_str(), "r");
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
    if (len > INT_MAX) {
        printf("ReadFile Error: Input length too long\n");
        return 0;
    }
    std::streamsize slen = (std::streamsize)len;

    if (!file.is_open()) {
        printf("Readfile Error: Could not open file. Ensure directory exists\n" \
                    "  Filename: %s\n", filename.c_str());
        return 0;
    }

    file.read((char *)buffer, slen);
    size_t count = (size_t)file.gcount();
    file.close();

    return count;
}

// Writes len bytes from the beginning of a file. Does NOT append
// Returns number of bytes written, or 0 if the file couldn't be opened.
// ostream CANNOT create a folder, so it has to exist already, to succeed
size_t WriteFile(const std::string& filename, const void *buffer, size_t len)
{
    std::ofstream file(filename, std::ofstream::out);
    if (len > INT_MAX) {
        printf("WriteFile Error: Input length too long\n");
        return 0;
    }
    std::streamsize slen = (std::streamsize)len;

    if (!file.is_open()) {
        printf("WriteFile Error: Could not open/create file. Ensure directory exists\n" \
                    "  Filename: %s\n", filename.c_str());
        return 0;
    }
    printf("Writing to file: %s\n", filename.c_str());

    file.write((char *)buffer, slen);
    size_t count = (size_t)file.tellp();
    file.close();

    return count;
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

bool StrToArray(std::string in_string, uint8_t *array, uint32_t array_size)
{
    std::string substring = "";

    if(array_size < in_string.size() / 2) {
        return false;
    }

    for(size_t i = 0; i < in_string.size()/2; i++) {
        substring = in_string.substr(i*2, 2);
        array[i] = (uint8_t)strtol(substring.c_str(), NULL, 16);
    }

    // printf("\nSTRING TO ARRAY: ");
    // for(size_t i = 0; i < array_size; i++) {
    //     printf("%02x", array[i]);
    // }
    // printf("\n");

    return true;
}

void AsciiHexBytesToBinary(void *out, const char *in_bytes, size_t len)
{
    std::string temp;

    for(size_t i = 0; i < len; i++)
    {
        temp = {in_bytes[i*2], in_bytes[(i*2)+1], '\0'};
        ((uint8_t *)out)[i] = (uint8_t)stoi(temp, NULL, 16);
    }

}

bool reverse_bytes(uint8_t *bytes, size_t size)
{
	uint8_t *start = bytes;
	uint8_t *end = bytes + size - 1;

	if (!bytes)
        return false;

	while (start < end)
	{
		uint8_t byte = *start;
		*start = *end;
		*end = byte;
		start++;
		end--;
	}

	return true;
}