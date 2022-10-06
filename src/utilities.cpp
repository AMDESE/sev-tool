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

#include "utilities.h"
#include <climits>
#include <cstring>      // memcpy
#include <fstream>
#include <cstdio>
#include <ctime>
#include <sys/random.h>
#include <array>
#include <memory>
#include <vector>

bool sev::execute_system_command(const std::string cmd, std::string *log)
{
    std::unique_ptr<FILE, decltype(&pclose)> pipe{nullptr, &pclose};
    pipe.reset(popen(cmd.c_str(), "r"));
    if (!pipe) {
        return false;
    }

    while (!feof(pipe.get())) {
        std::array<char, 4096> output;
        size_t count;
        if ((count = fread(output.data(), 1, output.size(), pipe.get())) > 0) {
            if (log) {
                log->append(output.data(), count);
            }
        }
    }

    return true;
}

/**
 * Read up to len bytes from the beginning of a file
 * Returns number of bytes read, or 0 if the file couldn't be opened.
 */
size_t sev::read_file(const std::string file_name, void *buffer, size_t len)
{
    std::ifstream file(file_name, std::ios::binary);
    if (len > INT_MAX) {
        printf("read_file Error: Input length too long\n");
        return 0;
    }
    auto slen = (std::streamsize)len;

    if (!file.is_open()) {
        printf("read_file Error: Could not open file. " \
               " ensure directory and file exists\n" \
               "  file_name: %s\n", file_name.c_str());
        return 0;
    }

    file.read(reinterpret_cast<char *>(buffer), slen);
    auto count = (size_t)file.gcount();
    file.close();

    return count;
}

/**
 * Writes len bytes from the beginning of a file. Does NOT append
 * Returns number of bytes written, or 0 if the file couldn't be opened.
 * ostream CANNOT create a folder, so it has to exist already, to succeed
 */
size_t sev::write_file(const std::string file_name, const void *buffer, size_t len)
{
    std::ofstream file(file_name, std::ofstream::out);
    if (len > INT_MAX) {
        printf("write_file Error: Input length too long\n");
        return 0;
    }
    auto slen = (std::streamsize)len;

    if (!file.is_open()) {
        printf("write_file Error: Could not open/create file. " \
               "Ensure directory exists\n" \
               "  Filename: %s\n", file_name.c_str());
        return 0;
    }
    printf("Writing to file: %s\n", file_name.c_str());

    file.write(reinterpret_cast<char const *>(buffer), slen);
    size_t count = (size_t)file.tellp();
    file.close();

    return count;
}

/**
 * Returns the file size in number of bytes
 * May be used to tell if a file exists
 */
size_t sev::get_file_size(const std::string file_name)
{
    std::ifstream file(file_name, std::ios::binary | std::ios::ate);

    if (!file.is_open()) {
        return 0;
    }

    size_t count = (size_t)file.tellg();
    file.close();

    return count;
}

void sev::gen_random_bytes(void *bytes, size_t num_bytes)
{
    ssize_t num_gen_bytes = 0;
    num_gen_bytes = getrandom(bytes, num_bytes, 0);
    if (num_gen_bytes != (ssize_t)num_bytes) {
        printf("Warning: getrandom failed. Generating random bytes manually\n");
        // Do it manually
        auto *addr = reinterpret_cast<uint8_t *>(bytes);
        srand((unsigned int)time(nullptr));
        while (num_bytes--) {
            *addr++ = (uint8_t)(rand() & 0xff);
        }
    }
}

bool sev::verify_access(uint8_t *buf, size_t len)
{
    std::vector<uint8_t> master(len);
    gen_random_bytes(master.data(), len);
    memcpy(buf, master.data(), len);
    return memcmp(buf, master.data(), len) == 0;
}

bool sev::str_to_array(const std::string in_string, uint8_t *array,
                       uint32_t array_size)
{
    std::string substring = "";

    if (array_size < in_string.size() / 2) {
        return false;
    }

    for (size_t i = 0; i < in_string.size()/2; i++) {
        substring = in_string.substr(i*2, 2);
        array[i] = (uint8_t)strtol(substring.c_str(), nullptr, 16);
    }

    // printf("\nSTRING TO ARRAY: ");
    // for (size_t i = 0; i < array_size; i++) {
    //     printf("%02x", array[i]);
    // }
    // printf("\n");

    return true;
}

std::vector<uint8_t> sev::ascii_hex_bytes_to_binary(const char *in_bytes, size_t len)
{
    std::vector<uint8_t> result{};
    result.reserve(len);
    std::string temp;

    for (size_t i = 0; i < len; i++) {
        temp = {in_bytes[i*2], in_bytes[(i*2)+1], '\0'};
        result.push_back((uint8_t)stoi(temp, nullptr, 16));
    }
    return result;
}

bool sev::reverse_bytes(uint8_t *bytes, size_t size)
{
    uint8_t *start = bytes;
    uint8_t *end = bytes + size - 1;

    if (!bytes)
        return false;

    while (start < end) {
        uint8_t byte = *start;
        *start = *end;
        *end = byte;
        start++;
        end--;
    }

    return true;
}

bool sev::is_zero(const uint8_t *ptr, size_t bytes)
{
    uint8_t val = 0;
    for (size_t i = 0; i < bytes; i++) {
        val |= ptr[i];
    }
    return (val == 0);
}
