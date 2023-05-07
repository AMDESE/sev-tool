cmake_minimum_required(VERSION 3.23)

project(networking CXX)

find_package(OpenSSL REQUIRED COMPONENTS SSL)

set(CMAKE_CXX_STANDARD 20)

add_executable(sev-tool
    src/amdcert.cpp
    src/commands.cpp
    src/crypto.cpp
    src/main.cpp
    src/sevcert.cpp
    src/utilities.cpp
    src/tests.cpp
    src/x509cert.cpp
    src/sevcore_linux.cpp
    src/sevcore_win.cpp
)
target_include_directories(sev-tool PRIVATE ${CMAKE_SOURCE_DIR}/lib)

target_link_libraries(sev-tool OpenSSL::SSL)
