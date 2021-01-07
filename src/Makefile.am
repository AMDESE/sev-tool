# The name of the resulting application after it is build.
bin_PROGRAMS = sevtool

sevtool_SOURCES = amdcert.cpp commands.cpp crypto.cpp\
				  main.cpp sevcert.cpp\
				  utilities.cpp tests.cpp
if LINUX
sevtool_SOURCES += sevcore_linux.cpp
else
sevtool_SOURCES += sevcore_win.cpp
endif

# linked libraries
sevtool_LDADD = -lcrypto -lssl -lvirt -lvirt-qemu -luuid

# Compilation flags
sevtool_CXXFLAGS = -g -Wall -Wextra -Wconversion -pthread -std=c++11 -I../lib
