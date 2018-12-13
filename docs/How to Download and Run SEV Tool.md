# How to Download and Run SEV Tool
&nbsp;
Version: v3
Updated: 2018-11-26
&nbsp;
&nbsp;
&nbsp;

## OS Requirements

  - When using Ubuntu, you must have Ubuntu 18.10 or later to have the latest kernel headers and libc. If you try to use an older kernel and use ukuu to update the kernel manually, this will give you the newest kernel headers, but you will have an old version of libc, which processed the older kernel headers, not the original ones. It’s (probably) possible to update libc and have it process the new kernel headers, but it’s a lot of work.

## Downloading the SEV Tool
These instructions assume you are running a normal Linux kernel. The SEV Tool has only been officially tested on 18.10
1. Installation Steps
   - Boot into a kernel that supports SEV (>= Ubuntu 18.10, etc)
   - Install git, make, gcc, g++ and dependencies
     ```sh
      $ sudo apt install git make gcc g++ -y --allow-unauthenticated
     ```
2. The Github is located at: [SEV-Tool Github](https://github.com/AMDESE/sev-tool). Do a git clone with SSH
     ```sh
     $ git clone git@github.com:AMDESE/sev-tool.git
     ```
3. Compile the driver
This needs to be done for each kernel you want to test with. Running the build script does the following things:
   - Downloads, configs, and builds the OpenSSL Git code (submodule init/update)
   - Cleans and builds the SEV Tool
     ```sh
     $ cd sev-tool
     $ sh ./build.sh
     ```
## Run the SEV-Tool
1. Pull latest changes from Git for any new added/modified tests
     ```sh
     $ cd sev-tool
     $ git pull
     $ sh ./build.sh
     ```
2.	Run tool:
     ```sh
     $ cd src
     $ sudo ./sevtool
     ```
The tool will provide you with instructions on input parameters, etc

## Debugging the SEV Tool
   - kdbg makes it very easy to step through, add breakpoints to, and debug the test suite
     ```sh
     $ sudo apt-get install kdbg
     ```
- Note: kdbg seems to have some issues with Ubuntu 18.04/18.10, but works fine on Ubuntu 16.04
