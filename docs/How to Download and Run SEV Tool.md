# How to Download and Run SEV Tool
&nbsp;
Version: v4
Updated: 2019-01-15
&nbsp;
&nbsp;
&nbsp;

## OS Requirements

  - When using Ubuntu, you must have Ubuntu 18.10 or later to have the latest kernel headers and libc. If you try to use an older kernel and use ukuu to update the kernel manually, this will give you the newest kernel headers, but you will have an old version of libc, which processed the older kernel headers, not the original ones. It’s (probably) possible to update libc and have it process the new kernel headers, but it’s a lot of work.

## Downloading the SEV Tool
These instructions assume you are running a normal Linux kernel. The SEV Tool has only been officially tested on Ubuntu 18.10
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
- The tool will provide you with instructions on input parameters, etc
- Note that the -h flag can also be used to view the help menu to see a list of the available commands
     ```sh
     $ sudo ./sevtool -h
     ```

## Running calc_measurement
   - The purpose of the calc_measurement command is for the user to be able to validate that they are calculating the HMAC/measurement correctly when they would be calling Launch_Measure during the normal API flow. The user can input all of the parameters used to calculate the HMAC and an output will be generated that the user can compare to their calculated measurement.
   - The format of the input parameters of the calc_measurement command can be difficult to understand. To better understand them, an example of how to run this command can be seen below. The user will need to input all 10 parameters as ascii-encoded hex bytes. 
     ```sh
     $ sudo ./sevtool calc_measurement 04 00 12 0f 00 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 4fbe0bedbad6c86ae8f68971d103e554 66320db73158a35a255d051758e95ed4
     ```
   - The output from the tool can be found below
     ```sh
     You have entered 10 arguments
     Command: calc_measurement
     Input Arguments:
       Context: 04
       Api Major: 00
       Api Minor: 12
       Build ID: 0f
       Policy: 00
       Digest: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
       MNonce: 4fbe0bedbad6c86ae8f68971d103e554
       TIK: 66320db73158a35a255d051758e95ed4
    
     Output Measurement:
     6faab2daae389bcd3405a05d6cafe33c0414f7bedd0bae19ba5f38b7fd1664ea
     
     Command Successful
     ```
   - Note that, for security reasons, the TIK will not be shown when the user runs the tool

## Debugging the SEV Tool
   - kdbg makes it very easy to step through, add breakpoints to, and debug the test suite
     ```sh
     $ sudo apt-get install kdbg
     ```
- Note: kdbg seems to have some issues with Ubuntu 18.04/18.10, but works fine on Ubuntu 16.04
