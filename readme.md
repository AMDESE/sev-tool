# How to Download and Run SEV-Tool
&nbsp;
Version: v6
Updated: 2019-02-20
&nbsp;
&nbsp;
&nbsp;

## Related Docs
- The SEV API can be found here: https://developer.amd.com/sev/

## OS Requirements
  - Your Kernel must support SEV. 
  - If running Linux, the ccp Kernel driver must be running and supported, as that is how the SEV-Tool communicates to the firmware. To tell if your Kernel supports SEV and the ccp driver is working correctly, run a dmesg and look for the following line
     ```sh
      $ ccp [xxxx:xx:xx.x]: SEV API:x.xx build:x
     ```
     For example, in Ubuntu 18.10, Kernel 4.18.0-15-generic, you will see something similar to
     ```sh
      $ ccp [0000:01:00.2]: SEV API:0.17 build:5
     ```
    Note: You might also see a dmesg line noting that "Direct firmware load for amd/sev.fw failed with error -2". This just means that the firmware file is not there, and you will be running with the SEV firmware that is provided in the BIOS. This is totally normal.
  - Note if running Linux, it is recommended that your OS come with a Kernel that supports SEV by default (Ubuntu 18.10 or later, etc) to have the latest Kernel headers and libc. If you start with an older Kernel and use a Kernel upgrade utility (ex: ukuu in Ubuntu) to update the Kernel manually, this will give you the newest Kernel headers, but you will have an old version of libc, which processed the older Kernel headers, not the new ones. It’s (probably) possible to update libc and have it process the new Kernel Keaders, but it’s a lot of work.

## Downloading the SEV-Tool
1. Boot into a Kernel that supports SEV (see above to confirm your Kernel supports SEV)
2. Install git, make, gcc, g++ and dependencies
   - If running Debian, Ubuntu
     ```sh
      $ sudo apt install git make gcc g++ -y --allow-unauthenticated
     ```
    - Otherwise, use the method that is supported by your OS
2. The Github is located at: [SEV-Tool Github](https://github.com/AMDESE/SEV-Tool). Do a git clone with SSH
     ```sh
     $ git clone git@github.com:AMDESE/sev-tool.git
     ```
3. Compile the SEV-Tool. 
   - Running the build script does the following things:
      - Downloads, configs, and builds the OpenSSL Git code (submodule init/update)
      - Cleans and builds the SEV-Tool
   - To run the build script
     ```sh
     $ cd sev-tool
     $ sh ./build.sh
     ```

## How to Run the SEV-Tool
1. Pull latest changes from Git for any new added/modified tests
     ```sh
     $ cd sev-tool
     $ git pull
     $ sh ./build.sh
     ```
2.	Run the tool with the help flag (-h or --help):
     ```sh
     $ cd src
     $ sudo ./sevtool -h
     ```
- The help menu (and also the documentation below) will provide you with instructions on input parameters, etc

## Input flag format
- The input flag format for every command is as follows and will be explained further in the coming sections
     ```sh
     $ sudo ./sevtool [optional_input_flags] [command_flag] [required_command_arguments]
     ``` 

## Optional Input Flags for Every Command
* The -h or --help flag will display the help menu to the user
     ```sh
     $ sudo ./sevtool -h
     ```
* The --sysinfo flag will display the system information to the user such as: BIOS version, BIOS release date, SMT status, processor frequency, OS, Kernel version, Git commit number of the SEV-Tool, etc
     ```sh
     $ sudo ./sevtool --sysinfo --get_id
     ```
* The --verbose and --brief flags will turn on/off displaying the out certs/IDs/etc to the screen on commands such as pek_csr, pdh_cert_export, get_id, etc
     ```sh
     $ sudo ./sevtool --verbose --sysinfo --get_id
     $ sudo ./sevtool --brief --pek_csr
     ```
* Certain commands support the --ofolder flag which will allow the user to select the output folder for the certs exported by the command. See specific command for details

## Command List
The following commands are supposed be the SEV-Tool. Please see the SEV-API for info on each specific command
Note: All input and output cert's mentioned below are SEV (special format) Certs. See SEV API for details
1. factory_reset
     - Input args: none
     - Outputs: none
     - Note: in the current SEV API, this command was renamed to PLATFORM_RESET 
     - Example
         ```sh
         $ sudo ./sevtool --factory_reset
         ```
2. platform_status
     - Input args: none
     - Outputs: The current platform status will be printed to the screen
     - Example
         ```sh
         $ sudo ./sevtool --platform_status
         ```
3. pek_gen
     - Input args: none
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --pek_gen
         ```
4. pek_csr
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the certificate signing request
     - Outputs: 
         - If --[verbose] flag used: The pek_csr will be printed out to the screen as a hex dump and as a readable format 
         - If --[ofolder] flag used: The pek_csr will be written as files to the specified folder as a hex dump and as a readable format. Files: pek_csr_out.cert and pek_csr_out_readable.cert
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --pek_csr
         ```
5. pdh_gen
     - Input args: none
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --pdh_gen
         ```
6. pdh_cert_export
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the PDH cert and the Cert Chain (PEK, OCA, CEK)
     - Outputs:
         - If --[verbose] flag used: The PDH cert and Cert Chain will be printed out to the screen as hex dumps and as readable formats
         - If --[ofolder] flag used: The PDH cert and Cert Chain will be written as files to the specified folder as hex dumps and as readable formats. Files: pdh_out.cert, pdh_readable_out.cert, cert_chain_out.cert, cert_chain_readable_out.cert
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --pdh_cert_export
         ```
7. pek_cert_import
     - Required input args: The OCA Private key file (.pem) and OCA cert file (.cert) are required arguments.
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --pek_cert_import [oca_priv_key_file] [oca_cert_file]
         $ sudo ./sevtool --pek_cert_import ../psp-sev-assets/oca_key_in.pem ../psp-sev-assets/oca_in.cert
         ```
8. get_id
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the IDs for Socket0 and Socket1
     - Outputs:
         - If --[verbose] flag used: The IDs for Socket0 and Socket1 will be printed out to the screen
         - If --[ofolder] flag used: The IDs for Socket0 and Socket1 will be written as files to the specified folder. Files: getid_s0_out.txt and getid_s1_out.txt
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --get_id
         ```
9. calc_measurement
     - The purpose of the calc_measurement command is for the user to be able to validate that they are calculating the HMAC/measurement correctly when they would be calling Launch_Measure during the normal API flow. The user can input all of the parameters used to calculate the HMAC and an output will be generated that the user can compare to their calculated measurement.
     - Required input args: [Context] [Api Major] [Api Minor] [Build ID] [Policy] [Digest] [MNonce] [TIK]
         - The format of the input parameters are ascii-encoded hex bytes.
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the calculated measurement
     - Outputs:
         - If --[verbose] flag used: The input data and calculated measurement will be printed out to the screen
         - If --[ofolder] flag used: The calculated measurement will be written to the specified folder. File: calc_measurement_out.txt
     - Example
         ```sh
         $ sudo ./sevtool --calc_measurement [Context] [Api Major] [Api Minor] [Build ID] [Policy] [Digest] [MNonce] [TIK]
         $ sudo ./sevtool --folder ./certs --calc_measurement 04 00 12 0f 00 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 4fbe0bedbad6c86ae8f68971d103e554 66320db73158a35a255d051758e95ed4
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
10. set_self_owned
     - Input args: none
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --set_self_owned
         ```
11. set_externally_owned
     - Required input args: This function, among other things, calls pek_cert_import, so the OCA Private key file (.pem) and OCA cert file (.cert) are required arguments.
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --set_externally_owned [oca_priv_key_file] [oca_cert_file]
         $ sudo ./sevtool --set_externally_owned ../psp-sev-assets/oca_key_in.pem ../psp-sev-assets/oca_in.cert
         ```
12. generate_cek_ask
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the cek_ark.cert to
     - Outputs:
        - If --[ofolder] flag used: The cek_ask.cert file for your specific platform (processor in socket0) will be exported to the folder specified. Otherwise, it will be exported to the same directory as the SEV-Tool executable. File: cek_ask.cert
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --generate_cek_ask
         ```
13. get_ask_ark
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the ask_ark certificate to
     - Outputs:
        - If --[ofolder] flag used: The ark_ark certificate will be exported to the folder specified. Otherwise, it will be exported to the same directory as the SEV-Tool executable. File: ask_ark.cert
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --get_ask_ark
         ```
14. validate_cert_chain
     - This function validates the entire cert chain, from the PDH to the ARK. The steps are as follows:
        - Call pdh_cert_export to get the PDH and the Cert Chain (PEK, OCA, CEK)
        - Call get_ask_ark to download the ask_ark.cert
        - Call generate_cek_ask to generate the cek_ask.cert
        - Replace the CEK in the Cert Chain with the cek_ask.cert. In the cek_ask.cert, the CEK is signed by the ask (hence the file name), in the Cert Chain, the CEK is not signed by the ASK
        - Validates the ARK
        - Validates the ASK using the ARK
        - Validates the CEK using the ASK
        - Validates the PEK using the CEK (from cek_ask.cert) and the OCA
        - Validates the PEK using the PEK
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the ask_ark and cek_ask certificates to
     - Outputs: None (see below)
        - As a byproduct of running this command, the ask_ark and cek_ask certificates are produced and exported to either the same directory as the SEV-Tool executable, or if --[ofolder] flag is used, the folder specified.
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --validate_cert_chain
         ```

## Issues, Feature Requests
   - For any issues with the tool itself, please create a ticket at https://github.com/AMDESE/sev-tool/issues
   - For any questions/converns with the SEV API spec, please create a ticket at https://github.com/AMDESE/AMDSEV/issues
