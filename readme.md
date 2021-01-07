# How to Download and Run SEV-Tool
&nbsp;
Version: v16
Updated: 2019-10-03
&nbsp;
&nbsp;

## Related Docs
- The SEV API can be found here: https://developer.amd.com/sev/

## OS Requirements
  - Your Kernel must support SEV.
  - SME/SEV OS Support
     ```
                          SEV Guest      SEV Host
                             (VM)       (Hypervisor)
     Linux® 4.15              Y
     Linux® 4.16              Y              Y
     RHEL 7.6                 Y
     RHEL 8                   Y              Y     
     Fedora 28                Y              Y
     SLES 15                  Y              Y
     Ubuntu 18.04             Y
     Ubuntu 10.10, 19.04      Y              Y
     Oracle Linux UEK 5       Y              Y
     VMWare    - Support in Upcoming version of vSphere
     OpenStack - Support Upstream    
     ```
  - If running Linux, the ccp Kernel driver must be running and supported, as that is how the SEV-Tool communicates to the firmware. To tell if your Kernel supports SEV and the ccp driver is working correctly, run a dmesg and look for the following line:
     ```sh
     $ ccp [xxxx:xx:xx.x]: SEV API:x.xx build:x
     ```
     For example, in Ubuntu 18.10, Kernel 4.18.0-15-generic, you will see something similar to
     ```sh
     $ ccp [0000:01:00.2]: SEV API:0.17 build:5
     ```
    This means that the ccp driver was able to run the Init command against the SEV firmware.
    Note: You might also see a dmesg line noting that "Direct firmware load for amd/sev.fw failed with error -2". This just means that the firmware file is not there for the ccp driver to run the Download_Firmware command on startup, and you will be running with the SEV firmware that is provided in the BIOS. This is totally normal.
  - Note if running Linux, it is recommended that your OS come with a Kernel that supports SEV by default (Ubuntu 18.10 or later, etc) to have the latest Kernel headers and libc. If you start with an older Kernel and use a Kernel upgrade utility (ex: ukuu in Ubuntu) to update the Kernel manually, this will give you the newest Kernel headers, but you will have an old version of libc, which processed the older Kernel headers, not the new ones. It’s (probably) possible to update libc and have it process the new Kernel Headers, but it’s a lot of work.
#### User Space Requirements
  - OpenSSL 1.1.0 or newer is required to compile the SEV-Tool.
  - Ubuntu 16.04's user space only officially supports OpenSSL 1.0.x. It is possible to manually download and install the OpenSSL libraries to work around this issue. Go to the following links to download the packages and run the following command to install them.
    - https://packages.ubuntu.com/bionic-updates/amd64/libssl-dev/download
    - https://packages.ubuntu.com/bionic-updates/amd64/libssl1.1/download
    - sudo dpkg -i [DEB_PACKAGE]
    - __OR__ you may run the `deps-install.sh` script to meet this requirement (see below).
  - Ubuntu 18.04 might not come with OpenSSL 1.1.x pre-installed, so it will need to updated through apt-get

## Downloading the SEV-Tool
1. Boot into a Kernel that supports SEV (see above to confirm your Kernel supports SEV)
2. Install git, make, gcc, g++, and openssl dependencies
   - In most cases, you can run `deps-install.sh`.
     ```sh
     $ sh deps-install.sh
     ```
   - If you would like to manually install dependencies, and are running Debian, Ubuntu
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
     $ autoreconf -vif && ./configure && make
     ```

## How to Run the SEV-Tool
1. Pull latest changes from Git for any new added/modified tests
     ```sh
     $ cd sev-tool
     $ git pull
     $ autoreconf -vif && ./configure && make
     ```
2. Run the tool with the help flag (-h or --help):
     ```sh
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
* The --sys_info flag will display the system information to the user such as: BIOS version, BIOS release date, SMT status, processor frequency, OS, Kernel version, Git commit number of the SEV-Tool, etc
     ```sh
     $ sudo ./sevtool --sys_info --get_id
     ```
* The --verbose and --brief flags will turn on/off displaying the out certs/IDs/etc to the screen on commands such as pek_csr, pdh_cert_export, get_id, etc
     ```sh
     $ sudo ./sevtool --verbose --sys_info --get_id
     $ sudo ./sevtool --brief --pek_csr
     ```
* Certain commands support the --ofolder flag which will allow the user to select the output folder for the certs exported by the command. See specific command for details

## Proposed Provisioning Steps
##### Platform Owner
1. Generate your OCA. Please see the API spec for key/certificate specifications.
     ```sh
     $ openssl ecparam -genkey -name secp384r1 -noout -out ec384-key-pair.pem
     $ openssl ec -in ec384-key-pair.pem -pubout -out ec384pub.pem
     ```
2. Get Platform and connect to Internet
3. Install SEV-supported operating system
4. Confirm that SEV is supported (using steps in [OS Requirements](#os-requirements))
5. Make a folder for the SEV-Tool to import/export certs/IDs from/to (pass into commands with the --ofolder flag)
6. Run the get_id command. As a simple check if running when 2 processors, make sure the returned IDs are different by using the --verbose flag
7. Get the CEK_ASK from the AMD KDS server by running the generate_cek_ask command
   - Note: the CEK certificate will be different every time you pull it from the KDS sever. The server re-generates/re-signs the cert every time instead of storing a static cert
8. Run the pek_csr command to generate a certificate signing request for your PEK. This will allow you to take ownership of the platform.
9. Sign PEK with OCA (example using openssl coming soon)
10. Run the pek_cert_import command
11. Run the pdh_cert_export command
12. Run the get_ask_ark command
13. Run the export_cert_chain command to export the PDH down to the ARK (AMD root) and zip it up
14. Save the complete cert chain to send to the Guest Owners (GO's)
15. Make available UEFI image for guests

##### Guest Owner
1. Make a folder for the SEV-Tool to import/export certs/IDs from/to (pass into commands with the --ofolder flag)
2. Get UEFI image from the Platform Owner
3. (Out of scope) Confirm the UEFI image is trustable.
4. Get cert chain (PDH through ARK) from the Platform Owner (PO) and unzip them into a local folder
5. Run the validate_cert_chain command to verify the cert chain from the PDH down to the ARK (AMD root)
   - TODO. Wouldn't we want the GO to download the ASK_ARK, otherwise, the PO can make up the entire chain and we'd validate it and it'd pass?
6. (Out of scope) Verify OCA cert chain from the Platform Owner
7. Run the generate_launch_blob command
   - Reads in Platform Diffie-Hellman key (PDH cert from Platform) and generates new public/private Guest Owner Diffie-Hellman keypair. The DH key exchange is completed when the PO calls Launch_Start using the GODH public key.
8. Send the blob and the Guest Owner's DH public key to the Platform Owner so it can launch your Guests
9. Get the measurement from the Platform Owner
10. Run the calc_measurement command and verify the measurement from the Platform owner matches what you calculated/expected
    - The UEFI image is the digest param that we hash, so we  know the Platform Owner isn't modifying that
11. Run the package_secret command
12. Send the secret(s) to the Platform Owner
13. Give "ready to run" approval to the Platform Owner

##### Hypervisor
This is the flow that the Hypervisor will take to prepare the guest
1. After receiving the launch blob and the GO Diffie-Hellman public key from the Guest Owner, the Hypervisor can launch (call Launch_Start on) the guest
2. Call Launch_Update_Data and Activate, etc
3. Call Launch_Measure and send the measurement received from the PSP to the Guest Owner so it can verify against its expected result
4. Call Launch_Finish, etc
5. After receiving the packaged secrets from the Guest Owner (this step is optional), call Launch_Secret to pass the Guest Owner's secrets into the guest
6. The Guest Owner should now give the Hypervisor approval to run its Guest

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
This command imports an OCA private key from the user, runs a platform_status command to get the API major/minor used to create the certificate, runs the pek_csr to create the PEK certificate signing request, signs the PEK signing request with the OCA private key, and calls pek_cert_import to import the PEK and OCA certificates.
     - Required input args: The unencrypted OCA Private key file (.pem).
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --pek_cert_import [oca_priv_key_file]
         $ sudo ./sevtool --pek_cert_import ../psp-sev-assets/oca_key_in.pem
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
9. set_self_owned
     - Input args: none
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --set_self_owned
         ```
10. set_externally_owned
     - Required input args: This function, among other things, calls pek_cert_import, so the OCA Private key file (.pem) is a required argument.
     - Outputs: none
     - Example
         ```sh
         $ sudo ./sevtool --set_externally_owned [oca_priv_key_file]
         $ sudo ./sevtool --set_externally_owned ../psp-sev-assets/oca_key_in.pem
         ```
11. generate_cek_ask
This command calls the get_id command and passes that ID into the AMD KDS server to retrieve the cek_ask. If the command returns an error while connecting to the KDS server, please try the command again.
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the cek_ark.cert to
     - Outputs:
        - If --[ofolder] flag used: The cek_ask.cert file for your specific platform (processor in socket0) will be exported to the folder specified. Otherwise, it will be exported to the same directory as the SEV-Tool executable. File: cek_ask.cert
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --generate_cek_ask
         ```
12. get_ask_ark
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the ask_ark certificate to
     - Outputs:
        - If --[ofolder] flag used: The ark_ark certificate will be exported to the folder specified. Otherwise, it will be exported to the same directory as the SEV-Tool executable. File: ask_ark.cert
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --get_ask_ark
         ```
13. export_cert_chain
     - This command exports all of the certs (PDH, PEK, OCA, CEK, ASK, ARK) and zips them up so that the Platform Owner can send them to the Guest Owner to allow the Guest Owner to validate the cert chain. The tool gets the CEK from the AMD KDS server and gets the ASK_ARK certificate from the SEV Developer website.
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export all of the certificates to and the zip folder in
     - Outputs:
        - If --[ofolder] flag used: The certificates will be exported to and zipped up in the folder specified. Otherwise, they will be exported to and zipped up in the same directory as the SEV-Tool executable. Files: pdh.cert, pek.cert, oca.cert, cek.cert, ask.cert, ark.cert, certs_export.zip
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --export_cert_chain
         ```
14. calc_measurement
     - The purpose of the calc_measurement command is for the user to be able to validate that they are calculating the HMAC/measurement correctly when they would be calling Launch_Measure during the normal API flow. The user can input all of the parameters used to calculate the HMAC and an output will be generated that the user can compare to their calculated measurement.
     - The digest parameter is the SHA256 (Naples) or SHA384 (Rome) output digest of the data passed into LaunchUpdateData and LaunchUpdateVMSA
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
         $ sudo ./sevtool --ofolder ./certs --calc_measurement 04 00 12 0f 00 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 4fbe0bedbad6c86ae8f68971d103e554 66320db73158a35a255d051758e95ed4
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
15. validate_cert_chain
     - This function imports the entire cert chain as separate cert files and validates it.
     - When calling this command, please unzip the certs into the folder you expect the tool to use.
     - The steps are as follows:
        - Imports the PDH, PEK, OCA, CEK, ASK, and ARK certs
        - Validates the ARK using the ARK (self-signed)
        - Validates the ASK using the ARK
        - Validates the CEK using the ASK
        - Validates the PEK using the CEK and the OCA
        - Validates the PDH using the PEK
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will import the certs from, otherwise it will use the same folder as the SEV-Tool executable
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --validate_cert_chain
         ```
16. generate_launch_blob
     - This function imports the PDH certificate from the Platform and builds the Launch_Start session buffer (blob) and the Guest Owner Diffie-Hellman public key certificate. As part of the session buffer, a new public/private Diffie-Hellman keypair for the Guest Owner is generated, which is then used with the Platform's public DH key to calculate a shared secret, and then a master secret, which then is then used generate a new TEK and TIK. The session buffer (launch blob) and Guest Owner DH public key cert will be used as inputs to LaunchStart.
     - Required input args: Guest policy in hex format
     - Optional input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will export the blob file to
     - Outputs:
        - If --[ofolder] flag used: The blob file and Guest Owner DH public key certificate will be exported to the folder specified. The Guest Owner DH public and private keys are also exported during the process and are only to be used by the SEV-Tool. Otherwise, all files will be exported to the same directory as the SEV-Tool executable. Files: launch_blob.txt, godh.cert, (ignore these: godh_pubkey.pem, godh_privkey.pem). Note that the output blob file is a binary file; to import to qemu, the file needs to be manually converted to base64.
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --generate_launch_blob 39
         ```
17. package_secret
     - This command reads in the file generated by generate_launch_blob (launch_blob.txt) to get the TEK and also reads in the secret file (secret.txt) to be encrypted/wrapped by the TEK. It then outputs a file (packaged_secret.txt) which is then passed into Launch_Secret as part of the normal API flow
     - Required input args: --ofolder [folder_path]
         - This allows the user to specify the folder where the tool will look for the launch blob file and the secrets file, and where it will export the packaged secret file to
     - Outputs:
        - If --[ofolder] flag used: The blob file will be exported to the folder specified. Otherwise, it will be exported to the same directory as the SEV-Tool executable. File: packaged_secret.txt
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./certs --package_secret
         ```

## Running tests
To run tests to check that each command is functioning correctly, run the test_all command and check that the entire thing returns success.
1. test_all
     - Required input args: --ofolder [folder_path]
         - Make a directly that the tests can use to store certs/data in during the test. Note that the tool will clear this directly before the tests are run.
     - Example
         ```sh
         $ sudo ./sevtool --ofolder ./tests --test_all
         ```
## Issues, Feature Requests
   - For any issues with the tool itself, please create a ticket at https://github.com/AMDESE/sev-tool/issues
   - For any questions/concerns with the SEV API spec, please create a ticket at https://github.com/AMDESE/AMDSEV/issues
