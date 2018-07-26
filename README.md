# Talos Decryptor POC for Remcos RAT version 2.0.5 and earlier #

./remcos_decryptor.py -f <remcos_executable_file> [-e <encrypted_data_file>] [-d] [-v]

-f [--file] <remcos_executable_file>           Remcos executable file
-e [--encypted_data] <encrypted_data_file>     Remcos executable file
-d [--decrypted_only]                          Show only decrypted data strings
                                               (-d is suppressing all error msg!)
-v [--verbose]                                 Verbose output

e.g. ./remcos_decryptor.py -f Remcos205.exe -d

Disclaimer: This tool comes without any warranties. Use it at your own risk.


