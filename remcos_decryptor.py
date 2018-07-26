#!/usr/bin/env python2

####################################################################################
#                                                                                  #
# Decryptor POC for Remcos RAT version 2.0.5 and earlier                           #
#                                                                                  #
# Disclaimer: This tool comes without any warranties. Use it at your own risk.     #
#                                                                                  #
# Created July 2018 by Talos                                                       #
#                                                                                  #
####################################################################################

import sys
import string 
import pefile
import magic
import getopt
from pprint import pprint

PRG=None
VERBOSE=False
DECRYPT_ONLY=False
FATAL_ERROR=10

def print_hexdata(s,d,astart):

    l=len(d)
    print("%s Length:%d(%x)" % (s,l,l))
    c=0
    sys.stdout.write("%06x  " % (c + astart))
    a=[]
    for byte in d:
        sys.stdout.write("%02x " % byte)
        a.append(byte)
        c = c + 1
        if not c % 16:
            sys.stdout.write("  ")
            for x in a:
                if x < 127 and x > 33:
                    sys.stdout.write("%c" % x)
                else:
                    sys.stdout.write(".")
            sys.stdout.write("\n%06x  " % (c + astart))
            a = []
    print("\n") 


def print_hexdata_str(d):

    l=len(d)
    for byte in d:
        if byte < 127 and byte > 33:
            sys.stdout.write("%c" % byte)
    print("\n")


def get_named_resource_from_PE(pefilename,ResourceName):

    pe = pefile.PE(pefilename)

    ResourceData = "" 
    offset = 0x0
    size = 0x0

    for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:
      for entry in rsrc.directory.entries:
	if entry.name is not None:
	  if entry.name.__str__() == ResourceName:
	     offset = entry.directory.entries[0].data.struct.OffsetToData
	     size = entry.directory.entries[0].data.struct.Size

    ResourceData = pe.get_memory_mapped_image()[offset:offset+size]

    return ResourceData


def RC4_build_S_array(key,keylen):

    S = range(256)
       
    b=0
    for counter in range(256):
        a = key[counter % keylen] + S[counter] 
        b = (a + b) % 256
     
        S[counter],S[b] = S[b],S[counter]

    return S


def RC4_stream_generator(PlainBytes,S):

    plainLen = len(PlainBytes)
    cipherList = []

    i = 0
    j = 0
    for m in range(plainLen):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        cipherList.append(k ^ PlainBytes[m])


    return cipherList


def print_out(msg,errorlevel=0):

    if not DECRYPT_ONLY: 
        print(msg)

    if errorlevel == FATAL_ERROR:
        exit(0)


def check_filetype(filename):
  
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
    IMAGE_FILE_DLL = 0x2000

    try:
        file_type = magic.from_file(filename)
        if VERBOSE:
            print_out("Filetype for %s:\n%s" % (filename,file_type))
        if "PE32 executable" in file_type:
            pe=pefile.PE(filename)
            if (pe.FILE_HEADER.Characteristics & IMAGE_FILE_DLL):
                if VERBOSE:
                    print_out("Subtype is: DLL\n")
                return("PE32 DLL")
                
            elif (pe.FILE_HEADER.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE):
                if VERBOSE:
                     print_out("Subtype is: EXE\n")
                return("PE32 EXE")
                
    except:
        print_out("ERROR: Could not open file %s" % filename, FATAL_ERROR)
        raise
    
    return None


def usage(prg):
    print
    print("Talos Decryptor POC for Remcos RAT version 2.0.5 and earlier")
    print
    print("%s -f [--file] <remcos_executable_file>           Remcos executable file" % prg)
    print("%s -e [--encypted_data] <encrypted_data_file>     Remcos executable file" % prg)
    print("%s -d [--decrypted_only]                          Show only decrypted data strings (Suppress all error msg)" % prg)
    print("%s -v [--verbose]                                 Verbose output" % prg)
    print
    print("e.g. %s -f Remcos205.exe -d" % prg)
    print
    print("Disclaimer: This tool comes without any warranties. Use it at your own risk.\n") 


# --------------------- Main -------------------------
def main(argv):

    global VERBOSE
    global DECRYPT_ONLY

    if len(sys.argv) < 3: 
        usage(sys.argv[0])
        exit(1)

    pefilename           = None
    encrypted_data_file  = None

    try:
        opts, args = getopt.getopt(argv,"hve:df:",["help","verbose","encypted_data","decrypted_only","file"])
    except getopt.GetoptError:
        print_out("\nWrong parameter. Check syntax:")
        usage(sys.argv[0])
        exit(1)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage(sys.argv[0])
            exit(0)
        elif opt in ("-v", "--verbose"):
            VERBOSE = True
        elif opt in ("-e", "--encypted_data"):
            encrypted_data_file = arg
        elif opt in ("-d", "--decrypted_only"):
            DECRYPT_ONLY = True
        elif opt in ("-f", "--file"):
            pefilename = arg

    if not DECRYPT_ONLY:
        print

    if not pefilename:
        usage();
        exit(1)

    filetype = check_filetype(pefilename)

    if filetype != "PE32 EXE":
        print_out("ERROR: File %s is not a PE executable or it is a DLL. Try -v to see what it is." % pefilename, FATAL_ERROR)

    print_out("Analysing file: %s\n" % pefilename)

    # Get data from the PE resource section
    ResourceData = get_named_resource_from_PE(pefilename,"SETTINGS")

    # Extact the key from the PE resource section data
    keylen = ord(ResourceData[0]) 
    key = map(ord, list(ResourceData[1:keylen+1]))
    if not DECRYPT_ONLY and VERBOSE:
        print_hexdata("Key:",key,0x0)

    # Do we have the encryted data in a file or should we get it from the resource section
    try:
        if encrypted_data_file != None:
            with open(encrypted_data_file, mode='rb') as file: 
                 encrypted_str = file.read()
        else:
            encrypted_str = ResourceData[keylen+1:]
    except:
        print_out("ERROR: Could not read encrypted file %s or file has wrong format\n" % encrypted_data_file,FATAL_ERROR)

    # Convert it into an list
    encrypted = map(ord, list(encrypted_str))
    if not DECRYPT_ONLY and VERBOSE:
        print_hexdata("Encrypted data:",encrypted,0x0)
    
    # Generate S
    S = RC4_build_S_array(key,keylen)

    if not DECRYPT_ONLY and VERBOSE:
        print_hexdata("Generated S array:",S,0x0)

    # Decode the encrypted data
    clear_text = RC4_stream_generator(encrypted,S)

    if DECRYPT_ONLY:
        print_hexdata_str(clear_text)
    else:
        print_hexdata("\nDecrypted data:",clear_text,0x0)
    
    exit(0)

if __name__ == "__main__":
    main(sys.argv[1:])

