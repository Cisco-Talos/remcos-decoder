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
import array
import re
import string
from pprint import pprint


PRG=None
VERBOSE=False
DECRYPT_ONLY=False
C2_ONLY=False
FATAL_ERROR=10

def print_hexdata(s,d,astart):

    l=len(d)
    print("%s Length:%d(0x%x)" % (s,l,l))
    c=0
    sys.stdout.write("%06x  " % (c + astart))
    a=[]
    for c,byte in enumerate(d,1):
        sys.stdout.write("%02x " % byte)
        a.append(byte)
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

    a = array.array('b')
    a.extend(d)
    print a.tostring()
    print


def get_C2(d):

    a = array.array('b')    
    a.extend(d)
    d_str = a.tostring()

    fields=d_str.split("|")
    C2=[]
    for field in fields:
            if bool(re.search('.*:.*(:.*)*', field)):
                    C2.append(field)

    return(C2)


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


def check_version(remcos_binary_name):

    printable = set(string.printable)

    with open(remcos_binary_name, 'rb') as myfile:
        fcontent=myfile.read()

    s=""
    slist=[]
    # find strings in binary file
    for c in fcontent:
        if len(s) > 4 and ord(c) == 0: # no strings <= 4
            slist.append(s)
	    s=""
	    continue

	if c in printable:
	    s += c

    version_found = False
    # find and extract version string e.g. "2.0.5 Pro" or "1.7 Free"
    for s in slist:
        if bool(re.search('^[12]\.\d+\d{0,1}.*[FP].*', s)):
            print_out("%s is version %s\n" % (remcos_binary_name,s))
	    version_found = True
	    break

    if not version_found:
        print_out("ERROR: %s no version found\n" % remcos_binary_name, FATAL_ERROR)


def usage(prg):
    print
    print("################################################################")
    print("# Talos Decryptor POC for Remcos RAT version 2.0.5 and earlier #")
    print("################################################################")
    print
    print("%s -f <remcos_executable_file> [-e <encrypted_data_file>] [-d] [-v] [-c] [-r]" % prg)
    print
    print("-f [--file] <remcos_executable_file>           Remcos executable file")
    print("-e [--encypted_data] <encrypted_data_file>     Encrypted data file (optional)")
    print("-d [--decrypted_only]                          Show only decrypted data strings (optional)") 
    print("                                               (-d is suppressing all error msg!)")
    print("-c [--c2_only]                                 Show only extracted C2 data (optional)")
    print("-v [--verbose]                                 Verbose output (optional)")
    print("-r [--remcos_version]                          Print Remcos version info")
    print
    print("e.g. %s -f Remcos205.exe -d" % prg)
    print
    print("Disclaimer: This tool comes without any warranties. Use it at your own risk.\n") 


# --------------------- Main -------------------------
def main(argv):

    global VERBOSE
    global DECRYPT_ONLY
    global C2_ONLY

    REMCOS_VERSION_CHECK = False

    if len(sys.argv) < 3: 
        usage(sys.argv[0])
        exit(1)

    pefilename           = None
    encrypted_data_file  = None

    try:
        opts, args = getopt.getopt(argv,"hve:df:cr",["help","verbose","encypted_data","decrypted_only","file","c2_only","remcos_version"])
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
        elif opt in ("-c", "--c2_only"):
            C2_ONLY      = True
            DECRYPT_ONLY = True
        elif opt in ("-r", "--remcos_version"):
            REMCOS_VERSION_CHECK = True
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

    if REMCOS_VERSION_CHECK:
        check_version(pefilename)
        exit(0)

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

    if DECRYPT_ONLY and not C2_ONLY:
        print_hexdata_str(clear_text)
    elif not DECRYPT_ONLY and not C2_ONLY:
        print_hexdata("\nDecrypted data:",clear_text,0x0)

    if C2_ONLY:
        C2 = get_C2(clear_text)
        for C2_server in C2:
            print("%s" % C2_server)
        print
 
    exit(0)

if __name__ == "__main__":
    main(sys.argv[1:])

