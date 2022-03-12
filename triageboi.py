import hashlib
import json
import os
import pefile
import re
import requests
import sys



def main():
    global wholeDir
    if len(sys.argv) > 1:
        if sys.argv[1] == "help":
            # Access the help menu and exit
            helpMenu()
            return
        try:
            # Run against single file
            wholeDir = False
            fileh = open(sys.argv[1], "rb")
            startup(fileh,sys.argv[1])
        except FileNotFoundError:
            print("Please provide a valid input file as an argument.")
    else:
        # Run against entire directory
        wholeDir = True
        filelist = []
        x = os.listdir()
        for file in x:
            if "triageboi" in file or os.path.isdir(file):
                pass
            else:
                filelist.append(file)

        for i in filelist:
            # Run against each file
            fileh = open(i, "rb")
            startup(fileh, i)

        print("Congratulations, your directory has been triageboi'd! \nPlease refer to the dropped log files for further information.")

def startup(fd, path):
    fclass = data(fd, path)
    fclass.vtSearch()
    fclass.createLogFile()

    if "-j" in sys.argv or wholeDir:
        fclass.jiraFormat()
    if not wholeDir:
        fclass.printVals()



class data():
    def __init__(self, handle, path):
        self.path = path
        self.fname = os.path.basename(self.path)
        self.handle = handle
        self.fsize = os.path.getsize(self.path)
        self.ftype = self.getFileType()
        self.fhash = self.hashfile()

        self.isDLL = False
        self.isPacked = ""
        if self.ftype == "PE File":
            pe = pefile.PE(self.path)
            self.pefile_info(pe)
            if self.isDLL == True:
                self.exportData = self.dll_data(pe)
        elif self.ftype == "ELF File":
            self.elffile_info(self.handle)
        else:
            pass

    def getFileType(self):
        # Grab file type based on magic number.

        ftypes = {
            b"MZ" : "PE File",
            b"\x7fEL" : "ELF File",
            b"PK" : "DOCX/XLSX/PPTX/Jar/Zip Folder",
            b"\x25PD" : "PDF Document",
            b"\x1f\x8b" : "GZip Folder",
            b"\x75\x73\x74" : "Tar Folder",
            b"\xd0\xcf\x11" : "Microsoft Installer",
            b"\x1f\x9d" : "Compressed File (Tar or Zip)",
            b"\x1f\xa0" : "Compressed File (Tar or Zip)",
            b"\xff\xd8" : "JPEG File",
            b"\x37\x7a\xbc" : "7-Zip File",
        }

        magic = self.handle.read(3)
        self.handle.seek(0)
        for key,value in ftypes.items():
            if key in magic:
                return value
        return "Unknown File Type"

    def hashfile(self):
        # Produce MD5, SHA1, and SHA256 hashes. returns as class var.

        md5 = hashlib.md5()
        with open(self.path, 'rb') as afile:
            buf = afile.read()
            md5.update(buf)

        sha1 = hashlib.sha1()
        with open(self.path, 'rb') as afile:
            buf = afile.read()
            sha1.update(buf)

        sha256 = hashlib.sha256()
        with open(self.path, 'rb') as afile:
            buf = afile.read()
            sha256.update(buf)

        md5 = md5.hexdigest().upper()
        sha1 = sha1.hexdigest().upper()
        sha256 = sha256.hexdigest().upper()
        hashes = (md5, sha1, sha256)

        return hashes

    def pefile_info(self, pe):
        peMachTypes = {
            0x0    : "IMAGE_FILE_MACHINE_UNKNOWN",
            0x1d3  : "Matsushita AM33",
            0x8664 : "x64",
            0x1c0  : "ARM little endian",
            0xaa64 : "ARM64 little endian",
            0x1c4  : "ARM Thumb-2 little endian",
            0xebc  : "EFI byte code",
            0x14c  : "Intel 386 or later processors and compatible processors",
            0x200  : "Intel Itanium processor family",
            0x6232 : "LoongArch 32-bit processor family",
            0x6264 : "LoongArch 64-bit processor family",
            0x9041 : "Mitsubishi M32R little endian",
            0x266  : "MIPS16",
            0x366  : "MIPS with FPU",
            0x466  : "MIPS16 with FPU",
            0x1f0  : "Power PC little endian",
            0x1f1  : "Power PC with floating point support",
            0x166  : "MIPS little endian",
            0x5032 : "RISC-V 32-bit address space",
            0x5064 : "RISC-V 64-bit address space",
            0x5128 : "RISC-V 128-bit address space",
            0x1a2  : "Hitachi SH3",
            0x1a3  : "Hitachi SH3 DSP",
            0x1a6  : "Hitachi SH4",
            0x1a8  : "Hitachi SH5",
            0x1c2  : "Thumb",
            0x169  : "MIPS little-endian WCE v2"
        }

        # Check if it is a 32-bit or 64-bit binary
        if hex(pe.FILE_HEADER.Machine) == '0x14c':
            self.ftype = "32bit PE File"
        else:
            self.ftype = "64bit PE File"

        # Looking if it's a DLL or EXE
        if pe.dump_dict()['FILE_HEADER']['Characteristics']['Value'] & 0x2000:
            self.ftype += ' (DLL)'
            self.isDLL = True

        # Machine Type
        peMachType = pe.FILE_HEADER.Machine
        for key,value in peMachTypes.items():
            if peMachType == key:
                self.peMachType = value

        # Compiled Time
        self.compile_time = (pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])

        # Imphash
        self.imphash = pe.get_imphash().upper()

        # Rich Header Hash
        self.rHeadHash = pe.get_rich_header_hash().upper()

        # Get Imports
        self.peImports = ""
        self.peImports = "\nImports:\n"
        for i in pe.DIRECTORY_ENTRY_IMPORT:
            self.peImports += i.dll.decode('utf-8') + "\n"

        # Section data
        self.commonSections = {".text",".bss",".rdata",".data",".pdata",".reloc",".edata",".idata",".tls",".debug",".rsrc"}
        self.peSections = ""
        self.funkySections = []
        for section in pe.sections:
            if "UPX" in section.Name.decode('utf-8'):
                self.isPacked = "UPX"

            #self.funkySections.append(section.Name.decode('utf-8'))

            self.peSections += section.Name.decode('utf-8')
            self.peSections += "\n\tVirtual Address: " + hex(section.VirtualAddress) + "\n"
            self.peSections += "\tVirtual Size: " + hex(section.Misc_VirtualSize) + "\n"
            self.peSections += "\tRaw Size: " + hex(section.SizeOfRawData) + "\n\n"
        for i in self.funkySections:
            print(self.funkySections)
            print(i)
            if i in self.commonSections:
                self.funkySections.remove(i)
                print(self.funkySections)
        #if self.funkySections:
        #    self.peSections += "Odd section names were found:\n"
        #    for i in self.funkySections:
        #        self.peSections += i + "\n"




    def dll_data(self,pe):
        # Grab Export Data
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exportData = "Ordinal: | Export Name:\n"

        ords = [(e.ordinal) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        exports = [(e.name) for e in pe.DIRECTORY_ENTRY_EXPORT.symbols]
        i = 0
        while i < len(ords):
            if i < 9:
                exportData += (str(ords[i]) + "        | " + exports[i].decode("utf-16") + "\n")
            else:
                exportData += (str(ords[i]) + "       | " + exports[i].decode("utf-16") + "\n")
            i+=1

        return exportData

    def elffile_info(self,handle):
        ABItypes = {
            0x0 : "System V",
            0x1 : "HP-UX",
            0x2 : "NetBSD",
            0x3 : "Linux",
            0x4 : "GNU Hurd",
            0x6 : "Solaris",
            0x7 : "AIX",
            0x8 : "IRIX",
            0x9 : "FreeBSD",
            0xA : "Tru64",
            0xB : "Novell Modesto",
            0xC : "OpenBSD",
            0xD : "OpenVMS",
            0xE : "NonStop Kernel",
            0xF : "AROS",
            0x10: "Fenix OS",
            0x11: "CloudABI",
            0x12: "Stratus Technologies OpenVOS"
            }
        Objtypes = {
            0x0 : "None",
            0x1 : "Relocatable",
            0x2 : "Executable",
            0x3 : "Shared Object",
            0x4 : "Core"
            }
        Machtypes = {
            0x00 : "No specific instruction set",
            0x01 : "AT&T WE 32100",
            0x02 : "SPARC",
            0x03 : "x86",
            0x04 : "Motorola 68000 (M68k)",
            0x05 : "Motorola 88000 (M88k)",
            0x06 : "Intel MCU",
            0x07 : "Intel 80860",
            0x08 : "MIPS",
            0x09 : "IBM System/370",
            0x0A : "MIPS RS3000 Little-endian",
            0x0E : "Hewlett-Packard PA-RISC",
            0x0F : "Reserved for future use",
            0x13 : "Intel 80960",
            0x14 : "PowerPC",
            0x15 : "PowerPC (64-bit)",
            0x16 : "S390, including S390x",
            0x17 : "IBM SPU/SPC",
            0x24 : "NEC V800",
            0x25 : "Fujitsu FR20",
            0x26 : "TRW RH-32",
            0x27 : "Motorola RCE",
            0x28 : "ARM (up to ARMv7/Aarch32)",
            0x29 : "Digital Alpha",
            0x2A : "SuperH",
            0x2B : "SPARC Version 9",
            0x2C : "Siemens TriCore embedded processor",
            0x2D : "Argonaut RISC Core",
            0x2E : "Hitachi H8/300",
            0x2F : "Hitachi H8/300H",
            0x30 : "Hitachi H8S",
            0x31 : "Hitachi H8/500",
            0x32 : "IA-64",
            0x33 : "Stanford MIPS-X",
            0x34 : "Motorola ColdFire",
            0x35 : "Motorola M68HC12",
            0x36 : "Fujitsu MMA Multimedia Accelerator",
            0x37 : "Siemens PCP",
            0x38 : "Sony nCPU embedded RISC processor",
            0x39 : "Denso NDR1 microprocessor",
            0x3A : "Motorola Star*Core processor",
            0x3B : "Toyota ME16 processor",
            0x3C : "STMicroelectronics ST100 processor",
            0x3D : "Advanced Logic Corp. TinyJ embedded processor family",
            0x3E : "AMD x86-64",
            0x8C : "TMS320C6000 Family",
            0xAF : "MCST Elbrus e2k",
            0xB7 : "ARM 64-bits (ARMv8/Aarch64)",
            0xF3 : "RISC-V",
            0xF7 : "Berkeley Packet Filter",
            0x101 : "WDC 65C816"
            }

        # Grab Header
        elf_head = self.handle.read(0x14)

        # Check if it is a 32-bit or 64-bit binary
        if elf_head[0x4] == 0x2:
            self.ftype = "64bit ELF File"
        else:
            self.ftype = "32bit ELF File"

        # Check ABI
        abi = elf_head[0x7]
        for key,value in ABItypes.items():
            if abi == key:
                self.abi = value

        # Check Object File Type
        objtype = elf_head[0x10]
        for key,value in Objtypes.items():
            if objtype == key:
                self.objtype = value

        # Check Machine Type
        machtype = elf_head[0x12]
        for key,value in Machtypes.items():
            if machtype == key:
                self.machtype = value

    def vtSearch(self):
        # Send file to VT

        # \/\/INSERT VT API KEY IF YOU WANT THIS TO WORK\/\/
        apikey = '<INSERT_VT_API_KEY>'
        # /\/\INSERT VT API KEY IF YOU WANT THIS TO WORK/\/\

        if apikey == '<INSERT_VT_API_KEY>':
            self.VTsuccess = False
        else:
            api_url = 'https://www.virustotal.com/vtapi/v2/file/scan'
            params = dict(apikey=apikey)
            with open(sys.argv[1], 'rb') as file:
                files = dict(file=(sys.argv[1], file))
                response = requests.post(api_url, files=files, params=params)
            if response.status_code == 200:
                self.VTsuccess = True
                result=response.json()
                print(json.dumps(result, sort_keys=False, indent=4))

            # Retrieve Report from VT
            api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
            params = dict(apikey=apikey, resource='275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1577043276')
            response = requests.get(api_url, params=params)
            if response.status_code == 200:
                self.result = response.json()
                self.VTOutput = json.dumps(self.result, sort_keys=False, indent=4)

                # Write VT JSON Log
                hVTLog = open(sys.argv[1] + "_VT_REPORT.json", "a")
                hVTLog.write(self.VTOutput)
                hVTLog.close()
            hVTLog.close()

    def susStrSearch(self):
        pass
        # Will will finish this when will wills himself to finish this.

    def printVals(self):
        print("\n" + "-"*65 + "\nTRIAGEBOI Console Output For File: " + self.fname + "\n\n" + \
               "TRIAGEBOI is Written and directed by [William (Nathan] Robinson)" + "\n" + "-"*65 + "\n")
        print("Give argument \"help\" for the help menu.")
        # Print output to console. Same as what's put into the triagelog file.
        print("\nStandard Data:" + \
               "\nFile Name: " + str(self.fname) + \
               "\nFile Size: " + str(self.fsize) + " Bytes" + \
               "\nFile Type: " + str(self.ftype) + \
               "\nMD5: " + self.fhash[0] + \
               "\nSHA1: " + self.fhash[1] + \
               "\nSHA256: " + self.fhash[2] + "\n")

        if self.isPacked:
            print("\nThis file is " + self.isPacked + " packed.\n")

        # Conditional prints based on file type
        if "PE" in self.ftype:
            print("\nPE Data:" + \
                  "\nMachine Type: " + self.peMachType + \
                  "\nImphash: " + self.imphash + \
                  "\nRich Header Hash: " + self.rHeadHash + \
                  "\nCompiled Time: " + self.compile_time)
            print(self.peImports)
            if self.isDLL == True:
                print("\nExports:\n" + \
                      self.exportData)
            print("\nSection Data:\n" + self.peSections)
        if "ELF" in self.ftype:
            print("\nELF Data:" + \
                  "\nABI: " + self.abi + \
                  "\nObject File Type: " + self.objtype + \
                  "\nMachine Type: " + self.machtype + "\n")

        # Print VT results
        print("\nVirusTotal Data:")
        if self.VTsuccess == True:
            print("\nScan Result: " + str(self.result['positives']) + "/" + str(self.result['total']) + \
                  "\nLink to Report: " + str(self.result['permalink']))
        else:
            print("Implement VirusTotal API Key for VirusTotal Results")

    def createLogFile(self):
        # Write output to log file
        if wholeDir:
            hLogFile = open("triageboi_LOG.txt", "a")
        else:
            hLogFile = open(self.fname + "_triageboi_LOG.txt", "a")
        hLogFile.write("\n" + "-"*65 + "\nTRIAGEBOI Log Output For File: " + self.fname + "\n\n" + \
                       "TRIAGEBOI is Written and directed by [William (Nathan] Robinson)" + "\n" + "-"*65 + "\n")
        hLogFile.write("\nStandard Data:" + \
                        "\nFile Name: " + str(self.fname) + \
                        "\nMD5: " + self.fhash[0] + \
                        "\nSHA1: " + self.fhash[1] + \
                        "\nSHA256: " + self.fhash[2] + \
                        "\nFile Size: " + str(self.fsize) + " Bytes" + \
                        "\nFile Type: " + str(self.ftype) + "\n")

        # Conditional prints based on file type
        if "PE" in self.ftype:
            hLogFile.write("\n\nPE Data:" + \
                           "\nMachine Type: " + self.peMachType + \
                           "\nImphash: " + self.imphash + \
                           "\nRich Header Hash: " + self.rHeadHash + \
                           "\nCompiled Time: " + self.compile_time + "\n")
            if self.isPacked:
                hLogFile.write("\nThis file is " + self.isPacked + " packed.\n")
            hLogFile.write(self.peImports)
            if self.isDLL == True:
                try:
                    hLogFile.write("\n\nExports:" + \
                                   "\n" + self.exportData)
                except UnicodeEncodeError:
                    hLogFile.write("\nUnicode Translation error while parsing exports. Working on it\n")
            hLogFile.write("\nSection Data:\n" + self.peSections)
        if "ELF" in self.ftype:
            hLogFile.write("\n\nELF Data:" + \
                           "\nABI: " + self.abi + \
                           "\nObject File Type: " + self.objtype + \
                           "\nMachine Type: " + self.machtype)

        # Write VT results to Log file
        hLogFile.write("\n\nVirusTotal Data:")
        if self.VTsuccess == True:
            hLogFile.write("\nScan Result: " + str(self.result['positives']) + "/" + str(self.result['total']) + \
                           "\nLink to Report: " + str(self.result['permalink']))
        else:
            hLogFile.write("\nImplement VirusTotal API Key for VirusTotal Results\n\n\n")

        hLogFile.close()

    def jiraFormat(self):
        # Write output to log file
        if wholeDir:
            hLogFile = open("triageboi_JIRA.txt", "a")
        else:
            hLogFile = open(self.fname + "_triageboi_JIRA.txt", "a")
        hLogFile.write("\n" + "-"*65 + "\nTRIAGEBOI Log Output For File: " + self.fname + "\n\n" + \
                       "TRIAGEBOI is Written and directed by [William (Nathan] Robinson)" + "\n" + "-"*65 + "\n")

        hLogFile.write("\n|+*Metadata Details*+|********|\n" + \
                       "\n|*Filename*|" + str(self.fname) + "|" + \
                       "\n|*VALUE*|" + "|" + \
                       "\n|*MD5*|" + self.fhash[0] + "|" + \
                       "\n|*SHA1*|" + self.fhash[1] + "|" + \
                       "\n|*SHA256*|" + self.fhash[2] + "|" + \
                       "\n|*File Size*|" + str(self.fsize) + " Bytes" + "|" + \
                       "\n|*File Type*|" + str(self.ftype) + "|" + \
                       "\n|*V/T*||" + \
                       "\n|Poss. Attribution*||" + \
                       "\n|Family||\n")

        if self.isPacked:
            hLogFile.write("\nThis file is " + self.isPacked + " packed.\n")

        # Conditional prints based on file type
        if "PE" in self.ftype:
            hLogFile.write("\n\n|+*PE Data*+|********|" + "|" + \
                           "\n|*Compile Time*|" + self.compile_time + "|" + \
                           "\n|*Machine Type*|" + self.peMachType + "|" + \
                           "\n|*Imphash*|" + self.imphash + "|" + \
                           "\n|*Rich Header Hash*|" + self.rHeadHash + "|\n")
            hLogFile.write(self.peImports)
            if self.isDLL == True:
                try:
                    hLogFile.write("\n\nExports:" + \
                                   "\n" + self.exportData)
                except UnicodeEncodeError:
                    hLogFile.write("\nUnicode Translation error while parsing exports. Working on it\n")
        elif "ELF" in self.ftype:
            hLogFile.write("\n\nELF Data:" + \
                           "\nABI: " + self.abi + \
                           "\nObject File Type: " + self.objtype + \
                           "\nMachine Type: " + self.machtype)

        # Write VT results to Log file
        hLogFile.write("\n\nVirusTotal Data:")
        if self.VTsuccess == True:
            hLogFile.write("\nScan Result: " + str(self.result['positives']) + "/" + str(self.result['total']) + \
                           "\nLink to Report: " + str(self.result['permalink']))
        else:
            hLogFile.write("\nImplement VirusTotal API Key for VirusTotal Results\n\n\n")

        hLogFile.close()

def helpMenu():
    a = 0
    print("\n" + "-"*70 + "\n" + "-"*70 + "\nWelcome to the TRIAGEBOI Help Menu\n\n" + \
           "TRIAGEBOI is Written and directed by [William (Nathan] Robinson)" + "\n" + "-"*70 + "\n\n" + \
           "Thanks for accessing the help menu. You are number " + str(id(a)) + " in queue.\n\n" + \
           "Run triageboi with no arguments to log the entire current directory. \nDrag and drop a " + \
           "file to log only that file. \n\nAdd a '-j' argument to produce a JIRA ready log file.\n\n" + \
           "Running against an entire directory will produce both a regular log file and a JIRA ready log file.\n" + \
           "-"*70)

if __name__ == "__main__":
    main()
