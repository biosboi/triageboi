import sys
import hashlib
import os
import pefile

def main():
    try:
        fclass = data(open(sys.argv[1],"rb"))
        fclass.printVals()
    except IndexError:
        print("Please provide input file as argument")

class data():
    def __init__(self, handle):
        self.handle = handle
        self.fsize = os.path.getsize(sys.argv[1])
        self.ftype = self.getFileType()
        self.fhash = self.hashfile()

        if self.ftype == "PE File":
            self.binbool = True
            pe = pefile.PE(sys.argv[1])
            self.pefile_info(pe)
        elif self.ftype == "ELF File":
            self.binbool = True
            self.elffile_info(self.handle)
        else:
            self.binbool = False
    
    def getFileType(self):
        #Grab file type based on magic number.
        
        ftypes = {
            b"MZ\x90" : "PE File",
            b"\x7fEL" : "ELF File",
            b"PK\x03" : "DOCX/XLSX/PPTX/Jar/Zip Folder",
            b"\x25PD" : "PDF Document",
            b"\x1f\x8b\x08" : "GZip Folder",
            b"\x75\x73\x74" : "Tar Folder",
            b"\xd0\xcf\x11" : "Microsoft Installer"
        }
        magic = self.handle.read(3)
        self.handle.seek(0)
        for key,value in ftypes.items():
            if magic == key:
                return value

    def hashfile(self):
        #Produce MD5, SHA1, and SHA256 hashes. returns as class var.
        
        md5 = hashlib.md5()
        with open(sys.argv[1], 'rb') as afile:
            buf = afile.read()
            md5.update(buf)

        sha1 = hashlib.sha1()
        with open(sys.argv[1], 'rb') as afile:
            buf = afile.read()
            sha1.update(buf)

        sha256 = hashlib.sha256()
        with open(sys.argv[1], 'rb') as afile:
            buf = afile.read()
            sha256.update(buf)
            
        md5 = md5.hexdigest().upper()
        sha1 = sha1.hexdigest().upper()
        sha256 = sha256.hexdigest().upper()
        hashes = (md5, sha1, sha256)
        
        return hashes

    def pefile_info(self, pe):
        #Check if it is a 32-bit or 64-bit binary
        if hex(pe.FILE_HEADER.Machine) == '0x14c':
            self.ftype = "64bit PE File"
        else:
            self.ftype = "32bit PE File"

        #Compiled Time    
        self.compile_time = ("Compiled Time: " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])

    def elffile_info(self,handle):
        ABItypes = {
            0 : "System V",
            1 : "HP-UX",
            2 : "NetBSD",
            3 : "Linux",
            4 : "GNU Hurd",
            6 : "Solaris",
            7 : "AIX",
            8 : "IRIX",
            9 : "FreeBSD",
            10: "Tru64",
            11: "Novell Modesto",
            12: "OpenBSD",
            13: "OpenVMS",
            14: "NonStop Kernel",
            15: "AROS",
            16: "Fenix OS",
            17: "CloudABI",
            18: "Stratus Technologies OpenVOS"
            }
        Objtypes = {
            0 : "None",
            1 : "Relocatable",
            2 : "Executable",
            3 : "Shared Object",
            4 : "Core"
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
        
        #Grab Header
        elf_head = self.handle.read(0x14)
        
        #Check if it is a 32-bit or 64-bit binary
        if elf_head[4] == 2:
            self.ftype = "64bit ELF File"
        else:
            self.ftype = "32bit ELF File"

        #Check ABI
        abi = elf_head[0x7]
        for key,value in ABItypes.items():
            if abi == key:
                self.abi = value

        #Check Object File Type
        objtype = elf_head[0x10]
        for key,value in Objtypes.items():
            if objtype == key:
                self.objtype = value

        #Check Machine Type
        machtype = elf_head[0x12]
        for key,value in Machtypes.items():
            if machtype == key:
                self.machtype = value
                
    def printVals(self):
        #Produces output

        print("\nStandard Data:")
        print("File Name: " + sys.argv[1])
        print("File Size: " + str(self.fsize) + " Bytes")
        print("File Type: " + str(self.ftype))
        print("MD5: " + self.fhash[0])
        print("SHA1: " + self.fhash[1])
        print("SHA256: " + self.fhash[2])

        #Conditional prints based on file type
        #if self.binbool == True:
        #    print(self.compile_time)
        if "ELF" in self.ftype:
            print("\nELF Data:")
            print("ABI: " + self.abi)
            print("Object File Type: " + self.objtype)
            print("Machine Type: " + self.machtype)

main()
