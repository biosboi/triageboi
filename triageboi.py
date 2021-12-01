import sys
import hashlib
import os
import pefile

def main():
    try:
        fileh = open(sys.argv[1],"rb")
        fclass = data(fileh)
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
            pe = pefile.PE(sys.argv[1])
            self.pefile_info(pe)
    
    def getFileType(self):
        #Grab file type based on magic number.
        
        ftypes = {
            b"MZ\x90" : "PE File",
            b"ELF" : "ELF File"
        }
        magic = self.handle.read(3)
        for key,value in ftypes.items():
            if magic == key:
                return value
        

    def hashfile(self):
        #Produce MD5, SHA1, and SHA256 hashse. returns as class var.
        
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
    
    def printVals(self):
        #Produces output
        print("File Name: " + sys.argv[1])
        print("File Size: " + str(self.fsize) + " Bytes")
        print("File Type: " + str(self.ftype))
        print(self.compile_time)
        print("MD5: " + self.fhash[0])
        print("SHA1: " + self.fhash[1])
        print("SHA256: " + self.fhash[2])
        

main()
