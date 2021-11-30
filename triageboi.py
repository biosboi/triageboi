import sys
import hashlib
import os

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
    
    def getFileType(self):
        ftypes = {
            b"MZ\x90" : "PE File",
            b"ELF" : "ELF File"
        }
        magic = self.handle.read(3)
        for key,value in ftypes.items():
            if magic == key:
                return value
        

    def hashfile(self):
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
        print("MD5: " + md5)
        print("SHA1: " + sha1)
        print("SHA256: " + sha256)


    def printVals(self):
        print("File Name: " + sys.argv[1])
        print("size calculated: " + str(self.fsize) + " Bytes")
        print("File Type: " + str(self.ftype))

main()
