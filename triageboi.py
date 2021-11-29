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
        print("Class Initialized") # TEST
        self.handle = handle
        self.fsize = os.path.getsize(sys.argv[1])
        self.ftype = self.getFileType()
        #self.fhash = self.hashfile()
    
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
        buff_size = 65536# lets read stuff in 64kb chunks!

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        while True:
            data = self.read(buf_size)
            if not data:
                break
            md5.update(data)
            sha1.update(data)

        print("MD5: {0}".format(md5.hexdigest()))
        print("SHA1: {0}".format(sha1.hexdigest()))

    def printVals(self):
        print("File Name: " + sys.argv[1])
        print("size calculated: " + str(self.fsize) + " Bytes")
        print("File Type: " + str(self.ftype))
        print("MD5: {0}".format(md5.hexdigest()))
        print("SHA1: {0}".format(sha1.hexdigest()))

main()
