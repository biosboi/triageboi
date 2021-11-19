import sys
import hashlib

def main():
    try:
        fileh = open(sys.argv[1],"rb")
        fclass = data()
    except IndexError:
        print("Please provide input file as argument")



class data:
    def __init__(self):
        self.fname = sys.argv[1]
        #self.fsize = fsize
        #self.ftype = ftype
        self.fhash = self.hashfile(fname)

    def hashfile(fileh):
        buff_size = 131072# lets read stuff in 128kb chunks!

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()

        while True:
            data = fileh.read(buf_size)
            if not data:
                break
            md5.update(data)
            sha1.update(data)

        print("MD5: {0}".format(md5.hexdigest()))
        print("SHA1: {0}".format(sha1.hexdigest()))
    
main()
