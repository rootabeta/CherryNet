import py7zr
from os import mkdir,listdir,remove,path,rmdir
from random import choice
from string import ascii_letters, digits

class Archive():
    def __init__(self,archivePath, decryptionKey):
        self.archivePath = archivePath #Path to encrypted archive
        self.decryptionKey = decryptionKey #Cherrytree decryption password
        self.fileName = None
        self.makeTempPath() #Folder for plaintext data

    def makeTempPath(self):
        tempPath = "/tmp/CherryTmp_"
        for _ in range(16):
            tempPath += choice(ascii_letters + digits)

        mkdir(tempPath)
        self.tempPath = tempPath

    def emptyDir(self):
        for file in listdir(self.tempPath):
            remove(path.join(self.tempPath,file))
        rmdir(self.tempPath)

    def new(self):
        raise NotImplementedError("New encrypted archive not yet supported") # TODO: Handle empty file

    def open(self):
        if self.archivePath[-4:] != ".ctz":
            return -1 #Invalid file format

        #Extract filename
        with py7zr.SevenZipFile(self.archivePath, 'r',password=self.decryptionKey) as archive:
            fileName = archive.getnames()[0] #Get file name - a ctz file should only have one entry.
            if fileName[-4:] != ".ctd": 
                return -3 #Invalid file format
            try:
                archive.extractall(path=self.tempPath)
            except Exception as e:
                print(e)
                return -2 #Bad password

        self.fileName = fileName
        return path.join(self.tempPath,fileName) #return path to new ctd file

    def close(self):
        #Bundle file
        with py7zr.SevenZipFile(self.archivePath, 'w', password=self.decryptionKey) as archive:
            archive.write(path.join(self.tempPath,self.fileName),self.fileName) #Write all from temppath 

        self.emptyDir()
