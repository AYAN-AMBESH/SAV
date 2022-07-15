import base64
import os
import sys
import sqlite3
import hashlib
import yara
from os import walk, path


class Scanner:
    filetoscan = ""
    dbpath = "../../scripts/hash.db"
    directorytoscan = ""
    rule_file = "../../test.yar"

    def __init__(self,filetoscan,pathtodb="../../scripts/hash.db", rule_file="C:/Users/Ayan Ambesh/Documents/Github/Mal-ANALYSIS/SAV/test.yar"):
        self.pathtodb = pathtodb
        self.conn = sqlite3.connect(pathtodb)
        self.cur = self.conn.cursor()
        self.filetoscan = filetoscan
        self.rule_file = rule_file
        print("[+]Initialzing..............................")
    def __init__(self):
        try:
            self.conn = sqlite3.connect(self.dbpath)
            self.cur = self.conn.cursor()
        except sqlite3.Error as error:
            print("Error while connecting to sqlite", error)

        print("[+]Initializing..............................")

    def convtosha256(self):
        try:
            with open(self.filetoscan, 'rb') as f:
                temp = f.readline()
                sha256hash = hashlib.sha256(temp).hexdigest()
        except IOError:
            print("File not accessible")
        else:
            return sha256hash
        finally:
            f.close()

    def scan_hash(self):
        global malwarehashes
        if not os.path.exists(self.filetoscan):
            print("invalid file path")
            self.__exit__()
        filehash = self.convtosha256()
        try:
            self.cur.execute('SELECT * FROM "check"')
            malwarehashes = self.cur.fetchall()
        except sqlite3.Error as error:
            print("Error : ", error)

        malwarelist = []
        for i in malwarehashes:
            _id, _virushash = i
            malwarelist.append(_virushash)
        res = []
        # res = [x for x in malwarelist if x == filehash]
        for x in malwarelist:
            if x == filehash:
                res.append(os.path.abspath(self.filetoscan))

        if res:
            print("[+]-----------Malware-Found-------------[+]")
            print(f"HASH OF MALWARE FOUND:{res}")
            print(res)
            print("")
            choice = input('Do you want to delete malicious file?(Y/N) ')
            print(choice)
            if choice == 'Y' or choice == 'y':
                os.remove(self.filetoscan)
                print("file removed")
            else:
                print("file not removed")
            print("[+]-------------------------------------[+]")
            return self.filetoscan
        else:
            print("[+]File free from malware")

    def scan_yara(self):
        if not os.path.exists(self.rule_file):
            print("invalid rule file path")
            self.__exit__()
        if not os.path.exists(self.directorytoscan):
            print("invalid directory path")
            self.__exit__()
        print("[+]-----Scanning---through----Yara-----------[+]")
        rules = yara.compile(filepath=self.rule_file)
        for root, _, files in walk(self.directorytoscan, followlinks=False):
            for filename in files:
                filePath = path.join(root, filename)
                print("scanning ", filePath)
                matches = rules.match(filePath, fast=True)
                print(matches)
        if matches  != []:
            return filename
        else: return "NO MALACIOUS FILE FOUND"
    
                filepath = path.join(root, filename)
                print("scanning ", filepath)
                matches = rules.match(filepath, fast=True, )
                print(matches)

    def __exit__(self):
        self.conn.close()
        print("[+]Exiting...............................")
        sys.exit()




class Quarantine(File_Scanner):
    def __init__(self,dirtoscan,filetoscan):
        super(Quarantine,self).__init__(filetoscan)
        self.maldir = dirtoscan
        self.filevir = super().scan_yara(self.maldir)
    
    def qurantine_file_via_b64(self):
        with open(f'{self.maldir}/{self.filevir}', 'rb' ) as  vir:
            virus=base64.b64encode(vir.read())
        print(virus)
        
            

if __name__ == "__main__":
    pathofdb = "../../scripts/hash.db"
    filetoscan = "../../test/test.txt"
    Directorytoscan = "C:/Users/Ayan Ambesh/Documents/Github/Mal-ANALYSIS/SAV/test"
    rule_file = "C:/Users/Ayan Ambesh/Documents/Github/Mal-ANALYSIS/SAV/test.yar"

    myScanner = File_Scanner(
         filetoscan=filetoscan,pathtodb=pathofdb ,rule_file=rule_file)
    myScanner.scan_hash()
    # mal_file = myScanner.scan_yara(Directorytoscan=Directorytoscan)
    # print(mal_file)
    # print(path.abspath(mal_file))
    # # File_Scanner.__exit__(myScanner)
    # directoryOfmal = path.dirname(mal_file)
    # print(directoryOfmal)
    quarant = Quarantine(Directorytoscan,filetoscan)
    quarant.qurantine_file_via_b64()
    quarant.qurantine_file_via_b64()
    myScanner = Scanner()
    myScanner.filetoscan = "../../test/test.txt"
    myScanner.directorytoscan = "../../test"
    myScanner.scan_hash()
    myScanner.scan_yara()
    Scanner.__exit__(myScanner)
