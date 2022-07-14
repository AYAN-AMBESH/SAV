from ast import Not
import sqlite3
import hashlib
import yara
from os import walk, path


class File_Scanner:

    def __init__(self, pathtodb, filetoscan, rule_file):
        self.pathtodb = pathtodb
        self.conn = sqlite3.connect(pathtodb)
        self.cur = self.conn.cursor()
        self.filetoscan = filetoscan
        self.rule_file = rule_file
        print("[+]Initialzing..............................")

    def scan_hash(self):
        def convtohash():
            with open(self.filetoscan, 'rb') as f:
                temp = f.readline()
                hash = hashlib.sha256(temp).hexdigest()
                f.close()
                return hash
        _hash = convtohash()
        # print(_hash)
        self.cur.execute('SELECT * FROM "check"')
        _mal_hash = self.cur.fetchall()
        # for i in _lentgh: _extra +=1
        # print(_mal_hash)
        mallist = []
        for i in _mal_hash:
            _id, _virushash = i
            # print(_virushash)
            mallist.append(_virushash)
        # print(mallist)
        res = [x for x in mallist if x == _hash]
        if res !=  []:    
            print("[+]-----------Malware-Found-------------[+]")
            print(res)
            print("[+]-------------------------------------[+]")
        else:
            print("[+]File free from malware")
        # for a in mallist:
        #     if  a == _hash:return "Malware found"
        #     else: return "The file scanned is perfectly fine"

    def scan_yara(self, Directorytoscan):
        print("[+]-----Scanning---through----Yara-----------[+]")
        rules = yara.compile(filepath=self.rule_file)
        for root, _, files in walk(Directorytoscan, followlinks=False):
            for filename in files:
                filePath = path.join(root, filename)
                print("scanning ", filePath)
                matches = rules.match(filePath, fast=True,)
                print(matches)





    def __exit__(self):
        self.conn.close()
        print("[+]Exiting...............................")

if __name__ == "__main__":
    pathofdb = "../../scripts/hash.db"
    filetoscan = "../../test/test.txt"
    Directorytoscan = "../../test"
    rule_file = "C:/Users/Ayan Ambesh/Documents/Github/Mal-ANALYSIS/SAV/test.yar"

    myScanner = File_Scanner(
        pathtodb=pathofdb, filetoscan=filetoscan, rule_file=rule_file)
    myScanner.scan_hash()
    myScanner.scan_yara(Directorytoscan=Directorytoscan)
    File_Scanner.__exit__(myScanner)