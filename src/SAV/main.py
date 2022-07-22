import base64
import sqlite3
import hashlib
import yara
from os import walk, path, remove
import sys


class Scanner:
    db_path = "../../scripts/hash.db"

    def __init__(self):
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.cur = self.conn.cursor()
        except sqlite3.Error as error:
            print("Error while connecting to sqlite", error)

    def convert_to_sha256(self, file):
        try:
            with open(file, 'rb') as f:
                temp = f.readline()
                sha256hash = hashlib.sha256(temp).hexdigest()
        except IOError:
            print("File not accessible")
        else:
            return sha256hash
        finally:
            f.close()

    def file_remove(self, result_dic):
        for key in result_dic:
            try:
                remove(key)
            except OSError as e:
                print("Error while removing : {}".format(key))
                print("Error : {}".format(e))
            else:
                print("file removed : {}".format(key))

    def scan_hash(self, file_to_be_checked, hash_list=""):

        global malware_hashes
        if not path.exists(file_to_be_checked):
            print("invalid file path")
            self.__exit__()
        file_to_be_checked_hash = self.convert_to_sha256(file_to_be_checked)

        if not hash_list:
            try:
                self.cur.execute('SELECT * FROM "check"')
                malware_hashes = self.cur.fetchall()
            except sqlite3.Error as error:
                print("Error : ", error)
            malware_hashes_list = []
            for i in malware_hashes:
                _id, _virushash = i
                malware_hashes_list.append(_virushash)
            result = {}
            for x in malware_hashes_list:
                if x == file_to_be_checked_hash:
                    result[path.abspath(file_to_be_checked)] = x
            return result

        elif hash_list:
            result = {}
            malware_hashes_list = list(open(hash_list, "r").read().split("\n"))
            for x in malware_hashes_list:
                if x == file_to_be_checked_hash:
                    result[path.abspath(file_to_be_checked)] = x
            return result

    def scan_yara(self, path_to_be_checked, rule_file="../../test.yar"):
        if not path.exists(rule_file):
            print("invalid rule file path")
            self.__exit__()
        if not path.exists(path_to_be_checked):
            print("invalid directory path")
            self.__exit__()

        rules = yara.compile(filepath=rule_file)
        result = {}
        for root, _, files in walk(path_to_be_checked, followlinks=False):
            for filename in files:
                current_file = path.join(root, filename)
                print("scanning ", path.abspath(current_file))
                matches = rules.match(current_file, fast=True, )
                if matches:
                    result[path.abspath(current_file)] = matches[0]
        return result

    def __exit__(self):
        self.conn.close()
        sys.exit()

# class Quarantine(Scanner):
#     def __init__(self,dirtoscan,filetoscan):
#         super(Quarantine,self).__init__(filetoscan)
#         self.maldir = dirtoscan
#         self.filevir = super().scan_yara(self.maldir)
#
#     def qurantine_file_via_b64(self):
#         with open(f'{self.maldir}/{self.filevir}', 'rb' ) as  vir:
#             virus=base64.b64encode(vir.read())
#         print(virus)


# if __name__ == "__main__":
# myScanner = Scanner()
# myScanner.filetoscan = "../../test/test.txt"
# myScanner.directorytoscan = "../../test"
# res = myScanner.scan_hash("../../test/test.txt")
# print(res)
# myScanner.scan_yara()
# Scanner.__exit__(myScanner)
# mal_file = myScanner.scan_yara(Directorytoscan=Directorytoscan)
# print(mal_file)
# print(path.abspath(mal_file))
# # File_Scanner.__exit__(myScanner)
# directoryOfmal = path.dirname(mal_file)
# print(directoryOfmal)
# quarant = Quarantine(Directorytoscan,filetoscan)
# quarant.qurantine_file_via_b64()
