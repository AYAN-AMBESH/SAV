import base64
import sqlite3
import hashlib
import yara
from os import walk, path, remove
import sys


class sav:
    
    db_path = "../Database/hash.db"
    rule_file="../test/test.yar"
    hash_list=""

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
            print("Files not accessible")
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

    def scan_hash(self, path_to_be_checked)->dict:

        global malware_hashes
        if not path.exists(path_to_be_checked):
            print("invalid path")
            self.__exit__()
        
        files_to_be_checked = {}
        for root, _, files in walk(path_to_be_checked, followlinks=False):
            for filename in files:
                current_file = path.join(root, filename)
                files_to_be_checked[path.abspath(current_file)] = self.convert_to_sha256(path.abspath(current_file))

        if not self.hash_list:
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
            for key in files_to_be_checked:
                print("scanning ", path.abspath(key))
                if files_to_be_checked[key] in malware_hashes_list:
                    result[path.abspath(key)] = files_to_be_checked[key]
            return result

        elif self.hash_list:
            result = {}
            malware_hashes_list = list(open(self.hash_list, "r").read().split("\n"))
            for key in files_to_be_checked:
                if files_to_be_checked[key] in malware_hashes_list:
                    result[path.abspath(key)] = files_to_be_checked[key]
            return result            

    def scan_yara(self, path_to_be_checked)->dict:
        if not path.exists(self.rule_file):
            print("invalid rule file path")
            self.__exit__()
        if not path.exists(path_to_be_checked):
            print("invalid directory path")
            self.__exit__()

        rules = yara.compile(filepath=self.rule_file)
        result = {}
        for root, _, files in walk(path_to_be_checked, followlinks=False):
            for filename in files:
                current_file = path.join(root, filename)
                print("scanning ", path.abspath(current_file))
                matches = rules.match(current_file, fast=True, )
                if matches:
                    result[path.abspath(current_file)] = matches[0]
        return result

    def qurantine_file_via_b64(self,result_file:dict={}):

        for key in result_file:
            
            tmp = path.basename(key)
            file_name=path.splitext(tmp)[0]
            file_dir= path.dirname(key)
            
            with open(key,'rb') as vir:
                virus = base64.b64encode(vir.read())
            
            with open(f'{file_dir}/quarantine_{file_name}.txt','w') as virw:
                virw.write(str(virus))

        self.file_remove(result_file)
    
    def __exit__(self):
        self.conn.close()
        sys.exit()
