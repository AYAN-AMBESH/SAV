from sav import sav
import argparse


if __name__ == "__main__":
    print("           _____ ___ _    __         ")
    print("          / ___//   | |  / /         ")
    print("          \__ \/ /| | | / /          ")
    print("         ___/ / ___ | |/ /           ")
    print("        /____/_/  |_|___/            ")
    print("            Version 1.0              ")
    print("     A project by Ayush & Ayan       ")

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", type=int, choices=[1, 2],help="mode 1 = hash scan \n mode 2 = yara scan")
    parser.add_argument("-d", "--directory", help="directory",metavar='')
    parser.add_argument("-yR", "--yararules", help="yararules",metavar='')
    parser.add_argument("-hL", "--hashlist", help="hashlist",metavar='')
    args = parser.parse_args()

    if (args.directory is None) or (args.mode is None):
        print("   main.py --help to get started ")
        quit()

    mysav = sav()
    if args.mode == 1:
        if args.hashlist:
            mysav.hash_file = args.hashlist
        res = mysav.scan_hash(args.directory)
        if res:
            for key in res:
                print(f"Malware found: {key}")
            choice = input("Do you want to quarantine and remove file(s)?(y/n)")
            if choice == "y" or choice == "Y":
                mysav.qurantine_file_via_b64(res)
            else:
                pass
        else:
            print("No malicious found")
    elif args.mode == 2:
        if args.yararules:
            mysav.rule_fule = args.yararules
        res = mysav.scan_yara(args.directory)
        if res:
            for key in res:
                print(f"Malware found: {key}")
            choice = input("Do you want to quarantine and remove file(s)?(y/n)")
            if choice == "y" or choice == "Y":
                mysav.qurantine_file_via_b64(res)
            else:
                pass
        else:
            print("No malicious found")


