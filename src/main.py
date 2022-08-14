from sav import sav
import argparse


if __name__ == "__main__":
    print("           _____ ___ _    __         ")
    print("          / ___//   | |  / /         ")
    print("          \__ \/ /| | | / /          ")
    print("         ___/ / ___ | |/ /           ")
    print("        /____/_/  |_|___/            ")
    print("            Version 1.0             ")
    print("     A project by Ayush & Ayan            ")

    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mode", type=int, choices=[1, 2],help="mode 1 = hash scan \n mode 2 = yara scan")
    parser.add_argument("-d", "--directory", help="directory")
    parser.add_argument("-y", "--yararules", help="yararules")
    parser.add_argument("-h", "--hashlist", help="hashlist")
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
            choice = input("Do you want to quarantine file(s)?(y/n)")
            if choice == "y" or choice == "Y":
                mysav.qurantine_file_via_b64(res)
            else:
                pass
    elif args.mode == 2:
        if args.yararules:
            mysav.rule_fule = args.yararules
        res = mysav.scan_yara(args.directory)
        choice = input("Do you want to quarantine file(s)?(y/n)")
        if choice == "y" or choice == "Y":
            mysav.qurantine_file_via_b64(res)
        else:
            pass


