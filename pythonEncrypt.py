import os, sys, argparse
import modules.AES256, modules.auxiliary

def getArgs(argv=None):
    """
    Argument parser function. Returns the namespace of the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog = "pythonEncrypt.py",
        description='Python utility to encrypt or decrypt files.'
        )
    parser.add_argument("-f", "--file", help="File to perform action on", required=True)
    parser.add_argument("-m", "--mode", help="Select mode for encryption, default CBC (CBC, CTR, OFB)", nargs="?", type=str, default="CBC")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--encrypt", help="Encrypt the file", action="store_true")
    group.add_argument("-d", "--decrypt", help="Decrypt the file", action="store_true")

    if len(sys.argv) < 2:
        parser.print_usage()
        sys.exit(2)

    args = parser.parse_args()
    if args.mode != "CBC" and args.mode != "CTR" and args.mode != "OFB":
        print("Error: Invalid mode of operation!")
        sys.exit(2)

    return parser.parse_args(argv)

if __name__ == "__main__":
    args = getArgs()

    if os.path.isfile(args.file):
        # Valid file given
        if args.encrypt and args.mode == "CBC":
            print("Encrypting file: {}".format(args.file))
            modules.AES256.AesCBCencrypt(os.path.abspath(args.file))
            modules.auxiliary.SecureDelete(os.path.abspath(args.file))
        elif args.encrypt and args.mode == "CTR":
            print("Encrypting file: {}".format(args.file))
            modules.AES256.AesCTRencrypt(os.path.abspath(args.file))
            modules.auxiliary.SecureDelete(os.path.abspath(args.file))
        elif args.encrypt and args.mode == "OFB":
            modules.AES256.AesOFBencrypt(os.path.abspath(args.file))
            modules.auxiliary.SecureDelete(os.path.abspath(args.file))
        elif args.decrypt:
            print("Decrypting file: {}".format(args.file))
            modules.AES256.AesDecrypt(os.path.abspath(args.file))
    else:
        print("Error: File {} could not be found!".format(args.file))
        sys.exit(2)