import os
from sys import exit

def ExtractHeader(file):
    """
    Extract the header information from an encrypted file. Parses the salt, IV and mode of operation. CBC = 1, CTR = 2, OFB = 3
    Input: Filename (Absolute path recommended)
    Output: Array of salt, IV, mode of operation code
    """
    CBChash = "03872ff57deb958f37678ed016fb340709bbeb4deba111ca518ddc8f064c0ddd"
    CTRhash = "2d676e12555bcd4e155538681b165af6b494cc9cbff16adb27ad4533592a51b4"
    OFBhash = "2e4146a86c183223f533d4ad39eed6d6280795e354279a65555944648d899112"

    with open(file, 'rb') as f:
        header = f.read(64)

    # Parse the header information
    salt = header[:16]
    iv = header[16:32]
    hash = header[32:64]

    if hash.hex() != CBChash and hash.hex() != CTRhash and hash.hex() != OFBhash:
        print("Error: Incorrect mode of operation in header")
        exit(2)
    elif hash.hex() == CBChash:
        return [salt, iv, 1]
    elif hash.hex() == CTRhash:
        return [salt, iv, 2]
    else:
        return [salt, iv, 3]

def SecureDelete(path, passes=1):
    """
	Secure delete original plaintext file function.
 	Input: File path
	Output: 1 on success
	"""
    with open(path, "ba+") as delfile:
        length = delfile.tell()
    with open(path, "br+") as delfile:
        for i in range(passes):
            delfile.seek(0)
            delfile.write(os.urandom(length))
    os.remove(path)
    return 1

