from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import modules.keyDerivation, modules.auxiliary
import os, hashlib

def AesCBCencrypt(file):
    """
    Performs AES CBC Encryption with 256 bit key to a file and outputs the ciphertext into a new file.
    Input: Filename (Absolute path recommended)
    Output: 1 on success.
    """
    Blocksize_bytes, Blocksize_bits = 16, 128
    ofile = file + ".enc"
    iv = os.urandom(Blocksize_bytes)
    hash = hashlib.sha256(b'AesCBC').digest()

    # Derive the key from password
    KeyandSalt = modules.keyDerivation.DeriveKey()

    # Read the plaintext
    with open(file, "rb") as reader: 
        plaintext = reader.read()

    # Do the padding and encrypt data
    padder = padding.PKCS7(Blocksize_bits).padder()
    plaintext = padder.update(plaintext) + padder.finalize()
    aesCipher = Cipher(algorithms.AES256(KeyandSalt[0]), modes.CBC(iv), default_backend())
    aesEncryptor = aesCipher.encryptor()
    ciphertext = aesEncryptor.update(plaintext) + aesEncryptor.finalize()

    # Create encrypted file
    with open(ofile, "wb+") as writer:
        writer.write(KeyandSalt[1] + iv + hash + ciphertext)    # Variables salt + IV + hash are required for decryption

    print('Success! Encrypted file at: %s' % ofile)
    return 1

def AesCTRencrypt(file):
    """
    Performs AES CTR Encryption with 256 bit key to a file and outputs the ciphertext into a new file.
    Input: Filename (Absolute path recommended)
    Output: 1 on success.
    """
    Blocksize_bytes, Blocksize_bits = 16, 128
    ofile = file + ".enc"
    nonce = os.urandom(Blocksize_bytes)
    hash = hashlib.sha256(b'AesCTR').digest()

    # Derive the key from password
    KeyandSalt = modules.keyDerivation.DeriveKey()

    # Read the plaintext
    with open(file, "rb") as reader: 
        plaintext = reader.read()

    # Do the padding and encrypt data
    padder = padding.PKCS7(Blocksize_bits).padder()
    plaintext = padder.update(plaintext) + padder.finalize()
    aesCipher = Cipher(algorithms.AES256(KeyandSalt[0]), modes.CTR(nonce), default_backend())
    aesEncryptor = aesCipher.encryptor()
    ciphertext = aesEncryptor.update(plaintext) + aesEncryptor.finalize()

    # Create encrypted file
    with open(ofile, "wb+") as writer:
        writer.write(KeyandSalt[1] + nonce + hash + ciphertext)    # Variables salt + nonce + hash are required for decryption

    print('Success! Encrypted file at: %s' % ofile)
    return 1

def AesOFBencrypt(file):
    """
    Performs AES OFB Encryption with 256 bit key to a file and outputs the ciphertext into a new file.
    Input: Filename (Absolute path recommended)
    Output: 1 on success.
    """
    Blocksize_bytes, Blocksize_bits = 16, 128
    ofile = file + ".enc"
    iv = os.urandom(Blocksize_bytes)
    hash = hashlib.sha256(b'AesOFB').digest()

    # Derive the key from password
    KeyandSalt = modules.keyDerivation.DeriveKey()

    # Read the plaintext
    with open(file, "rb") as reader: 
        plaintext = reader.read()

    # Encrypt the data, no padding needed
    aesCipher = Cipher(algorithms.AES256(KeyandSalt[0]), modes.OFB(iv), default_backend())
    aesEncryptor = aesCipher.encryptor()
    ciphertext = aesEncryptor.update(plaintext) + aesEncryptor.finalize()

    # Create encrypted file
    with open(ofile, "wb+") as writer:
        writer.write(KeyandSalt[1] + iv + hash + ciphertext)    # Variables salt + iv + hash are required for decryption

    print('Success! Encrypted file at: %s' % ofile)
    return 1

def AesDecrypt(file):
    """
    Decrypts AES256 encrypted file.
    Input: Filename (Absolute path recommended)
    Output: 1 on Success
    """
    Blocksize_bits = 128
    ofile = file[:-4]
    HeaderInfo = modules.auxiliary.ExtractHeader(file)
    KeyandSalt = modules.keyDerivation.DeriveKey(HeaderInfo[0])

    # Get the ciphertext
    with open(file, 'rb') as f:
        f.seek(64)
        ciphertext = f.read()

    # CBC Mode
    if HeaderInfo[2] == 1:
        print("CBC Mode of operation detected...")
        aesCipher = Cipher(algorithms.AES256(KeyandSalt[0]), modes.CBC(HeaderInfo[1]), default_backend())
        aesDecryptor = aesCipher.decryptor()
        paddedData = aesDecryptor.update(ciphertext) + aesDecryptor.finalize()

        unpadder = padding.PKCS7(Blocksize_bits).unpadder()
        plaintext = unpadder.update(paddedData) + unpadder.finalize()

        with open(ofile, "wb+") as writer:
            writer.write(plaintext)

        print("File decrypted succesfully!")

    # CTR Mode
    if HeaderInfo[2] == 2:
        print("CTR Mode of operation detected...")
        aesCipher = Cipher(algorithms.AES256(KeyandSalt[0]), modes.CTR(HeaderInfo[1]), default_backend())
        aesDecryptor = aesCipher.decryptor()
        paddedData = aesDecryptor.update(ciphertext) + aesDecryptor.finalize()

        unpadder = padding.PKCS7(Blocksize_bits).unpadder()
        plaintext = unpadder.update(paddedData) + unpadder.finalize()

        with open(ofile, "wb+") as writer:
            writer.write(plaintext)

        print("File decrypted succesfully!")

    # OFB Mode
    if HeaderInfo[2] == 3:
        print("OFB Mode of operation detected...")
        aesCipher = Cipher(algorithms.AES256(KeyandSalt[0]), modes.OFB(HeaderInfo[1]), default_backend())
        aesDecryptor = aesCipher.decryptor()
        plaintext = aesDecryptor.update(ciphertext) + aesDecryptor.finalize()

        with open(ofile, "wb+") as writer:
            writer.write(plaintext)

        print("File decrypted succesfully!")

    return 1
