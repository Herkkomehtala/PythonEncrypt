# PythonEncrypt

Python3 solution to perform AES256 file encryption/decryption with key derivation. 

## Installation

1. Install [Cryptography library](https://cryptography.io/en/latest/) for python.
- With pip:  ```pip install cryptography```  

2. Clone this repository or download the latest release of PythonEncrypt to your machine.  
3. Run ```PythonEncrypt.py```

## Usage

PythonEnrypt supports AES256 file encryption/decryption with the following modes: ```CBC, CTR, OFB``` . You can select the mode with the ```--mode``` flag.  
Print program usage with the flag ```-h```  

To encrypt a file with the default CBC mode, run command:  
```PythonEncrypt.py --file <File> --encrypt```  
To decrypt a file, run command:  
```PythonEncrypt.py --file <File> --decrypt```  

## Security

<span style="color:red">This program is **ONLY** for low-security uses.</span> This tool is not NIST SP 800-57 or FIPS 140 compliant. There are a few reasons for this, most importantly the cryptographic keys are not held in tamper proof memory and there aren't adequate cryptographic boundaries. This tool is made to protect against your snoopy co-worker or that cousin you have.

There won't be updates to address this issue. This is due to Python being a poor choice for creating high security cryptograhic modules. To find out why, you can read up [here](https://stackoverflow.com/questions/728164/securely-erasing-password-in-memory-python).

