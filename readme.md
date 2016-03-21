# CRYPTOGRAPHY TOOL
Tool to encrypt and decrypt files based on https://cryptography.io.

## Installation  
```bash
sudo pip install cryptography
```

## RSA keys with PEM encoding genereation  
```bash
python rsa_keygen_tool.py
```

## File encryption
```bash
python rsa_crypto_tool.py --action=encrypt
```
The image ./to_encrypt/lena512.pgm will be encrypted as enc_lena.pgm inside the folder./encrypted/

## File decryption
```bash
python rsa_crypto_tool.py --action=decrypt
```
The encrypted image ./encrypted/enc_lena.pgm will be decrypted as dev_lena.pgm inside the folder ./decrypted.

## File comparison
```bash
python rsa_crypto_tool.py --action=compare
```
The decrypted image ./decrypted/dev_lena.pgm and original file ./to_encrypt/lena512.pgm will be compared.


## Licence
Apache License Version 2.0, January 2004 http://www.apache.org/licenses/
