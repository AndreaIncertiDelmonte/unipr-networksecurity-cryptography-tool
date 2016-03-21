#!/usr/bin/env python
"""
Provides API to crypt and decrypt files
"""
import os
import re
import sys
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

from cryptography.fernet import Fernet

__author__ = "Andrea Incerti Delmonte"
__email__ = "andrea.incertidelmonte@studenti.unipr.it"

class RSACryptoTool(object):
      
    # Constructor
    def __init__(self):
        self._backend = default_backend()

        
    def encrypt(self, file_path, enc_file_path, dest_public_key_path, src_private_key_path, src_private_key_pass):

        # Load dest public key
        dest_public_key = self._load_public_key_from_file(dest_public_key_path)

        # Generate random symmetric key
        sym_random_key = Fernet.generate_key()

        # Encrypt symmetric key with destination public key
        sym_random_key_encrypted = dest_public_key.encrypt(
             sym_random_key,
             padding.OAEP(
                 mgf=padding.MGF1(algorithm=hashes.SHA1()),
                 algorithm=hashes.SHA1(),
                 label=None
            )
        )

        # Load file to encrypt content
        message = self._read_file(file_path)

        # Load src private key
        src_private_key = self._load_private_key_from_file(src_private_key_path, src_private_key_pass)

        # Sign message
        signer = src_private_key.signer(
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )        
        signer.update(message)
        message_signature = signer.finalize()
                
        # Encrypt file content with symmetric cryptograpy
        fernet = Fernet(sym_random_key)
        message_encrypted = fernet.encrypt(message)

        # Encrypted file content composition
        enc_file_header = """<head><skey>{0}</skey><sign>{1}</sign></head>""".format(sym_random_key_encrypted, message_signature)
        enc_file_body = """<body>{0}</body>""".format(message_encrypted)       
        enc_file_payload = """{0}{1}""".format(enc_file_header, enc_file_body)

        # Write encrypted file
        self._write_file(enc_file_path,enc_file_payload)

        print ("Encrypted file: {0}".format(enc_file_path)       )


    def decrypt(self, enc_file_path, dec_file_path, dest_private_key_path, dest_private_key_pass, src_public_key_path):

        # Read encrypted file
        enc_file_payload = self._read_file(enc_file_path)

        # Extract file parts
        file_header, file_body = self._extract_file_parts(enc_file_payload)

        # Extract file header parts
        sym_key_encypted, message_signature = self._extract_header_parts(file_header)

        # Load dest private key
        dest_private_key = self._load_private_key_from_file(dest_private_key_path, dest_private_key_pass)

        # Decrypt symmetric key with private key
        sym_random_key_decrypted = dest_private_key.decrypt(
            sym_key_encypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        # Decrypt file message
        fernet = Fernet(sym_random_key_decrypted)
        dec_message = fernet.decrypt(file_body)

        # Load src public key
        src_public_key = self._load_public_key_from_file(src_public_key_path)

        verifier = src_public_key.verifier(
            message_signature,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        verifier.update(dec_message)
        
        try:
            verifier.verify()
            print ("File signature verification seccess!!!")

            # Write decrypted data to file
            self._write_file(dec_file_path, dec_message)

            print ("Decrypted file: {0}".format(dec_file_path))
        except:
            print ("File signature verification failed")

       
    def compare_files(self, first_file_path, second_file_path):

        first_file_payload = self._read_file(first_file_path)
        second_file_payload = self._read_file(second_file_path)

        return first_file_payload == second_file_payload


    def _read_file(self, file_path):

        f = open(file_path, 'r')
        f_data = f.read()
        f.close()
        return f_data


    def _write_file(self, file_path, file_data):

        f = open(file_path, 'w')
        f.write(file_data)
        f.close()


    def _load_public_key_from_file(self, public_key_path):

        public_key_data = self._read_file(public_key_path)
       
        public_key = serialization.load_pem_public_key(
            data = public_key_data, 
            backend = self._backend)

        return public_key


    def _load_private_key_from_file(self, private_key_path, private_key_pass):

        private_key_data = self._read_file(private_key_path)

        private_key = serialization.load_pem_private_key(
            data = private_key_data, 
            password = private_key_pass,
            backend = self._backend
        )

        return private_key


    def _extract_file_parts(self, file_payload):

        header = self._extract_tag_content(file_payload, "<head>", "</head>")
        body = self._extract_tag_content(file_payload, "<body>", "</body>")
        return header, body


    def _extract_header_parts(self, header_payload):

        skey = self._extract_tag_content(header_payload, "<skey>", "</skey>")
        signaure = self._extract_tag_content(header_payload, "<sign>", "</sign>")
        return skey, signaure


    def _extract_tag_content(self, data, tag_start_delimiter, tag_end_delimiter):

        try:
            tag_start = data.index( tag_start_delimiter ) + len( tag_start_delimiter )
            tag_end = data.index( tag_end_delimiter, tag_start )
            
            return data[tag_start:tag_end]
        except ValueError:
            return ""


if __name__ == '__main__':    

    parser = argparse.ArgumentParser(description='RSA Crypto tool')
    parser.add_argument('--action', 
                       help='Action to be executed [encrypt, decrypt, compare]')
    

    args = parser.parse_args()    
    action =  args.action

    rsa_crypto = RSACryptoTool()

    file_path = "./to_encrypt/lena512.pgm"
    enc_file_path = "./encrypted/enc_lena512.pgm"
    dec_file_path = "./decrypted/dec_lena512.pgm" 


    if action == "encrypt":

        print ("Encrypt file: {0}".format(file_path))

        rsa_crypto.encrypt(
            file_path = file_path,
            enc_file_path = enc_file_path, 
            dest_public_key_path = "./keys/bob_ns_key_pair.pub",
            src_private_key_path = "./keys/alice_ns_key_pair",
            src_private_key_pass = "alice_pwd"
        )

    elif action == "decrypt":

        print ("Decrypt file: {0}".format(enc_file_path))

        rsa_crypto.decrypt(
            enc_file_path = enc_file_path,
            dec_file_path = dec_file_path, 
            dest_private_key_path = "./keys/bob_ns_key_pair",
            dest_private_key_pass = "bob_pwd",
            src_public_key_path = "./keys/alice_ns_key_pair.pub",        
        )

    elif action == "compare": 

        print ("Compare file {0} with {1}".format(file_path,dec_file_path))

        result = rsa_crypto.compare_files(
            first_file_path = file_path,
            second_file_path = dec_file_path, 
        )

        if result:
            print ("Files are equal")
        else:
            print ("Files are different")
    else:
        print ("Wrong action selected!!!")
        print ("Use [encrypt, decrypt, compare]")
    