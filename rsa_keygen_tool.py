#!/usr/bin/env python
"""
Provides API for creating RSA key pair
"""
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

__author__ = "Andrea Incerti Delmonte"
__email__ = "andrea.incertidelmonte@studenti.unipr.it"

class RSAKeyGenTool(object):
    
    # Parameters
    PUBLIC_EXPONENT = 65537  
    KEY_ZIZE = 2048
    
    # Constructor
    def __init__(self):
        
        self._key_folder = "keys/"
        self._publick_key_file_tail = ".pub"
        self._backend = default_backend()

        
    def create_key_pair(self, key_name, private_key_password):

        private_key = self._create_private_key(key_name,private_key_password)

        self._create_public_key(private_key, key_name)


    def _create_private_key(self, key_name,private_key_password):

        private_key = rsa.generate_private_key(
            public_exponent=self.PUBLIC_EXPONENT,
            key_size=self.KEY_ZIZE,
            backend=self._backend
        )
        
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(private_key_password)
        )       

        # File generation
        key_path = self._key_folder + key_name
        private_key_file = open(key_path, 'w')
        private_key_file.write(pem)
        private_key_file.close()

        return private_key


    def _create_public_key(self, private_key, key_name):

        public_key = private_key.public_key()
        
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # File generation
        key_path = self._key_folder + key_name + self._publick_key_file_tail
        public_key_file = open(key_path, 'w')
        public_key_file.write(pem)
        public_key_file.close()


if __name__ == '__main__':

    rsa_keygen = RSAKeyGenTool()

    rsa_keygen.create_key_pair("alice_ns_key_pair","alice_pwd")
    print ("Created Alice's keys")

    rsa_keygen.create_key_pair("bob_ns_key_pair","bob_pwd")
    print ("Created Bob's keys")

    rsa_keygen.create_key_pair("carl_ns_key_pair","carl_pwd")
    print ("Created Carl's keys")
    