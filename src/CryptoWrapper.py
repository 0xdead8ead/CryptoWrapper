#!/usr/bin/env python

'''

Python Crypto Wrapper - By Chase Schultz

Currently Supports: AES-256, RSA Public Key, RSA Signing

Dependencies: pyCrypto - https://github.com/dlitz/pycrypto


Python Cryptography Wrapper based on pyCrypto
    Copyright (C) 2011  Chase Schultz - chaschul@uat.edu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


'''

__author__ = 'Chase Schultz'
__version__ = '0.1'

import os
import base64
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


class CryptoWrapper():

    '''AES Cipher Specifics'''
    blockSize = 16          #Block Size
    keySize = 32            #keySize in Bytes - 32 bytes = 256bit Encryption
    mode = AES.MODE_CBC     #Cipher Block Mode
    
    def __init__(self):
        
        pass

    def __generateAESKeystring__(self):
        '''Generates Pseudo Random AES Key and Base64 Encodes Key - Returns AES Key'''
        key = os.urandom(self.keySize)
        keyString = base64.urlsafe_b64encode(str(key))
        return keyString
        
    def __extractAESKey__(self, keyString):
        '''Extracts Key from Base64 Encoding'''
        key = base64.urlsafe_b64decode(keyString)
        if len(key) != self.keySize:
            raise Exception('Error: Key Invalid')
            os._exit(1)
        return key
    
    def __extractCrypto__(self, encryptedContent):
        '''Decodes Base64 Encoded Crypto'''
        cipherText = base64.urlsafe_b64decode(encryptedContent)
        return cipherText
    
    def __encodeCrypto__(self, encryptedContent):
        '''Encodes Crypto with Base64'''
        encodedCrypto = base64.urlsafe_b64encode(str(encryptedContent))
        return encodedCrypto
    
    def aesEncrypt(self, data):
        '''Encrypts Data w/ pseudo randomly generated key and base64 encodes cipher - Returns Encrypted Content and AES Key'''
        key = self.__generateAESKeystring__()
        encryptionKey = self.__extractAESKey__(key)
        pad = self.blockSize - len(data) % self.blockSize
        data = data + pad * chr(pad)
        iv = os.urandom(self.blockSize)
        cipherText = AES.new(encryptionKey, self.mode, iv).encrypt(data)
        encryptedContent = iv + cipherText
        encryptedContent = self.__encodeCrypto__(encryptedContent)
        return encryptedContent, key

    def aesDecrypt(self, key, data):
        '''Decrypts AES(base64 encoded) Crypto - Returns Decrypted Data'''
        decryptionKey = self.__extractAESKey__(key)
        encryptedContent = self.__extractCrypto__(data)
        iv = encryptedContent[:self.blockSize] 
        cipherText = encryptedContent[self.blockSize:]
        plainTextwithpad = AES.new(decryptionKey, self.mode, iv).decrypt(cipherText)
        pad = ord(plainTextwithpad[-1])
        plainText = plainTextwithpad[:-pad]
        return plainText
    
    def generateRSAKeys(self,keyLength):
        '''Generates Public/Private Key Pair - Returns Public / Private Keys'''
        private = RSA.generate(keyLength)
        public  = private.publickey()
        privateKey = private.exportKey()
        publicKey = public.exportKey()
        return privateKey, publicKey
    
    def rsaPublicEncrypt(self, pubKey, data):
        '''RSA Encryption Function - Returns Encrypted Data'''
        publicKey = RSA.importKey(pubKey)
        encryptedData = publicKey.encrypt(data,'')
        return encryptedData
         
    def rsaPrivateDecrypt(self, privKey, data):
        '''RSA Decryption Function - Returns Decrypted Data'''
        privateKey = RSA.importKey(privKey)
        decryptedData = privateKey.decrypt(data)
        return decryptedData
    
    def rsaSign(self, privKey, data):
        '''RSA Signing - Returns an RSA Signature'''
        privateKey = RSA.importKey(privKey)
        if privateKey.can_sign() == True:
            digest = SHA256.new(data).digest()
            signature = privateKey.sign(digest,'')
            return signature
        else:
            raise Exception("Error: Can't Sign with Key")
        
    def rsaVerify(self, pubKey, data, signature):
        '''Verifies RSA Signature based on Data received - Returns a Boolean Value'''
        publicKey = RSA.importKey(pubKey)  
        digest = SHA256.new(data).digest()
        return publicKey.verify(digest, signature)

            
if __name__ == '__main__':
    '''Usage Examples'''
    
    print '''

            Python Crypto Wrapper - By Chase Schultz
            
            Currently Supports: AES-256, RSA Public Key, RSA Signing
            
            Dependencies: pyCrypto - https://github.com/dlitz/pycrypto
            
            
            '''
      
    '''Instantiation of Crypto Wrapper and Message'''
    crypto = CryptoWrapper();
    message = 'Crypto Where art Thou... For ye art a brother...'
    print 'Message to be Encrypted: %s\n' % message
    
    
    '''AES ENCRYPTION USAGE'''
    '''***Currently Supporting AES-256***'''
    encryptedAESContent, key = crypto.aesEncrypt(message)
    print 'Encrypted AES Message: %s\nEncrypted with Key: %s' % (encryptedAESContent, key)
    decryptedAESMessage = crypto.aesDecrypt(key, encryptedAESContent)
    print '\nDecrypted AES Content: %s\n' %  decryptedAESMessage


    '''RSA ENCRYPTION USAGE'''
    privateKey, publicKey = crypto.generateRSAKeys(2048)
    encryptedRSAContent = crypto.rsaPublicEncrypt(publicKey, message)
    print 'Encrypted RSA Message with Public Key: %s\n' % encryptedRSAContent
    decryptedRSAMessage = crypto.rsaPrivateDecrypt(privateKey, encryptedRSAContent)
    print '\nDecrypted RSA Content with Private Key: %s\n' %  decryptedRSAMessage
    
    
    '''RSA SIGNING USAGE'''
    signature = crypto.rsaSign(privateKey, message)
    print 'Signature for message is: %s\n ' % signature
    if crypto.rsaVerify(publicKey, message, signature) is False:
        print 'Could not Verify Message' 
    else:
        print 'Verified Content'
    