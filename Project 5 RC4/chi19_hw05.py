#!/usr/bin/env python3.4

### Author: Max Chi
### ECN: chi19
### HW: 05
### File: chi_hw05.py
### Due Date: 2/15/2018

import os

class RC4:
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("Key length must be 128 bits (16 ASCII characters) long")
        self.key = key

    #function to split header and content of img.ppm file
    def rhfi(self, img):
        self.header = []
        self.content = ''
        #with open(img ,'rb') as fp:
        with open(img, "rb") as fp:
            for x in range(3):
                self.header.append(fp.readline())
            self.content = fp.read()
        #self.content = self.content.decode()
            #self.content += fp.readline()
        #print(self.header)
        print(type(self.content))
        #print(self.content[:1])

    #key scheduling algorithm
    def ksa(self): #key scheduling algorithm
        S = [i for i in range(256)]
        T = [0]*256
        for i in range(256):
            T[i] = ord(self.key[i % len(self.key)])
        j = 0
        for i in range(256):
            j = (j + S[i] + T[i]) % 256
            S[i], S[j] = S[j], S[i]
            #temp = S[i]
            #S[i] = S[j]
            #S[j] = temp
        return S

### write bytes back to encrypted
    def encrypt(self, origImg):
        if os.path.exists("encrypted.ppm"):
            os.remove("encrypted.ppm")
        f = open("encrypted.ppm", "w+b")
        encrypted = ""
        self.rhfi(origImg)
        S = self.ksa()
        i = 0
        j = 0
        for x in self.content:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = (S[i] + S[j]) % 256
            encryptedByte = chr(S[k] ^ x)
            encrypted += encryptedByte
        for x in self.header:
            f.write(x)
        #f.write(bytearray(encrypted))
        f.write(encrypted.encode('utf-8'))
        #return encrypted.encode('utf-8')
        return encrypted
        

    def decrypt(self, enImg):
        if os.path.exists("decrypted.ppm"):
            os.remove("decrypted.ppm")
        f = open("decrypted.ppm", "w+b")
        decrypted = ""
        S = self.ksa()
        i = 0
        j = 0
        #for x in enImg.decode():
        #print(type(enImg))
        for x in enImg:
            #print("!!!")
            #print(x)
            #print(ord(x))
            #print(type(x))
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            #temp = S[i]
            #S[i] = S[j]
            #S[j] = temp
            k = (S[i] + S[j]) % 256
            decryptedByte = chr(S[k] ^ ord(x))
            decrypted += decryptedByte
        for x in self.header:
            f.write(x)
        f.write(decrypted.encode('utf-8'))
        return decrypted

if __name__ == "__main__":
    
    rc4Cipher = RC4('todayismonday123')
    
    rc4Cipher.ksa()
    rc4Cipher.rhfi("winterTown.ppm")
    
    originalImage = "winterTown.ppm" #File object with image data only, no header

    #Input is image file object *without* header. Output is file object of encrypted image:
    encryptedImage = rc4Cipher.encrypt(originalImage)
    #print("!!!")
    #Input is encrypted image file object *without* header. Output is file object of decrypted image:
    decryptedImage = rc4Cipher.decrypt(encryptedImage)
    #print(decryptedImage[:10])
    
    #print(originalImage[:10])

    #rc4Cipher.rhfi(originalImage)
    #print(rc4Cipher.content[:20].decode())
    #print(decryptedImage[:20])
    #print(bytes(decryptedImage[:20]).encode("utf-8"))

    with open("1.txt", "wb") as tfile:
        tfile.write(rc4Cipher.content)
    tfile.close()
    #with open("2.txt", "wb") as afile:
    #    afile.write(decryptedImage)
    #afile.close()
    
    #if rc4Cipher.content == decryptedImage: #Pseudocode, won't literally do this
    #    print('RC4 is awesome')
    #else:
    #    print('Hmm, something seems fishy!')

