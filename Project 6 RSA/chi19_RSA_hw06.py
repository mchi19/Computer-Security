#!/usr/bin/env python3.4

### Author: Max Chi
### ECN: chi19
### HW: 06
### File: chi_RSA_hw06.py
### Due Date: 2/22/2018

import sys
import os
import random
from BitVector import *
from PrimeGenerator import *

def RSA_encrypt(f_in, pubKey):
    #pubKey, privKey = gen_keys()
    e = pubKey[0]
    n = pubKey[1]
    #d = privKey[0]
    #p = privKey[2]
    #q = privKey[3]
    f = open("output.txt", "wb")
    f_hex = open("encrypted_hex.txt", "w")
    #file_check(f_in)
    bv = BitVector(filename=f_in)
    #print(e)
    #print(n)
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)
        while (len(bitvec) < 128):
            bitvec += BitVector(textstring="\n")
        #bitvec.pad_from_right(128 - len(bitvec))
        bitvec.pad_from_left(128)
        C = pow(int(bitvec), e, n)
        encrypted = BitVector(intVal = C, size = 256)
        encrypted.write_to_file(f)
        f_hex.write(encrypted.get_hex_string_from_bitvector())
    f.close()
    return

def RSA_decrypt(f_in, privKey):
    #pubKey, privKey = gen_keys()
    #e = pubKey[0]
    n = privKey[1]
    d = privKey[0]
    p = privKey[2]
    q = privKey[3]
    f = open("decrypted.txt", "wb")
    f_hex = open("decrypted_hex.txt", "w")
    bv = BitVector(filename = f_in)
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(256)
        D = CRT(bitvec, d, n, p, q)
        D_unpadded = BitVector(intVal = D, size = 256)[128:]
        D_unpadded.write_to_file(f)
        f_hex.write(D_unpadded.get_hex_string_from_bitvector())
    f.close()
    return
'''
def file_check(f1):
    with open (f1, "r") as f:
        contents = f.readlines()[0]
    #print(contents)
    tlen = (len(contents) * 8) % 128
    print(tlen)
    if tlen > 0:
        tlen = (128 - tlen) / 8
        with open(f1, 'a') as f:
            while tlen > 0:
                f.write('\n')
                tlen -= 1
'''    
def gen_keys(e):
    #e = 65537
    pg = PrimeGenerator(bits=128) #prime generator
    while True:
        p = pg.findPrime()
        q = pg.findPrime()
        p_gcd = gcd(p - 1, e)
        q_gcd = gcd(q - 1, e)
        p_msb1 = bin(p)[2:][0]
        p_msb2 = bin(p)[2:][1]
        q_msb1 = bin(q)[2:][0]
        q_msb2 = bin(q)[2:][1]
        if p != q and p_gcd == 1 and q_gcd == 1 and p_msb1 == '1' and p_msb2 == '1' and q_msb1 == '1' and q_msb2 == '1':
            break
    n = p * q
    tot_n = (p-1) * (q-1)
    bv1 = BitVector(intVal = tot_n)
    bv2 = BitVector(intVal = e)
    d = bv2.multiplicative_inverse(bv1)
    publicKey = [e,n]
    privateKey = [int(d), n, p, q]
    return publicKey, privateKey

def gcd(a,b):
    while b:
        a, b = b, a % b
    return a

### Chinese Remainder Theorem referenced from Professor Kak's Lecture 12.5 notes ###
### C denotes the current encrypted int ###
### Mainly used for RSA decryption ###
def CRT(C, d, n, p, q):
    Vp = pow(int(C), d, p)#int(C)^d % p
    Vq = pow(int(C), d, q)#d % q
    bvq = BitVector(intVal = q)
    bvp = BitVector(intVal = p)
    mi_q = bvq.multiplicative_inverse(bvp)
    mi_p = bvp.multiplicative_inverse(bvq)
    Xp = q * int(mi_q)
    Xq = p * int(mi_p)
    return (Vp*Xp + Vq*Xq) % n

if __name__ == "__main__":
    #file_check("message.txt")
    e = 65537
    #pubKey, privKey  = gen_keys(e)
    #print(pubKey)
    #print(privKey)
    #print(pubKey)
    #print(privKey)
    #pubKey = [65537, 86884724906634867421762202837842202577832955703454796709853446628245451315429]
    #privKey = [1525921515594804956016422714899314511900160772291257421200068896378129281505, 86884724906634867421762202837842202577832955703454796709853446628245451315429, 257092070808209240557244645847950270873, 337951787596945754970471954653401372973]
    
    if (sys.argv[1] == "-e" or sys.argv[1] == "-d") and len(sys.argv) == 4:
        x = sys.argv[1]
        y = sys.argv[2]
        z = sys.argv[3]
        #print(x)
        #print(y)
        #print(z)
        ### run encryption
        if x == "-e":
            if os.path.exists(z):
                os.remove(z)
            if os.path.exists("encrypted_hex.txt"):
                os.remove("encrypted_hex.txt")
            if os.path.exists("keys.txt"):
                os.remove("keys.txt")
            pubKey, privKey = gen_keys(e)
            f_k = open("keys.txt","w")
            for x in pubKey:
                f_k.write(str(x))
                f_k.write('\n')
            for x in privKey:
                f_k.write(str(x))
                f_k.write('\n')
            RSA_encrypt(y, pubKey)
            print("n = ",pubKey[1])
        ### run decryption
        else:# if x == "-d":
            if os.path.exists(z):
                os.remove(z)
            if os.path.exists("decrypted_hex.txt"):
                os.remove("decrypted_hex.txt")
            with open("keys.txt", "r") as tf:
                contents = tf.readlines()
            privKey = []
            for x in range(4):
                privKey.append(int(contents[x+2].strip()))
            RSA_decrypt(y, privKey)
            print("p:",privKey[2])
            print("q:",privKey[3])
            print("d:",privKey[0])
    else:
        print("Please input the one of the following:")
        print("Lastname_RSA_hw06.py -e message.txt output.txt")
        print("or")
        print("Lastname_RSA_hw06.py -d output.txt decrypted.txt")
        sys.exit()

