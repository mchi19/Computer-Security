#!/usr/bin/env python3.4

### Author: Max Chi
### ECN: chi19
### HW: 06
### File: chi_breakRSA_hw06.py
### Due Date: 2/22/2018

import sys
import os
from math import floor
from BitVector import *
from PrimeGenerator import *
from chi19_RSA_hw06 import *
from solve_pRoot import *

def encrypt(f1, pubKeyList):
    encL = ["enc0.txt", "enc1.txt", "enc2.txt"] #list of files to be encrypted message.txt, encrypted message 0, encrypted message 1
    enHexL = ["ehex0.txt", "ehex1.txt", "ehex2.txt"] # list of encrypted hex files
    for i in range(3):
        print("n",i,":",pubKeyList[i][1])
        f = open(encL[i],"wb")
        f_hex = open(enHexL[i], "w")
        bv = BitVector(filename=f1)
        while(bv.more_to_read):
            bitvec = bv.read_bits_from_file(128)
            while(len(bitvec) < 128):
                bitvec += BitVector(textstring='\n')
            bitvec.pad_from_left(128)
            C = pow(int(bitvec), pubKeyList[i][0], pubKeyList[i][1])
            encrypted = BitVector(intVal=C, size=256)
            encrypted.write_to_file(f)
            f_hex.write(encrypted.get_hex_string_from_bitvector())
        f.close()
    return

###modified chinese remainder theorem for breaking the RSA algorithm###
def CRT_break(bv0, bv1, bv2, privKeyList):
    N = int(privKeyList[0][1]) * int(privKeyList[1][1]) * int(privKeyList[2][1])
    N0 = floor(N / privKeyList[0][1])
    N1 = floor(N / privKeyList[1][1])
    N2 = floor(N / privKeyList[2][1])
    bvN0 = BitVector(intVal=N0)
    bvN1 = BitVector(intVal=N1)
    bvN2 = BitVector(intVal=N2)
    bv_n0 = BitVector(intVal=privKeyList[0][1]) #n value for privKey0
    bv_n1 = BitVector(intVal=privKeyList[1][1]) #n value for privKey1
    bv_n2 = BitVector(intVal=privKeyList[2][1]) #n value for privKey2
    MI0 = bv_n0.multiplicative_inverse(bvN0) 
    MI1 = bv_n1.multiplicative_inverse(bvN1)
    MI2 = bv_n2.multiplicative_inverse(bvN2)
    res = ((bv0 * N0 * int(MI0)) + (bv1 * N1 * int(MI1)) + (bv2 * N2 * int(MI2))) % N
    return res

def RSA_break(f1, f2):
    pub1, priv1 = gen_keys(3)
    pub2, priv2 = gen_keys(3)
    pub3, priv3 = gen_keys(3)
    pubL = [pub1, pub2, pub3]
    privL = [priv1, priv2, priv3]
    f_hex = open("cracked_hex.txt", "w")
    f = open(f2, "wb")
    encrypt(f1, pubL)
    #encL = ["enc0.txt", "enc1.txt", "enc2.txt"]
    bv0 = BitVector(filename="enc0.txt")
    bv1 = BitVector(filename="enc1.txt")
    bv2 = BitVector(filename="enc2.txt")
    while (bv0.more_to_read):
        bitvector0 = bv0.read_bits_from_file(256)
        bitvector1 = bv1.read_bits_from_file(256)
        bitvector2 = bv2.read_bits_from_file(256)
        D = CRT_break(int(bitvector0), int(bitvector1), int(bitvector2), privL)
        ###calling this solve_pRoot() function takes forever, only sometimes outputs but usually takes forever and sometimes doesn't terminate
        D_rt = solve_pRoot(3, D)
        D_unpadded = BitVector(intVal=D_rt, size=256)[128:]
        D_unpadded.write_to_file(f)
        f_hex.write(D_unpadded.get_hex_string_from_bitvector())
    f.close()
    return

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Please input the following command: Lastname_break_RSA_hw06.py message.txt cracked.txt")
        sys.exit()
    else:
    #print(gen_keys())
        f1 = sys.argv[1]
        #print(f1)
        f2 = sys.argv[2]
        #print(f2)
        RSA_break(f1, f2)
