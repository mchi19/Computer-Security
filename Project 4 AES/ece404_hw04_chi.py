#!/usr/bin/env python3.4

### Author: Max Chi
### ECN: chi19
### HW: 04
### File: ece404_hw_chi.py
### Due Date: 2/8/2018

import os
import sys
from BitVector import *

AES_modulus = BitVector(bitstring = '100011011') #x^8 + x^4 + x^3 + x + 1
stateArray = [[0 for x in range(4)] for x in range(4)] #used for arranging key in a 4 x 4 box
new_stateArray = [[0 for x in range(4)] for x in range(4)] #used for mixing columns
in_key = 'hackingteamitaly'

def gen_SubBytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(256):
        if (i != 0):
            a = BitVector(intVal = i, size = 8).gf_MI(AES_modulus, 8)
        else:
            a = BitVector(intVal = 0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_InvSubBytes_table():
    invSubBytesTable = []
    d = BitVector(bitstring='00000101')
    for i in range(256):
        b = BitVector(intVal = i, size = 8)
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        if isinstance(check, BitVector):
            b = check
        else:
            b = 0
        invSubBytesTable.append(int(b))
    return invSubBytesTable

def gen_key_schedule(kBV):
    key_schedule = []
    byte_sub_table = gen_SubBytes_table()
    round_num_const = BitVector(intVal = 0x01, size = 8)

    #generates the stateArray for the current key
    for i in range(4):
        for j in range(4):
            stateArray[j][i] = kBV[i*32 + j*8: i*32 + (j+1)*8]
    for i in range(44):
        if (i < 4): ### generates the first 4 words
            w_i = stateArray[0][i] + stateArray[1][i] + stateArray[2][i] + stateArray[3][i]
            key_schedule.append(w_i)
        else: ### generates the remaining 40 words
            if (i % 4) == 0: ### calls function gee() everytime a new set of 4 words is generating
                kwd, round_num_const = gee(key_schedule[i-1], round_num_const, byte_sub_table)
                key_schedule.append(key_schedule[i-4] ^ kwd)
            else:
                key_schedule.append(key_schedule[i-4] ^ key_schedule[i-1])
    return key_schedule
    
### referenced from Professor Kak's Lecture 8
def gee(keyword, round_num_const, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newWord = BitVector(size = 0)
    for i in range(4):
        newWord += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*(i+1)].intValue()], size=8)
    newWord[:8] ^= round_num_const
    round_num_const = round_num_const.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newWord, round_num_const

def encrypt_substitution(bv, subBytesTable):
    [l,r] = bv.divide_into_two()
    row = l.int_val()
    col = r.int_val()
    val = subBytesTable[16*row + col]
    return BitVector(intVal = val, size=8)

def decrypt_substitution(bv, invSubBytesTable):
    [l,r] = bv.divide_into_two()
    row = l.int_val()
    col = r.int_val()
    val = invSubBytesTable[16*row + col]
    return BitVector(intVal = val, size=8)

def AES_encrypt(f1, f2):
    ### get initial key in BitVector form
    #key_BV = get_initial_key()
    key_BV = BitVector(textstring = in_key)
    ### Create the BitVector for the file
    bv = BitVector(filename = f1)
    ### get the key_schedule
    key_schedule = gen_key_schedule(key_BV)
    subBytesTable = []
    subBytesTable = gen_SubBytes_table()
    hex2 = BitVector(hexstring = '02')
    hex3 = BitVector(hexstring = '03')
    if os.path.exists(f2):
        os.remove(f2)
    FILEOUT = open(f2, "a")
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)
        if (len(bitvec) != 128): #checks if it is 128 bits, if not then pads it
            bitvec.pad_from_right(128 - len(bitvec))
        ### XOR with first 4 words from 44 words key_schedule 
        bitvec = bitvec ^ (key_schedule[0] + key_schedule[1] + key_schedule[2] + key_schedule[3])
        ###generate state array
        for i in range(4):
            for j in range(4):
                stateArray[j][i] = bitvec[i*32 + j*8: i*32 + (j+1)*8]
        ### proceed with 10 full rounds of AES
        for round in range(10):
            ### STEP 1: single-byte based substitution
            #print(round)
            for j in range(4):
                for k in range(4):
                    temp = stateArray[j][k]
                    #stateArray[j][k] = BitVector(intVal = subBytesTable[temp])
                    stateArray[j][k] = encrypt_substitution(temp, subBytesTable)
            ### STEP 2: Row-wise permutation
            stateArray[1] = [stateArray[1][1], stateArray[1][2], stateArray[1][3], stateArray[1][0]]
            stateArray[2] = [stateArray[2][2], stateArray[2][3], stateArray[2][0], stateArray[2][1]]
            stateArray[3] = [stateArray[3][3], stateArray[3][0], stateArray[3][1], stateArray[3][2]]

            ### STEP 3: Column-wise mixing
            if round != 9:
                for j in range(4):
                    new_stateArray[0][j] = (hex2.gf_multiply_modular(stateArray[0][j], AES_modulus, 8) ^ hex3.gf_multiply_modular(stateArray[1][j], AES_modulus, 8) ^ stateArray[2][j] ^ stateArray[3][j])
                for j in range(4):
                    new_stateArray[1][j] = (stateArray[0][j] ^ hex2.gf_multiply_modular(stateArray[1][j], AES_modulus, 8) ^ hex3.gf_multiply_modular(stateArray[2][j], AES_modulus, 8) ^ stateArray[3][j])
                for j in range(4):
                    new_stateArray[2][j] = (stateArray[0][j] ^ stateArray[1][j] ^ hex2.gf_multiply_modular(stateArray[2][j], AES_modulus, 8) ^ hex3.gf_multiply_modular(stateArray[3][j], AES_modulus, 8))
                for j in range(4):
                    new_stateArray[3][j] = (hex3.gf_multiply_modular(stateArray[0][j], AES_modulus, 8) ^ stateArray[1][j] ^ stateArray[2][j] ^ hex2.gf_multiply_modular(stateArray[3][j], AES_modulus, 8))
            else: #if it is the final round of of AES encryption
                for i in range(4):
                    for j in range(4):
                        new_stateArray[i][j] = stateArray[i][j]
            
            ### STEP 4: Addition of the round key
            key = key_schedule[(round * 4) + 4] + key_schedule[(round * 4) + 5] + key_schedule[(round * 4) + 6] + key_schedule[(round * 4) + 7]
            w1 = new_stateArray[0][0] + new_stateArray[1][0] + new_stateArray[2][0] + new_stateArray[3][0]
            w2 = new_stateArray[0][1] + new_stateArray[1][1] + new_stateArray[2][1] + new_stateArray[3][1]
            w3 = new_stateArray[0][2] + new_stateArray[1][2] + new_stateArray[2][2] + new_stateArray[3][2]
            w4 = new_stateArray[0][3] + new_stateArray[1][3] + new_stateArray[2][3] + new_stateArray[3][3]
            words = w1 + w2 + w3 + w4
            res = key ^ words

            for i in range(4):
                for j in range(4):
                    stateArray[j][i] = res[32*i + 8*j:32*i + 8*j+8]
        res_in_hex = res.get_bitvector_in_hex()
        FILEOUT.write(res_in_hex)

def AES_decrypt(f1, f2):
    #key_BV = get_initial_key()
    key_BV = BitVector(textstring = in_key)
    key_schedule = gen_key_schedule(key_BV)
    invSubBytesTable = []
    invSubBytesTable = gen_InvSubBytes_table()
    hexE = BitVector(hexstring = '0E')
    hexB = BitVector(hexstring = '0B')
    hexD = BitVector(hexstring = '0D')
    hex9 = BitVector(hexstring = '09')
    if os.path.exists(f2):
        os.remove(f2)
    bv = BitVector(filename = f1)
    FILEOUT = open(f2, "a") 
    with open(f1) as tfile:
        while 1:
            data = tfile.read(32)
            if not data:
                break

    #while (bv.more_to_read):
    #    bitvec = bv.read_bits_from_file(128)
    #    if (len(bitvec) != 128):
    #        bitvec.pad_from_right(128 - len(bitvec))
            ### XOR with last 4 words from 44 words key_schedule 
            bitvec = BitVector(hexstring = data)
            bitvec = bitvec ^ (key_schedule[40] + key_schedule[41] + key_schedule[42] + key_schedule[43])
            #print(bitvec)
            ###generate state array
            for i in range(4):
                for j in range(4):
                    stateArray[j][i] = bitvec[i*32 + j*8: i*32 + (j+1)*8]

            ### Procced to 10 rounds of AES decryption
            for round in reversed(range(10)): #counting 10 rounds in reverse order to account for reverse order of keyschedule used
                #print(round)
                ### STEP 1: Inverse Shift Rows
                stateArray[1] = [stateArray[1][3], stateArray[1][0], stateArray[1][1], stateArray[1][2]]
                stateArray[2] = [stateArray[2][2], stateArray[2][3], stateArray[2][0], stateArray[2][1]]
                stateArray[3] = [stateArray[3][1], stateArray[3][2], stateArray[3][3], stateArray[3][0]]
                
                ### STEP 2: Inverse Substitute Bytes
                for i in range(4):
                    for j in range(4):
                        temp = stateArray[i][j]
                        #stateArray[i][j] = BitVector(intVal = invSubBytesTable[temp])
                        stateArray[i][j] = decrypt_substitution(temp, invSubBytesTable)
                
                ### STEP 3: Add Round Key
                key = key_schedule[(round*4)] + key_schedule[(round*4) + 1] + key_schedule[(round*4) + 2] + key_schedule[(round*4) + 3]
                w1 = stateArray[0][0] + stateArray[1][0] + stateArray[2][0] + stateArray[3][0]
                w2 = stateArray[0][1] + stateArray[1][1] + stateArray[2][1] + stateArray[3][1]
                w3 = stateArray[0][2] + stateArray[1][2] + stateArray[2][2] + stateArray[3][2]
                w4 = stateArray[0][3] + stateArray[1][3] + stateArray[2][3] + stateArray[3][3]
                words = w1 + w2 + w3 + w4
                #print(words)
                #break
                res = key ^ words
                for i in range(4):
                    for j in range(4):
                        stateArray[j][i] = res[32*i + 8*j:32*i + 8*(j+1)]
                
                ### STEP 4: Inverse Mix Columns
                if round != 0:
                    for j in range(4):
                        new_stateArray[0][j] = (hexE.gf_multiply_modular(stateArray[0][j], AES_modulus, 8) ^ hexB.gf_multiply_modular(stateArray[1][j], AES_modulus, 8) ^ hexD.gf_multiply_modular(stateArray[2][j], AES_modulus, 8) ^ hex9.gf_multiply_modular(stateArray[3][j], AES_modulus, 8))
                    for j in range(4):
                        new_stateArray[1][j] = (hex9.gf_multiply_modular(stateArray[0][j], AES_modulus, 8) ^ hexE.gf_multiply_modular(stateArray[1][j], AES_modulus, 8) ^ hexB.gf_multiply_modular(stateArray[2][j], AES_modulus, 8) ^ hexD.gf_multiply_modular(stateArray[3][j], AES_modulus, 8))
                    for j in range(4):
                        new_stateArray[2][j] = (hexD.gf_multiply_modular(stateArray[0][j], AES_modulus, 8) ^ hex9.gf_multiply_modular(stateArray[1][j], AES_modulus, 8) ^ hexE.gf_multiply_modular(stateArray[2][j], AES_modulus, 8) ^ hexB.gf_multiply_modular(stateArray[3][j], AES_modulus, 8))
                    for j in range(4):
                        new_stateArray[3][j] = (hexB.gf_multiply_modular(stateArray[0][j], AES_modulus, 8) ^ hexD.gf_multiply_modular(stateArray[1][j], AES_modulus, 8) ^ hex9.gf_multiply_modular(stateArray[2][j], AES_modulus, 8) ^ hexE.gf_multiply_modular(stateArray[3][j], AES_modulus, 8))
                else: #if it is the final round of of AES decryption
                    for i in range(4):
                        for j in range(4):
                            new_stateArray[i][j] = stateArray[i][j]
                ###potential error below this comment
                w1 = new_stateArray[0][0] + new_stateArray[1][0] + new_stateArray[2][0] + new_stateArray[3][0]
                w2 = new_stateArray[0][1] + new_stateArray[1][1] + new_stateArray[2][1] + new_stateArray[3][1]
                w3 = new_stateArray[0][2] + new_stateArray[1][2] + new_stateArray[2][2] + new_stateArray[3][2]
                w4 = new_stateArray[0][3] + new_stateArray[1][3] + new_stateArray[2][3] + new_stateArray[3][3]
                words = w1 + w2 + w3 + w4

                for i in range(4):
                    for j in range(4):
                        stateArray[j][i] = words[32*i + 8*j:32*i + 8*(j+1)]
            fres = words.get_text_from_bitvector()
            FILEOUT.write(fres)
    
if __name__ == "__main__":
    #a = gen_SubBytes_table()
    #b = gen_InvSubBytes_table()
    #print(a[104])
    #print(b)
    #print(get_initial_key())
    #AES_encrypt("message.txt", "encrypted.txt")
    #kBV = get_initial_key()
    #print(kBV)
    #gen_key_schedule(kBV)
    print("encrypting...")
    AES_encrypt("message.txt", "encrypted.txt")
    print("decrypting...")
    AES_decrypt("encrypted.txt", "decrypted.txt")
