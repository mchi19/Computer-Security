#!/usr/bin/env python

### Author: Max Chi
### ECN: chi19
### HW: 02
### File: DES_chi.py
### Due Date: 1/25/2018

import sys
from BitVector import *

expansion_permutation = [31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0]

p_box_permutation = [ 15, 6, 19, 20, 28, 11, 27, 16,
                      0, 14, 22, 25, 4, 17, 30, 9,
                      1, 7, 23, 13, 31, 26, 2, 8,
                      18, 12, 29, 5, 21, 10, 3, 24 ]

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                     54,29,39,50,44,32,47,43,48,38,55,33,52,
                     45,41,49,35,28,31]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

### generate s-boxes ###
def gen_s_boxes(filename):
    arr = []
    s_boxes = [] #stores all s-boxes 
    with open(filename, "r") as file:
        data = file.readlines()
    for line in data:
        if len(line) > 5:
            arr.append(line.split())
            if len(arr) == 4:
                s_boxes.append(arr)
                arr = []
    #print(s_boxes[1])
    return s_boxes

### generate key ###
def get_key(fn):
    with open(fn, "r") as file:
        data = file.read()
    temp_key = data[:-1]
    #print(temp_key)
    #print(len(temp_key))
    if (len(temp_key) != 8):
        raise ValueError("Invalid key size, key generation requires exactly 8 characters.")
    user_key_bv = BitVector( textstring = temp_key )
    #print(len(user_key_bv))
    key_bv = user_key_bv.permute( key_permutation_1 )
    #print(len(key_bv))
    return key_bv

### generate round keys ###
def gen_round_keys(e_key):
    round_keys = []
    for i in range(16):
        [left,right] = e_key.divide_into_two()
        left << shifts_for_round_key_gen[i]
        right >> shifts_for_round_key_gen[i]
        round_key = left + right
        round_key = round_key.permute(key_permutation_2)
        #print(tempBV)
        #print(len(tempBV))
        round_keys.append(round_key)
    #print(len(round_keys))
    #print(round_keys)
    return round_keys

### DES algorithm ###
def DES(encrypt_enable, input_f, output_f, key):
    s_boxes = gen_s_boxes("s-box-tables.txt") ###retreive s_boxes
    encrypted_key = get_key(key) ###generate encrypted key
    round_keys = gen_round_keys(encrypted_key) ###generate 16 round keys
    bv = BitVector( filename = input_f ) ###converts input txt into BitVector format
    FILEOUT = open(output_f, 'wb')
    #print(s_boxes[0][0][0])
    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(64)
        if (len(bitvec) != 64): #check if its 64 bits, if not needs to be padded
            #print(len(bitvec))
            bitvec.pad_from_right(64 - len(bitvec))
        #print(type(bitvec))
        [LE, RE] = bitvec.divide_into_two()
        #print(len(LE))
        #print(len(RE))
        for i in range(len(round_keys)):
            tempRE = RE
            ### expansion permutation
            newRE = RE.permute(expansion_permutation)
            ### XOR with Round Key
            if encrypt_enable is True:
                RE = RE ^ round_keys[i] #encryption key 
            else: #decryption key
                RE = RE ^ round_keys[15-i]
            ### Substitution with 8 S-boxes
            ts_boxBV = BitVector(size=0)
            #print(len(s_boxes))
            for j in range(len(s_boxes)):
                row = 2*RE[6*j] + 1*RE[5+6*j]
                col = 8*RE[1+6*j] + 4*RE[2+6*j] + 2*RE[3+6*j] + 1*RE[4+6*j]
                ts_boxBV += BitVector(intVal = int(s_boxes[j][row][col]), size=4)
            ### permutation using p_box
            permuteBV = ts_boxBV.permute(p_box_permutation)
            ### XOR files together
            RE = LE ^ permuteBV
            LE = tempRE
        ### reverse the order of the halfs for proceeding block
        bitvec = RE + LE
        bitvec.write_to_file(FILEOUT)
    FILEOUT.close()
    return

if __name__ == "__main__":
    #s_boxes = gen_s_boxes("s-box-tables.txt")
    #e_key = get_key("key.txt")
    #gen_round_keys(e_key)
    
    #0 for encrypt
    DES(True, "message.txt", "encrypted.txt","key.txt")
    print("DES Encryption complete.")

    #1 for decrypt
    DES(False, "encrypted.txt", "decrypted.txt", "key.txt")
    print("DES Decryption complete.")
