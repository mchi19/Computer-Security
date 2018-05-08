#!/usr/bin/env python3.4

### Author: Max Chi
### ECN: chi19
### HW: 07
### File: chi19_hw06.py
### Due Date: 3/6/2018

'''
###SHA-512 algorightm steps:
The following steps are from the 15.7.2 lecture notes provided by Professor Kak

STEP 1: Pad the message so that its length is an intergral multiple of 1024, the block size. The only complication here is that the last 128 bits of the last block must contain a value that is the legnth of the message.

STEP 2: Generate message schedule required for processing a 1024-bit block of the input message. The message schedule conssists of 80 64-bit words. the first 16 of these words are obtained directly from the 1024-bit message block. The rest of the words are obtained by applying permutation and mixing operations to the some of the previously generated words.

STEP 3: Applying round-based processign to each 1024-bit input message block. There are 80 rounds to be carried out for each message block. For this round-based processing, we first store the hash values calculated for the previous message block in a temporary 64-bit variable that is denoted by a,b,c,d,e,f,g,h. in the ith round, we premute the values stored in tehse eight variables and, with two of the variables, we mix in the message schedule word words[ii] and a round constant K[i].

STEP 4: We update the hash values calculated for the previous message block by adding to it the values in the temporary variables a,b,c,d,e,f,g,h.

'''

import sys
import os
from BitVector import *
import hashlib

if len(sys.argv) != 2:
    sys.stderr.write("Usage: %s <string to be hashed>\n" % sys.argv[0])
    sys.exit(1)

with open(sys.argv[1], "r") as fp:
    message = fp.read()

###initialize hashcode for the first block
h0 = BitVector(hexstring="6a09e667f3bcc908")
h1 = BitVector(hexstring="bb67ae8584caa73b")
h2 = BitVector(hexstring="3c6ef372fe94f82b")
h3 = BitVector(hexstring="a54ff53a5f1d36f1")
h4 = BitVector(hexstring="510e527fade682d1")
h5 = BitVector(hexstring="9b05688c2b3e6c1f")
h6 = BitVector(hexstring="1f83d9abfb41bd6b")
h7 = BitVector(hexstring="5be0cd19137e2179")

### K constants (round constants) #generated from parsing through table provided in lecture notes figure lecture 15 pg 44
K = ['428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc', '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118', 'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2', '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694', 'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65', '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5', '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4', 'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70', '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df', '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b', 'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30', 'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8', '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8', '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3', '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec', '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b', 'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178', '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b', '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c', '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817']

#modified from prof kak's SHA-1 example
###Step 1
bv = BitVector(textstring=message)
bv_len = bv.length()
bv1 = bv + BitVector(bitstring = "1")
bv1_len = bv1.length()
howmanyzeros = (896 - bv1_len) % 1024 #doubled the value used for block size of 512
zerolist = [0] * howmanyzeros
bv2 = bv1 + BitVector(bitlist = zerolist)
bv3 = BitVector(intVal= bv_len, size = 128)
bv4 = bv2 + bv3

words = [None] * 80
mod_add_64 = int(BitVector(hexstring="FFFFFFFFFFFFFFFF"))

for n in range(0, bv4.length(), 1024):
    block = bv4[n:n+1024]
    ###Step 2
    words[0:16] = [block[i:i+64] for i in range(0,1024, 64)]
    for i in range(16,80):
        i_sub2 = words[i - 2]
        i_sub15 = words[i-15]
        sigma0 = (i_sub15.deep_copy() >> 1) ^ (i_sub15.deep_copy() >> 8) ^ \
                 (i_sub15.deep_copy().shift_right(7))
        sigma1 = (i_sub2.deep_copy() >> 19) ^ (i_sub2.deep_copy() >> 61) ^ \
                 (i_sub2.deep_copy().shift_right(6))
        words[i] = BitVector(intVal=(int(words[i-16]) + int(sigma1) + int(words[i-7]) + int(sigma0)) & mod_add_64, size=64)
    a,b,c,d,e,f,g,h = h0,h1,h2,h3,h4,h5,h6,h7

    ###Step 3
    for i in range(80):
        ch = (e & f) ^ ((~e) & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        sumA = ((a.deep_copy()) >> 28) ^ ((a.deep_copy()) >> 34) ^ ((a.deep_copy()) >> 39)
        sumE = ((e.deep_copy()) >> 14) ^ ((e.deep_copy()) >> 18) ^ ((e.deep_copy()) >> 41)
        T1 = (int(h) + int(ch) + int(sumE) + int(words[i]) + int(BitVector(hexstring=K[i]))) & mod_add_64
        T2 = (int(sumA) + int(maj)) & mod_add_64

        h = g
        g = f
        f = e
        e = BitVector(intVal=((int(d) + T1) & mod_add_64), size=64)
        d = c
        c = b
        b = a
        a = BitVector(intVal=((T1 + T2) & mod_add_64), size=64)
        
    ###Step 4
    h0 = BitVector(intVal=((int(h0) + int(a)) & mod_add_64), size=64)
    h1 = BitVector(intVal=((int(h1) + int(b)) & mod_add_64), size=64)
    h2 = BitVector(intVal=((int(h2) + int(c)) & mod_add_64), size=64)
    h3 = BitVector(intVal=((int(h3) + int(d)) & mod_add_64), size=64)
    h4 = BitVector(intVal=((int(h4) + int(e)) & mod_add_64), size=64)
    h5 = BitVector(intVal=((int(h5) + int(f)) & mod_add_64), size=64)
    h6 = BitVector(intVal=((int(h6) + int(g)) & mod_add_64), size=64)
    h7 = BitVector(intVal=((int(h7) + int(h)) & mod_add_64), size=64)

message_hash = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7

with open("output.txt", "w") as f_out:
   f_out.write(message_hash.get_hex_string_from_bitvector())

#if __name__ == "__main__":
    #print(message_hash.get_hex_string_from_bitvector())
    #print(hashlib.sha512(message).hexdigest())
    #m = hashlib.sha512(bytes(message))
    #print(hashlib.blake2b(bytes(message)).hexdigest())
    
'''
### used to write the K table for first 80 blocks
    with open("temp.txt", "r") as f:
        data = f.readlines()
    K = []
    for x in data:
        #print(x)
        y = x.split()
        #print(y)
        for z in y:
            K.append(z)
        #print(type(y))
        #break
        #y = x.strip(" ")
        #print(y)
    print(len(K))
    print(K)
    
'''
