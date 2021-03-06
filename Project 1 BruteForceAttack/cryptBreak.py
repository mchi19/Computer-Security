#!/usr/bin/env python3

import sys
from BitVector import *

if len(sys.argv) is not 3:
    sys.exit('''Needs two command-line arguments, one for '''
             '''the message file and the other for the '''
             '''encrypted output file''')

PassPhrase = "Hopes and dreams of a million years"

BLOCKSIZE = 16
numbytes = BLOCKSIZE // 8

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )  

# Create a bitvector from the ciphertext hex string:
FILEIN = open(sys.argv[1])
encrypted_bv = BitVector( hexstring = FILEIN.read() )

# Brute force decryption approach, tries all possible keys until correct key is found
for combo in range(0, 2**16): #value found was 29556
    key_bv = BitVector(intVal = combo, size = 16)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv

    print(combo)#prints the current key value

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    # Write plaintext to the output file:
    # fix this for simpler write
    if "Benjamin Franklin" in outputtext:
        FILEOUT = open(sys.argv[2], 'w')
        FILEOUT.write(outputtext)
        FILEOUT.close()
        break
