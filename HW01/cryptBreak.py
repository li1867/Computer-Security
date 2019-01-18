#!/usr/bin/env python

###  DecryptForFun.py
###  Avi Kak  (kak@purdue.edu)
###  January 21, 2014, modified January 11, 2016

###  Medium strength encryption/decryption for secure message exchange
###  for fun.

###  Based on differential XORing of bit blocks.  Differential XORing
###  destroys any repetitive patterns in the messages to be ecrypted and
###  makes it more difficult to break encryption by statistical
###  analysis. Differential XORing needs an Initialization Vector that is
###  derived from a pass phrase in the script shown below.  The security
###  level of this script can be taken to full strength by using 3DES or
###  AES for encrypting the bit blocks produced by differential XORing.

###  Call syntax:
###
###        DecryptForFun.py  encrypted_file.txt  recover.txt
###
###  The decrypted output is deposited in the file `recover.txt'

import sys
from BitVector import *                                                     

if len(sys.argv) is not 3:
    sys.exit('''Needs two command-line arguments, one for '''
             '''the encrypted file and the other for the '''
             '''decrypted output file''')

PassPhrase = "Hopes and dreams of a million years"

BLOCKSIZE = 16  #changed the block size to 16
numbytes = BLOCKSIZE // 8

# Reduce the passphrase to a bit array of size BLOCKSIZE:
bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)
for i in range(0,len(PassPhrase) // numbytes):
    textstr = PassPhrase[i*numbytes:(i+1)*numbytes]
    bv_iv ^= BitVector( textstring = textstr )

FILEIN = open(sys.argv[1])
encrypted_bv = BitVector( hexstring = FILEIN.read())

#generating all of the possible passwords
for key in range(0, pow(2, 16)):  
    key_bv = BitVector(intVal=key, size = 16) 
    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )
    # Carry out differential XORing of bit blocks and encryption:
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv

    outputtext = msg_decrypted_bv.get_text_from_bitvector()
    if "Cormac McCarthy" in outputtext:
        print(key_bv)

        FILEOUT = open(sys.argv[2], 'w')
        FILEOUT.write(outputtext)
        FILEOUT.close()
        break

    #passcode: 0110100101110110
    #passcode: 26998


