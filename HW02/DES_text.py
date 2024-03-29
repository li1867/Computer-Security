#Homework Number: HW 02 problem 1
#Name: Peiyuan Li
#ECN Login: li1867
#Due Date: Jan 24, 2019

#!/usr/bin/env python

### hw2_starter.py

import sys
from BitVector import *

expansion_permutation = [31,  0,  1,  2,  3,  4,
                          3,  4,  5,  6,  7,  8,
                          7,  8,  9, 10, 11, 12,
                         11, 12, 13, 14, 15, 16,
                         15, 16, 17, 18, 19, 20,
                         19, 20, 21, 22, 23, 24,
                         23, 24, 25, 26, 27, 28,
                         27, 28, 29, 30, 31, 0]

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                     54,29,39,50,44,32,47,43,48,38,55,33,52,
                     45,41,49,35,28,31]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

s_boxes = {i:None for i in range(8)}

s_boxes[0] = [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
               [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
               [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
               [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ]

s_boxes[1] = [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
               [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
               [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
               [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ]

s_boxes[2] = [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
               [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
               [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
               [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ]

s_boxes[3] = [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
               [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
               [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
               [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ]

s_boxes[4] = [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
               [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
               [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
               [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ]

s_boxes[5] = [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
               [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
               [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
               [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ]

s_boxes[6] = [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
               [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
               [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
               [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ]

s_boxes[7] = [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
               [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
               [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
               [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]

p_box_permutation = [15,  6, 19, 20, 28, 11, 27, 16,
                      0, 14, 22, 25,  4, 17, 30,  9,
                      1,  7, 23, 13, 31, 26,  2,  8,
                     18, 12, 29,  5, 21, 10,  3, 24]

def substitute( expanded_half_block ):
    '''
    This method implements the step "Substitution with 8 S-boxes" step you see inside
    Feistel Function dotted box in Figure 4 of Lecture 3 notes.
    '''
    output = BitVector (size = 32)
    segments = [expanded_half_block[x*6:x*6+6] for x in range(8)]
    for sindex in range(len(segments)):
        row = 2*segments[sindex][0] + segments[sindex][-1]
        column = int(segments[sindex][1:-1])
        output[sindex*4:sindex*4+4] = BitVector(intVal = s_boxes[sindex][row][column], size = 4)
    return output

def generate_round_keys(encryption_key):
    round_keys = []
    key = encryption_key.deep_copy()
    for round_count in range(16):
        [LKey, RKey] = key.divide_into_two()
        shift = shifts_for_round_key_gen[round_count]
        LKey << shift
        RKey << shift
        key = LKey + RKey
        round_key = key.permute(key_permutation_2)
        round_keys.append(round_key)
    return round_keys

def get_encryption_key():
    key = ""
    F = open('key.txt', 'r')
    key = F.readline()
    key = BitVector(textstring = key)
    key = key.permute(key_permutation_1)
    return key

def DES_decryption(input, output):
    bv = BitVector(filename=input)  # construct a bit vector from a disk file by a two-step procedure
    key = get_encryption_key()
    round_key_list = generate_round_keys(key)
    round_key_list.reverse()
    res_mess = BitVector(size=0)
    # start to read bit from file.
    while (bv.more_to_read):
        # read 64 bit from the file
        bv_read = bv.read_bits_from_file(64)
        if len(bv_read) < 64:
            bv_read.pad_from_right(64 - len(bv_read))
        # divided the 64 bit text into two 32 bit vector
        [LE, RE] = bv_read.divide_into_two()


        # length of round_key output is 16, so it will run 16 times.
        for round_key in round_key_list:
            # expansion permutation
            new_RE = RE.permute(expansion_permutation)
            # key mixing
            key_mixing_output = round_key ^ new_RE
            # subsitute function will break key_mixing_output into eight 6 bit words, and each 6 bit words
            # goes into a subsitution step, replacement is a 4 bit word. the length of SBox_o should be 32
            SBox_o = substitute(key_mixing_output)
            # The 32-bits of the previous step then go through a P-box based
            # permutation
            PBox_o = SBox_o.permute(p_box_permutation)
            # what coms out of the P-box is then xor with left half of the 64-bit block.
            # the output of this xor operation gives us the right half block for the next round
            nextRE = PBox_o ^ LE
            LE = RE
            RE = nextRE
        new_content = RE + LE
        res_mess += new_content
    output_file = open(output, 'wb')
    res_mess.write_to_file(output_file)
    output_file.close()
    pass

def DES_encryption(input, output):
    bv = BitVector(filename=input)  #construct a bit vector from a disk file by a two-step procedure
    key = get_encryption_key()
    round_key_list = generate_round_keys( key )
    res_mess = BitVector(size=0)
    #start to read bit from file.
    while (bv.more_to_read):
        #read 64 bit from the file
        bv_read = bv.read_bits_from_file( 64 )
        if len(bv_read) < 64:
            bv_read.pad_from_right(64-len(bv_read))
        # divided the 64 bit text into two 32 bit vector
        [LE, RE] = bv_read.divide_into_two()

        #length of round_key output is 16, so it will run 16 times.
        for round_key in round_key_list:
            # expansion permutation
            new_RE = RE.permute(expansion_permutation)
            #key mixing
            key_mixing_output = new_RE ^ round_key
            #subsitute function will break key_mixing_output into eight 6 bit words, and each 6 bit words
            #goes into a subsitution step, replacement is a 4 bit word. the length of SBox_o should be 32
            SBox_o = substitute(key_mixing_output)
            #The 32-bits of the previous step then go through a P-box based
            #permutation
            PBox_o = SBox_o.permute(p_box_permutation)
            #what coms out of the P-box is then xor with left half of the 64-bit block.
            #the output of this xor operation gives us the right half block for the next round
            nextRE = PBox_o ^ LE
            LE = RE
            RE = nextRE
        new_content = RE + LE
        res_mess += new_content
    output_file = open(output, 'wb')
    res_mess.write_to_file(output_file)
    output_file.close()

if __name__ == '__main__':
    DES_encryption("message.txt", "encrypted.txt")
    DES_decryption("encrypted.txt", "decrypted.txt")
    pass

#encrypted output
#????W??QNn?J ???-?b_E??.???2?u??:??c??E????;?^d??}???W???x|?J?4c6]
# $? ??s`??b#?>??<????M??(v????#?R0??4?.W?y4?E??d?,z??w??~$???]??5
# HNb?p??=e^*???8>??O????rFF>??|????A????s?}?????Q~~Jv1/"4?GM???(?X?.
# ?E???a????zu?' T?d??\???SF{E?w?'@'En5$"?V?k??~?t??$[????.?LM&?	??L
# ?????x????#?* ^J???[????>k;E/?_*J?+OtRf????????f3?"]6???N6?f?????)6_
# ?}?@?5?o????eR?????"?SH(?g??zJ?Z(?{Y?+??,x???X?n???-?F??DM?	?9uW[?n?
# ?~??HgA?D?t?s??}???DX???tw?????>??L?|8??k???y??+??W?.3?$??C??JW _?? 
# d??????<???\	_Tl???C??f?????5?.&?E??%?3?5Y?y?X?M\?>??@A??@i??#?"??[??
# v?&?Yh?]?.?{f8?% ?B??9??????}??????e??R?????:?H??????W?yhF????Gy?G{Y
# ?+??,x/??0a??|%,L?F8????;Ztw???????z!4??p?t?tD?Gc4+
#?K???ej?uS?V??z??w
#?e(??PV?U?????n)??2???2??9??v?f+? {?&???<#(:???????T??`x)17A?gc?F??y??
# q?s|??$?OR?4\0?*?!{???n????R???o??????[?v?8???c???*?r??*?%y?????????L?%
# e?*?r??*?%y??S[e#yb??U,?d??J????
#5A?)=DM??57????~?H???}?M?G?-;?"A??L%=P?p!?F??b%?
#.?-k?<?1??~e?[???|I??za?
#/[??4??ZP??_?;e??>??????B?A?w\Z???z?? ?<?^?+2{??;???????qd`l???[

#decrypted output
#Earlier this week, security researchers took note of a series
# of changes Linux and Windows developers began rolling out in
# beta updates to address a critical security flaw: A bug in
# Intel chips allows low-privilege processes to access memory in
# the computer's kernel, the machine's most privileged inner
# sanctum. Theoretical attacks that exploit that bug, based on
# quirks in features Intel has implemented for faster processing,
# could allow malicious software to spy deeply into other processes
# and data on the target computer or smartphone. And on multi-user
# machines, like the servers run by Google Cloud Services or Amazon
# Web Services, they could even allow hackers to break out of one
# user's process, and instead snoop on other processes running on the
# same shared server. On Wednesday evening, a large team of researchers
# \at Google's Project Zero, universities including the Graz University
# of Technology, the University of Pennsylvania, the University of Adelaide
# in Australia, and security companies including Cyberus and Rambus together
# released the full details of two attacks based on that flaw, which they call
# Meltdown and Spectre.
