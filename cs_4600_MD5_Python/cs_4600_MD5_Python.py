
# -*- coding: utf-8 -*-
"""
Created on Wed Mar  8 21:54:46 2023

@author: khale
"""

# import the math module
import math

# define a list of 64 integers to be used as rotation amounts for each round 
# respectively
rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# define a list of 64 constants derived from the sine function
constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]
# note that this is equivalent to 
# constants = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
#              0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
#              0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
#              0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
#              0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
#              0xd62f105d, 0x2441453,  0xd8a1e681, 0xe7d3fbc8,
#              0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
#              0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
#              0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
#              0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
#              0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05,
#              0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
#              0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
#              0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
#              0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
#              0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]



# define a list of 4 initial values
# these values represent a, b, c, and d respectivly
init_values = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

# define four groups of 16 functions each, to be used in calculating the MD5 hash
# these functions are F, G, H, and I respectively
functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
            16*[lambda b, c, d: (d & b) | (~d & c)] + \
            16*[lambda b, c, d: b ^ c ^ d] + \
            16*[lambda b, c, d: c ^ (b | ~d)]

# define four groups of 16 index functions each, to be used in calculating the MD5 hash
# these index functions are F, G, H, and I respectively
index_functions = 16*[lambda i: i] + \
                  16*[lambda i: (5*i + 1)%16] + \
                  16*[lambda i: (3*i + 5)%16] + \
                  16*[lambda i: (7*i)%16]

# define a function to left rotate a number by a given amount
def left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x<<amount) | (x>>(32-amount))) & 0xFFFFFFFF

# define the main function for computing the MD5 hash of a message
def md5(message):

    # Convert message to a mutable bytearray
    message = bytearray(message)

    # Compute the original length of the message in bits
    orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff

    # Add padding to the message
    message.append(0x80)
    while len(message)%64 != 56:
        message.append(0)
    message += orig_len_in_bits.to_bytes(8, byteorder='little')

    # Initialize the hash_pieces variable to some fixed values
    hash_pieces = init_values[:]

    # Process the message in 64-byte chunks
    for chunk_ofst in range(0, len(message), 64):

        # Copy the current hash_pieces values into variables a, b, c, and d
        a, b, c, d = hash_pieces

        # Extract the current chunk of the message
        chunk = message[chunk_ofst:chunk_ofst+64]

        # Perform a series of operations to update the hash_pieces values
        for i in range(64):

            # Compute f and g values for this round of the MD5 algorithm
            f = functions[i](b, c, d)
            g = index_functions[i](i)

            # Compute a value to be rotated
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')

            # Compute the new value for variable b
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF

            # Update the values of a, b, c, and d for the next round
            a, b, c, d = d, new_b, b, c

        # Add the updated hash_pieces values to the original values
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF

    # Concatenate the hash_pieces values to produce the final hash value
    return sum(x<<(32*i) for i, x in enumerate(hash_pieces))

# define a function for converting an MD5 digest to a hexadecimal string    
def md5_to_hex(digest):
    # convert the 16-byte digest to a 128-bit integer in little-endian byte order
    raw = digest.to_bytes(16, byteorder='little')
    # convert the integer to a hexadecimal string with 32 characters (using zero-padding if necessary)
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))

if __name__=='__main__':
    demo = [b"", b"a", b"abc", b"message digest", b"abcdefghijklmnopqrstuvwxyz",
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            b"This is a top secret."]
   
    # Show encrypted message next to original
    for message in demo:
        print(md5_to_hex(md5(message)),' <= "',message.decode('ascii'),'"', sep='')
        
     # Test to see if the constants are indeed the same
     # count = 0;
     # print(f"Constant: {hex(constants[0])}", end = ", ")
     # for i in range(0, len(constants)):
     #     if i % 5 != 0:
     #         print(f"{hex(constants[i])}", end = ", ")
     #         count += 1 
     #     else:
     #         count = 0
     #         print("\n")