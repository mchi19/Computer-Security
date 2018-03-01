#!/usr/bin/env python3.4

### Author: Max Chi
### ECN: chi19
### HW: 03
### File: chi_field.py
### Due Date: 2/1/2018

import sys

### outputs whether or not given Z_num is a field or ring. Starts by evaluating if Z_num is a prime number or not. Prime numbers are definetly fields, an non prime numbers are not considered fields. If it is not a field, then it must be a ring since all Z_n are considered rings.
def det_field_or_ring(): 
    z_num = int(input("Enter an integer between 0 and 50: "))
    while 1:
        if z_num > 0 and z_num < 50:
            break
        else:
            z_num = int(input("Invalid input! Please enter an integer between 0 and 50: "))
    for i in range(1, z_num):
        if gcd(int(z_num),i) != 1:
            return "ring"
    return "field"

#determines greatest common denominator using Euclid's Algorithm
def gcd(a, b):
    while b:
        a, b = b, a%b
    #print(a)
    return a

if __name__ == "__main__":
    print(det_field_or_ring())
