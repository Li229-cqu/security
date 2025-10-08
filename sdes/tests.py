# -*- coding: utf-8 -*-
import time
from sdes import *

if __name__=="__main__":
    key=bits10_from_str("1010000010")
    P=0xA5
    C=int_from_bits(encrypt_block8(bits_from_int(P,8),key))
    D=int_from_bits(decrypt_block8(bits_from_int(C,8),key))
    print(f"[Demo] P={P:02X} -> C={C:02X} -> D={D:02X}")

    msg=b"S-DES!"
    enc=encrypt_bytes(msg,key)
    dec=decrypt_bytes(enc,key)
    print(f"[ASCII] {msg} -> {enc.hex()} -> {dec}")

    t0=time.time()
    keys=brute_force_known_pairs([(P,C)])
    t1=time.time()
    print(f"[BruteForce] Found {len(keys)} key(s) in {t1-t0:.6f}s")
