# -*- coding: utf-8 -*-

from typing import List, Tuple

#工具函数
def permute(bits: List[int], table: Tuple[int, ...]) -> List[int]:
    return [bits[i-1] for i in table]

def left_shift(bits: List[int], amount: int) -> List[int]:
    n = len(bits)
    return bits[amount % n:] + bits[:amount % n]

def split_lr(bits: List[int]):
    mid = len(bits)//2
    return bits[:mid], bits[mid:]

def join_lr(L, R): return L+R

def bits_from_int(x: int, n: int) -> List[int]:
    return [(x >> (n-1-i)) & 1 for i in range(n)]

def int_from_bits(bits: List[int]) -> int:
    v = 0
    for b in bits: v = (v<<1)|b
    return v

def bits_from_str8(s: str) -> List[int]:
    s = s.strip().replace(" ", "")
    if len(s)!=8 or any(c not in "01" for c in s): raise ValueError("8-bit binary expected")
    return [int(c) for c in s]

def bits10_from_str(s: str) -> List[int]:
    s = s.strip().replace(" ", "")
    if len(s)!=10 or any(c not in "01" for c in s): raise ValueError("10-bit binary expected")
    return [int(c) for c in s]
# S-DES 置换盒与 S 盒（与图片一致）
P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8  = (6, 3, 7, 4, 8, 5, 10, 9)

# 初始/逆初始置换
IP     = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)

# 轮函数中的扩展置换与 4 位置换
EP = (4, 1, 2, 3, 2, 3, 4, 1)     # EPBox
P4 = (2, 4, 3, 1)                 # SPBox


# S-DES 置换盒与S盒
P10=(3,5,2,7,4,10,1,9,8,6)
P8 =(6,3,7,4,8,5,10,9)
IP =(2,6,3,1,4,8,5,7)
IP_INV=(4,1,3,5,7,2,8,6)
EP =(4,1,2,3,2,3,4,1)
P4 =(2,4,3,1)

S1=((1,0,3,2),(3,2,1,0),(0,2,1,3),(3,1,0,2))
S2=((0,1,2,3),(2,3,1,0),(3,0,1,2),(2,1,0,3)) # 按题目修订

# 子密钥扩展
def key_schedule(K10):
    p10 = permute(K10, P10)
    L,R = split_lr(p10)
    L1,R1 = left_shift(L,1), left_shift(R,1)
    k1 = permute(join_lr(L1,R1), P8)
    L2,R2 = left_shift(L1,2), left_shift(R1,2)
    k2 = permute(join_lr(L2,R2), P8)
    return k1,k2

# 轮函数
def sbox_lookup(sbox, four):
    b0,b1,b2,b3 = four
    row = (b0<<1)|b3
    col = (b1<<1)|b2
    return bits_from_int(sbox[row][col], 2)

def F(R4, subkey):
    t = permute(R4, EP)
    t = [a^b for a,b in zip(t, subkey)]
    L4,R4 = split_lr(t)
    s1o = sbox_lookup(S1, L4)
    s2o = sbox_lookup(S2, R4)
    return permute(s1o+s2o, P4)

def fk(L,R,subkey):
    return [l^f for l,f in zip(L, F(R,subkey))], R

def SW(L,R): return R,L

# 加密/解密
def encrypt_block8(plain8, K10):
    k1,k2 = key_schedule(K10)
    state = permute(plain8, IP)
    L,R = split_lr(state)
    L,R = fk(L,R,k1)
    L,R = SW(L,R)
    L,R = fk(L,R,k2)
    return permute(join_lr(L,R), IP_INV)

def decrypt_block8(cipher8, K10):
    k1,k2 = key_schedule(K10)
    state = permute(cipher8, IP)
    L,R = split_lr(state)
    L,R = fk(L,R,k2)
    L,R = SW(L,R)
    L,R = fk(L,R,k1)
    return permute(join_lr(L,R), IP_INV)

# ASCII 模式
def encrypt_bytes(data: bytes, K10_bits): return bytes(int_from_bits(encrypt_block8(bits_from_int(b,8),K10_bits)) for b in data)
def decrypt_bytes(data: bytes, K10_bits): return bytes(int_from_bits(decrypt_block8(bits_from_int(b,8),K10_bits)) for b in data)

# 暴力破解
def brute_force_known_pairs(pairs):
    norm=[]
    for p,c in pairs:
        if isinstance(p,str): p=int(p,2)
        if isinstance(c,str): c=int(c,2)
        norm.append((p,c))
    candidates=[]
    for K in range(1024):
        Kbits=bits_from_int(K,10)
        if all(int_from_bits(encrypt_block8(bits_from_int(p,8),Kbits))==c for p,c in norm):
            candidates.append(K)
    return candidates
