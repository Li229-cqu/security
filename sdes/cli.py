# -*- coding: utf-8 -*-
import argparse, sys
from sdes import *

def main():
    p = argparse.ArgumentParser()
    sub=p.add_subparsers(dest="cmd",required=True)

    for name in ("enc","dec"):
        sp=sub.add_parser(name)
        g=sp.add_mutually_exclusive_group(required=True)
        g.add_argument("--bits")
        g.add_argument("--text")
        g.add_argument("--hex")
        sp.add_argument("--key",required=True)
        sp.add_argument("--show-hex",action="store_true")
        sp.add_argument("--as-text",action="store_true")

    bf=sub.add_parser("bruteforce")
    bf.add_argument("--pair",action="append",required=True)

    args=p.parse_args()
    if args.cmd in ("enc","dec"):
        key=bits10_from_str(args.key)
        if args.bits: data=bytes([int(args.bits,2)])
        elif args.text: data=args.text.encode()
        else: data=bytes.fromhex(args.hex)

        out=encrypt_bytes(data,key) if args.cmd=="enc" else decrypt_bytes(data,key)
        if args.as_text: print(out.decode(errors="ignore"))
        elif args.show_hex or args.text or args.hex: print(out.hex())
        else: print(format(out[0],"08b"))
    else:
        pairs=[]
        for pstr in args.pair:
            p,c=pstr.split(":")
            pairs.append((p,c))
        keys=brute_force_known_pairs(pairs)
        print("Found keys:",[format(k,'010b') for k in keys])

if __name__=="__main__":
    main()
