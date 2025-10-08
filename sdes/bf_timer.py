# bf_timer.py — 暴力破解计时小工具（第4关用）
import argparse, time, datetime
from sdes import brute_force_known_pairs

def parse_pc(s):
    p,c = s.split(":")
    def b(x):
        x=x.strip().lower()
        if all(ch in "01" for ch in x) and len(x)==8: return int(x,2)
        return int(x,16)
    return (b(p), b(c))

if __name__ == "__main__":
    ap = argparse.ArgumentParser("S-DES brute-force timer")
    ap.add_argument("--pair", action="append", required=True, help="P:C (8-bit bin or 2-hex)")
    args = ap.parse_args()

    pairs = [parse_pc(x) for x in args.pair]
    t0 = time.time()
    print(f"[START] {datetime.datetime.now().isoformat(timespec='seconds')}")
    keys = brute_force_known_pairs(pairs)
    t1 = time.time()
    print(f"[END]   {datetime.datetime.now().isoformat(timespec='seconds')}")
    print(f"[RESULT] {len(keys)} key(s) found in {t1-t0:.6f}s")
    if keys:
        print("Sample keys (bin):", ", ".join(format(k,"010b") for k in keys[:10]))
