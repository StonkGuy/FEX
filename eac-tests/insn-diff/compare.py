#!/usr/bin/env python3
"""Compares two insn_diff outputs (native oracle vs FEX).

  compare.py forms.json native.txt fex.txt [--examples N] [--cases-out file]

Categories per differing case:
  defined      a GPR, XMM, x87 register, memory byte, signal or architecturally defined flag differs
  undef-flags  only flags the SDM/APM leave undefined for this form differ
  x87-status   only FSW.PE (0x20) / FSW.C1 (0x200) differ (x87 precision/rounding indicator)
  x87-ulp      x87 transcendental result within 4 ulp of the 64-bit mantissa (and nothing else defined differs)
  mxcsr-flags  only MXCSR exception flag bits 0-5 differ
Exit status 1 when any 'defined' difference exists.
"""
import json, sys
from collections import defaultdict, OrderedDict


def parse(path):
    hdr, res, skip = [], {}, set()
    for line in open(path, errors="replace"):
        p = line.split()
        if not p:
            continue
        if not p[0].isdigit():
            hdr.append(line.rstrip())
            continue
        if p[1] == "skip":
            skip.add(int(p[0]))
            continue
        d = OrderedDict()
        for kv in p[2:]:
            k, _, v = kv.partition("=")
            d[k] = v
        res[(int(p[0]), int(p[1]))] = d
    return hdr, res, skip


def f80(h):
    h = h.rjust(20, "0")
    return int(h[:4], 16), int(h[4:], 16)


def classify(fm, a, b):
    cats = set()
    keys = set(a) | set(b)
    undef = fm["undef"]
    for k in sorted(keys):
        va, vb = a.get(k), b.get(k)
        if va == vb:
            continue
        if k == "fl" and va is not None and vb is not None:
            x = int(va, 16) ^ int(vb, 16)
            if x & ~undef:
                cats.add("defined")
            else:
                cats.add("undef-flags")
        elif k == "fsw" and fm["cls"].startswith("x87"):
            x = int(va or "0", 16) ^ int(vb or "0", 16)
            cats.add("x87-status" if not (x & ~0x220) else "defined")
        elif k == "mx" and va is not None and vb is not None and not ((int(va, 16) ^ int(vb, 16)) & ~0x3f):
            cats.add("mxcsr-flags")
        elif k.startswith("st") and fm["cls"] == "x87tr" and va and vb:
            (ea, ma), (eb, mb) = f80(va), f80(vb)
            cats.add("x87-ulp" if ea == eb and abs(ma - mb) <= 4 else "defined")
        else:
            cats.add("defined")
    if "defined" in cats:
        return "defined"
    for c in ("x87-ulp", "x87-status", "mxcsr-flags", "undef-flags"):
        if c in cats:
            return c
    return None


def fmt(d):
    return " ".join(f"{k}={v}" for k, v in d.items())


def main():
    args = sys.argv[1:]
    nex = 3
    casesout = None
    if "--examples" in args:
        i = args.index("--examples"); nex = int(args[i + 1]); del args[i:i + 2]
    if "--cases-out" in args:
        i = args.index("--cases-out"); casesout = args[i + 1]; del args[i:i + 2]
    forms = json.load(open(args[0]))
    hn, rn, sn = parse(args[1])
    hf, rf, sf = parse(args[2])
    print("native:", *hn, sep="\n  ")
    print("fex:", *hf, sep="\n  ")
    per = defaultdict(lambda: defaultdict(list))
    total = defaultdict(int)
    compared = 0
    missing = 0
    for key, a in rn.items():
        b = rf.get(key)
        if b is None:
            missing += 1
            continue
        compared += 1
        c = classify(forms[key[0]], a, b)
        if c:
            total[c] += 1
            per[key[0]][c].append(key[1])
    print(f"\ncompared {compared} cases over {len(set(k[0] for k in rn))} forms; missing in fex output: {missing}; "
          f"skipped (feature absent) native {len(sn)}, fex {len(sf)}: {sorted(sf - sn)[:40]}")
    print("totals:", dict(total))
    shows = []
    for cat in ("defined", "undef-flags", "x87-ulp", "x87-status", "mxcsr-flags"):
        rows = [(f, per[f][cat]) for f in sorted(per) if per[f][cat]]
        if not rows:
            continue
        print(f"\n=== {cat}: {len(rows)} forms ===")
        for f, cs in rows:
            fm = forms[f]
            ncases = sum(1 for k in rn if k[0] == f)
            print(f"[{f}] {fm['name']}  {len(cs)}/{ncases}  asm: {' ; '.join(fm['asm'])}")
            for c in cs[:nex if cat == "defined" else 1]:
                print(f"    case {c}\n      native: {fmt(rn[(f, c)])}\n      fex:    {fmt(rf[(f, c)])}")
                if cat == "defined":
                    shows.append(f"{f} {c}")
    if casesout:
        open(casesout, "w").write("\n".join(shows[:400]) + "\n")
    return 1 if total["defined"] else 0


sys.exit(main())
