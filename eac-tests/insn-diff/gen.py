#!/usr/bin/env python3
"""Generates the instruction table for insn-diff.

Writes forms.S (one stub per instruction form or random sequence) and forms.json (metadata used by compare.py).
Each stub runs with the guest state loaded by the trampoline in harness.c and returns with RET; it must keep RSP
balanced and must not touch R15 (base of the fixed data buffer).

Flag masks: CF=0x1 PF=0x4 AF=0x10 ZF=0x40 SF=0x80 OF=0x800.
  undef  = flags the SDM/APM leave architecturally undefined for this form (compared separately)
  reads  = flags the form consumes, writes = flags it defines (for taint tracking in random sequences)
Constraints (cons) are applied by harness.c to the random input before the stub runs.
"""
import json, random, sys

CF, PF, AF, ZF, SF, OF = 0x1, 0x4, 0x10, 0x40, 0x80, 0x800
ALL = CF | PF | AF | ZF | SF | OF
forms = []

def F(name, asm, undef=0, reads=0, writes=0, cons=(), feat=(), cls="int", seq=True):
    forms.append(dict(name=name, asm=asm if isinstance(asm, list) else [asm], undef=undef, reads=reads,
                      writes=writes, cons=list(cons), feat=list(feat), cls=cls, seq=seq))

R = {8: ("al", "bl", "cl", "dl"), 88: ("ah", "bh", "ch", "dh"), 16: ("ax", "bx", "cx", "dx"),
     32: ("eax", "ebx", "ecx", "edx"), 64: ("rax", "rbx", "rcx", "rdx")}
R2 = {8: "sil", 88: "bh", 16: "si", 32: "esi", 64: "rsi"}
PTR = {8: "byte", 88: "byte", 16: "word", 32: "dword", 64: "qword"}
M = "[r15+0x400]"

# ---- ALU ----
for op in ("add", "sub", "adc", "sbb", "and", "or", "xor", "cmp"):
    rd = CF if op in ("adc", "sbb") else 0
    ud = AF if op in ("and", "or", "xor") else 0
    for sz in (8, 88, 16, 32, 64):
        a, b = R[sz][0], R[sz][1]
        F(f"{op}{sz}_rr", f"{op} {a}, {b}", ud, rd, ALL)
        F(f"{op}{sz}_rr_r{R2[sz]}", f"{op} {R2[sz]}, {R[sz][3]}", ud, rd, ALL)
        imm = {8: "0x7f", 88: "0x81", 16: "0x8001", 32: "0x80000001", 64: "-0x7ffffff0"}[sz]
        F(f"{op}{sz}_ri", f"{op} {a}, {imm}", ud, rd, ALL)
        if sz != 88:
            F(f"{op}{sz}_mr", f"{op} {PTR[sz]} ptr {M}, {b}", ud, rd, ALL, seq=False)
            F(f"{op}{sz}_rm", f"{op} {a}, {PTR[sz]} ptr {M}", ud, rd, ALL, seq=False)
            if op != "cmp":
                F(f"lock_{op}{sz}_mr", f"lock {op} {PTR[sz]} ptr {M}, {b}", ud, rd, ALL, seq=False)
for op in ("neg", "not", "inc", "dec"):
    for sz in (8, 88, 16, 32, 64):
        a = R[sz][0]
        w = 0 if op == "not" else (ALL & ~CF if op in ("inc", "dec") else ALL)
        F(f"{op}{sz}_r", f"{op} {a}", 0, 0, w)
for sz in (8, 16, 32, 64):
    F(f"test{sz}_rr", f"test {R[sz][0]}, {R[sz][1]}", AF, 0, ALL)

# ---- shifts / rotates ----
for op in ("shl", "shr", "sar", "rol", "ror", "rcl", "rcr"):
    rd = CF if op in ("rcl", "rcr") else 0
    for sz in (8, 16, 32, 64):
        a = R[sz][0]
        if op in ("shl", "shr", "sar"):
            ud = OF | AF | (CF if sz in (8, 16) else 0)
            wr = ALL
        else:
            ud = OF
            wr = CF | OF
        F(f"{op}{sz}_cl", f"{op} {a}, cl", ud, rd, 0, cons=["count"])
        F(f"{op}{sz}_1", f"{op} {a}, 1", ud & ~OF if op in ("shl", "shr", "sar", "rol", "ror", "rcl", "rcr") else ud, rd, wr)
        for c in (0, 3, sz - 1, sz, sz + 1, 31, 63 if sz == 64 else 33):
            if c > 255: continue
            F(f"{op}{sz}_i{c}", f"{op} {a}, {c}", ud, rd, 0 if (c & (63 if sz == 64 else 31)) == 0 else wr)
for op in ("shld", "shrd"):
    for sz in (16, 32, 64):
        a, b = R[sz][0], R[sz][1]
        ud = OF | AF
        cons = ["count16"] if sz == 16 else ["count"]
        F(f"{op}{sz}_cl", f"{op} {a}, {b}, cl", ud, 0, 0, cons=cons, seq=(sz != 16))
        for c in (0, 1, 7, 15, 16, 31, 63):
            if sz == 16 and c > 16: continue
            F(f"{op}{sz}_i{c}", f"{op} {a}, {b}, {c}", ud, 0, 0 if (c & (63 if sz == 64 else 31)) == 0 else ALL & ~(OF | AF))
        F(f"{op}{sz}_m_cl", f"{op} {PTR[sz]} ptr {M}, {b}, cl", ud, 0, 0, cons=cons, seq=False)

# ---- multiply / divide ----
MULU = SF | ZF | AF | PF
for sz in (8, 16, 32, 64):
    b = R[sz][1]
    F(f"mul{sz}", f"mul {b}", MULU, 0, CF | OF)
    F(f"imul{sz}_1op", f"imul {b}", MULU, 0, CF | OF)
    F(f"mul{sz}_m", f"mul {PTR[sz]} ptr {M}", MULU, 0, CF | OF, seq=False)
    if sz != 8:
        F(f"imul{sz}_2op", f"imul {R[sz][0]}, {b}", MULU, 0, CF | OF)
        F(f"imul{sz}_3op", f"imul {R[sz][0]}, {b}, -3", MULU, 0, CF | OF)
        F(f"imul{sz}_3op_big", f"imul {R[sz][0]}, {b}, 0x7fff", MULU, 0, CF | OF)
    F(f"div{sz}", f"div {b}", ALL, 0, 0, cons=[f"div{sz}"], seq=False)
    F(f"idiv{sz}", f"idiv {b}", ALL, 0, 0, cons=[f"idiv{sz}"], seq=False)
    F(f"div{sz}_raw", f"div {b}", ALL, 0, 0, seq=False)
    F(f"idiv{sz}_raw", f"idiv {b}", ALL, 0, 0, seq=False)
    F(f"idiv{sz}_m", f"idiv {PTR[sz]} ptr {M}", ALL, 0, 0, seq=False)

# ---- bit scan / count ----
for sz in (16, 32, 64):
    a, b = R[sz][0], R[sz][1]
    F(f"bsf{sz}", f"bsf {a}, {b}", ALL & ~ZF, 0, ZF)
    F(f"bsr{sz}", f"bsr {a}, {b}", ALL & ~ZF, 0, ZF)
    F(f"bsf{sz}_m", f"bsf {a}, {PTR[sz]} ptr {M}", ALL & ~ZF, 0, ZF, seq=False)
    F(f"tzcnt{sz}", f"tzcnt {a}, {b}", ALL & ~(ZF | CF), 0, ZF | CF, feat=["bmi1"])
    F(f"lzcnt{sz}", f"lzcnt {a}, {b}", ALL & ~(ZF | CF), 0, ZF | CF, feat=["lzcnt"])
    F(f"popcnt{sz}", f"popcnt {a}, {b}", 0, 0, ALL, feat=["popcnt"])
    for op in ("bt", "bts", "btr", "btc"):
        ud = OF | SF | AF | PF
        F(f"{op}{sz}_rr", f"{op} {a}, {b}", ud, 0, CF)
        F(f"{op}{sz}_ri", f"{op} {a}, {sz + 5}", ud, 0, CF)
        F(f"{op}{sz}_mr", f"{op} {PTR[sz]} ptr {M}, {R[sz][2]}", ud, 0, CF, cons=["btoff"], seq=False)
        F(f"{op}{sz}_mi", f"{op} {PTR[sz]} ptr {M}, {sz - 3}", ud, 0, CF, seq=False)
        if op != "bt":
            F(f"lock_{op}{sz}_mr", f"lock {op} {PTR[sz]} ptr {M}, {R[sz][2]}", ud, 0, CF, cons=["btoff"], seq=False)

# ---- BMI1 / BMI2 / ADX ----
for sz in (32, 64):
    a, b, c, d = R[sz]
    F(f"andn{sz}", f"andn {a}, {b}, {c}", AF | PF, 0, ALL, feat=["bmi1"])
    F(f"bextr{sz}", f"bextr {a}, {b}, {c}", AF | PF | SF, 0, ALL & ~(AF | PF | SF), cons=["bextr"], feat=["bmi1"])
    F(f"bextr{sz}_raw", f"bextr {a}, {b}, {c}", AF | PF | SF, 0, ALL & ~(AF | PF | SF), feat=["bmi1"])
    for op in ("blsi", "blsr", "blsmsk"):
        F(f"{op}{sz}", f"{op} {a}, {b}", AF | PF, 0, ALL & ~(AF | PF), feat=["bmi1"])
    F(f"bzhi{sz}", f"bzhi {a}, {b}, {c}", AF | PF, 0, ALL & ~(AF | PF), cons=["count"], feat=["bmi2"])
    F(f"bzhi{sz}_raw", f"bzhi {a}, {b}, {c}", AF | PF, 0, ALL & ~(AF | PF), feat=["bmi2"])
    F(f"pdep{sz}", f"pdep {a}, {b}, {c}", feat=["bmi2"])
    F(f"pext{sz}", f"pext {a}, {b}, {c}", feat=["bmi2"])
    F(f"pdep{sz}_m", f"pdep {a}, {b}, {PTR[sz]} ptr {M}", feat=["bmi2"], seq=False)
    for i in (0, 1, 13, sz - 1, sz):
        F(f"rorx{sz}_i{i}", f"rorx {a}, {b}, {i}", feat=["bmi2"])
    for op in ("sarx", "shlx", "shrx"):
        F(f"{op}{sz}", f"{op} {a}, {b}, {c}", feat=["bmi2"])
    F(f"mulx{sz}", f"mulx {a}, {b}, {c}", feat=["bmi2"])
    F(f"mulx{sz}_same", f"mulx {a}, {a}, {c}", feat=["bmi2"])
    F(f"adcx{sz}", f"adcx {a}, {b}", 0, CF, CF, feat=["adx"])
    F(f"adox{sz}", f"adox {a}, {b}", 0, OF, OF, feat=["adx"])

# ---- CRC32 / byte order / cmpxchg ----
F("crc32_8", "crc32 eax, bl", feat=["sse42"])
F("crc32_8h", "crc32 eax, bh", feat=["sse42"])
F("crc32_16", "crc32 eax, bx", feat=["sse42"])
F("crc32_32", "crc32 eax, ebx", feat=["sse42"])
F("crc32_64", "crc32 rax, rbx", feat=["sse42"])
F("crc32_64_8", "crc32 rax, bl", feat=["sse42"])
F("crc32_m32", f"crc32 eax, dword ptr {M}", feat=["sse42"], seq=False)
F("bswap32", "bswap eax"); F("bswap64", "bswap rax"); F("bswap64_r9", "bswap r9")
for sz in (16, 32, 64):
    F(f"movbe{sz}_load", f"movbe {R[sz][0]}, {PTR[sz]} ptr {M}", feat=["movbe"], seq=False)
    F(f"movbe{sz}_store", f"movbe {PTR[sz]} ptr {M}, {R[sz][1]}", feat=["movbe"], seq=False)
for sz in (8, 16, 32, 64):
    a, b = R[sz][0], R[sz][1]
    F(f"cmpxchg{sz}_rr", f"cmpxchg {R[sz][3]}, {b}", 0, 0, ALL, cons=["cmpeq"])
    F(f"cmpxchg{sz}_mr", f"lock cmpxchg {PTR[sz]} ptr {M}, {b}", 0, 0, ALL, cons=["cmpeqm"], seq=False)
    F(f"xadd{sz}_rr", f"xadd {a}, {b}", 0, 0, ALL)
    F(f"xadd{sz}_mr", f"lock xadd {PTR[sz]} ptr {M}, {b}", 0, 0, ALL, seq=False)
    F(f"xchg{sz}_mr", f"xchg {PTR[sz]} ptr {M}, {b}", seq=False)
F("cmpxchg8b", f"lock cmpxchg8b qword ptr {M}", 0, 0, ZF, cons=["cx16eq"], seq=False)
F("cmpxchg16b", f"lock cmpxchg16b xmmword ptr {M}", 0, 0, ZF, cons=["cx16eq"], feat=["cx16"], seq=False)

# ---- flags / partial registers / misc ----
F("lahf", "lahf", 0, ALL & ~OF, 0)
F("sahf", "sahf", 0, 0, ALL & ~OF)
F("pushf_pop", ["pushfq", "pop rax"], 0, ALL, 0)
F("popf", ["mov r14, rax", "and r14, 0xcd5", "push r14", "popfq"], 0, 0, ALL)
F("cmc", "cmc", 0, CF, CF); F("stc", "stc", 0, 0, CF); F("clc", "clc", 0, 0, CF)
F("mov_ah_bl", "mov ah, bl"); F("mov_bh_al", "mov bh, al"); F("mov_ch_dh", "mov ch, dh")
F("movzx_eax_ah", "movzx eax, ah"); F("movsx_eax_bh", "movsx eax, bh"); F("movzx_ebx_bx", "movzx ebx, bx")
F("xchg_ah_al", "xchg ah, al"); F("xchg_ah_bh", "xchg ah, bh"); F("xor_ah_ah", "xor ah, ah", AF, 0, ALL)
F("mov_ax_bx", "mov ax, bx"); F("mov_eax_ebx", "mov eax, ebx"); F("mov_al_bh", "mov al, bh")
F("movsxd", "movsxd rax, ebx"); F("cbw", "cbw"); F("cwde", "cwde"); F("cdqe", "cdqe")
F("cwd", "cwd"); F("cdq", "cdq"); F("cqo", "cqo")
F("lea_scale", "lea rax, [rbx+rcx*8-0x7f]"); F("lea32", "lea eax, [ebx+ecx*4+0x10]"); F("lea16", "lea ax, [rbx+rcx*2]")
for cc in ("o", "no", "b", "ae", "e", "ne", "be", "a", "s", "ns", "p", "np", "l", "ge", "le", "g"):
    F(f"set{cc}", f"set{cc} ah", 0, ALL, 0)
    F(f"cmov{cc}32", f"cmov{cc} eax, ebx", 0, ALL, 0)
    F(f"cmov{cc}64", f"cmov{cc} rax, rbx", 0, ALL, 0)
F("cmovb16", "cmovb ax, bx", 0, CF, 0)

# ---- string ops ----
for op, sfx in (("movs", "bwdq"), ("stos", "bwdq"), ("lods", "bq"), ("scas", "bq"), ("cmps", "bq")):
    for s in sfx:
        fl = ALL if op in ("scas", "cmps") else 0
        F(f"{op}{s}", f"{op}{s}", 0, 0, fl, cons=["str"], seq=False)
        pre = {"movs": "rep", "stos": "rep", "lods": "rep", "scas": "repne", "cmps": "repe"}[op]
        F(f"{pre}_{op}{s}", f"{pre} {op}{s}", 0, 0, fl, cons=["str"], seq=False)
F("repe_scasb", "repe scasb", 0, 0, ALL, cons=["str"], seq=False)
F("repne_cmpsb", "repne cmpsb", 0, 0, ALL, cons=["str"], seq=False)

# ---- segment-prefixed memory (gs base = data buffer, fs = TLS) ----
F("gs_load", "mov rax, qword ptr gs:[0x400]", seq=False)
F("gs_add", "add dword ptr gs:[0x408], ebx", 0, 0, ALL, seq=False)
F("gs_index", "mov rax, qword ptr gs:[rcx*8+0x100]", cons=["idx64"], seq=False)
F("gs_cmpxchg", "lock cmpxchg qword ptr gs:[0x400], rbx", 0, 0, ALL, cons=["cmpeqm"], seq=False)
F("fs_self", ["mov rax, qword ptr fs:[0]", "mov rdx, qword ptr [rax]", "xor rax, rdx", "xor edx, edx"], seq=False)
F("gs_movs", ["push rsi", "mov rsi, 0x400", "lea rdi, [r15+0x500]", "mov rcx, 8", "rep movsb byte ptr es:[rdi], byte ptr gs:[rsi]", "xor rdi, rdi", "pop rsi"], seq=False, cons=["cld"])

# ---- x87 ----
X = dict(cls="x87", seq=False)
for op in ("fadd", "fsub", "fsubr", "fmul", "fdiv", "fdivr"):
    F(f"{op}_st0_st1", f"{op} st(0), st(1)", **X)
    F(f"{op}_m64", f"{op} qword ptr {M}", cons=["mdouble"], **X)
    F(f"{op}_m32", f"{op} dword ptr {M}", cons=["mfloat"], **X)
for op in ("fsqrt", "fprem", "fprem1", "fscale", "frndint", "fxtract", "f2xm1", "fyl2x", "fyl2xp1", "fsin", "fcos",
           "fsincos", "fptan", "fpatan", "fchs", "fabs", "fld1", "fldpi", "fldl2e", "fldl2t", "fldlg2", "fldln2", "fldz"):
    F(op, op, cls="x87tr" if op in ("f2xm1", "fyl2x", "fyl2xp1", "fsin", "fcos", "fsincos", "fptan", "fpatan") else "x87", seq=False)
F("fprem_loop", ["2:", "fprem", "fnstsw ax", "test ah, 4", "jnz 2b"], **X)
F("fprem1_loop", ["2:", "fprem1", "fnstsw ax", "test ah, 4", "jnz 2b"], **X)
F("fxam", ["fxam", "fnstsw ax"], **X)
F("fxam_st1", ["fxch", "fxam", "fnstsw ax"], **X)
F("ftst", ["ftst", "fnstsw ax"], **X)
F("fcom", ["fcom st(1)", "fnstsw ax"], **X)
F("fucompp", ["fucompp", "fnstsw ax"], **X)
F("fcomi", "fcomi st(0), st(1)", 0, 0, ALL, **X)
F("fucomi", "fucomi st(0), st(1)", 0, 0, ALL, **X)
F("fcmovb", "fcmovb st(0), st(1)", **X)
F("fcmovnbe", "fcmovnbe st(0), st(1)", **X)
for w, n in (("word", "16"), ("dword", "32"), ("qword", "64")):
    F(f"fist{n}", f"fistp {w} ptr {M}", **X)
    F(f"fisttp{n}", f"fisttp {w} ptr {M}", **X)
    if w != "qword":
        F(f"fild{n}", f"fild {w} ptr {M}", **X)
        F(f"fiadd{n}", f"fiadd {w} ptr {M}", **X)
F("fild64", f"fild qword ptr {M}", **X)
F("fstp80", f"fstp tbyte ptr {M}", **X)
F("fld80", f"fld tbyte ptr {M}", cons=["m80"], **X)
F("fstp64", f"fstp qword ptr {M}", **X)
F("fstp32", f"fstp dword ptr {M}", **X)
F("fld64", f"fld qword ptr {M}", cons=["mdouble"], **X)
F("fld32", f"fld dword ptr {M}", cons=["mfloat"], **X)
F("fbstp", f"fbstp tbyte ptr {M}", **X)
F("fbld", f"fbld tbyte ptr {M}", cons=["mbcd"], **X)
F("fnstenv_cw", ["fnstcw word ptr [r15+0x400]", "fnstsw word ptr [r15+0x402]"], **X)
F("fldcw_fadd", ["fldcw word ptr [r15+0x400]", "fadd st(0), st(1)"], cons=["mcw"], **X)
F("fldcw_fist", ["fldcw word ptr [r15+0x400]", "fistp dword ptr [r15+0x404]"], cons=["mcw"], **X)
F("fldcw_frndint", ["fldcw word ptr [r15+0x400]", "frndint"], cons=["mcw"], **X)
F("fxch_fincstp", ["fxch st(3)", "fincstp", "fdecstp", "fdecstp", "ffree st(0)"], **X)

# ---- SSE / crypto ----
S = dict(cls="sse", seq=False)
F("pshufb", "pshufb xmm0, xmm1", feat=["ssse3"], **S)
F("pshufb_m", f"pshufb xmm0, xmmword ptr {M}", feat=["ssse3"], **S)
for imm in (0x00, 0x01, 0x04, 0x08, 0x0C, 0x0D, 0x18, 0x1A, 0x3A, 0x40, 0x44, 0x48, 0x4C, 0x62, 0x70, 0x72, 0x7D):
    for op in ("pcmpestri", "pcmpestrm", "pcmpistri", "pcmpistrm"):
        F(f"{op}_{imm:02x}", f"{op} xmm0, xmm1, 0x{imm:x}", 0, 0, ALL, cons=["strxmm"], feat=["sse42"], **S)
for op in ("aesenc", "aesenclast", "aesdec", "aesdeclast", "aesimc"):
    F(op, f"{op} xmm0, xmm1", feat=["aes"], **S)
for imm in (0, 1, 0x1b, 0x36, 0xff):
    F(f"aeskeygenassist_{imm:x}", f"aeskeygenassist xmm0, xmm1, 0x{imm:x}", feat=["aes"], **S)
for imm in (0x00, 0x01, 0x10, 0x11, 0xff):
    F(f"pclmulqdq_{imm:x}", f"pclmulqdq xmm0, xmm1, 0x{imm:x}", feat=["pclmul"], **S)
for imm in range(4):
    F(f"sha1rnds4_{imm}", f"sha1rnds4 xmm2, xmm1, {imm}", feat=["sha"], **S)
for op in ("sha1nexte", "sha1msg1", "sha1msg2", "sha256msg1", "sha256msg2"):
    F(op, f"{op} xmm2, xmm1", feat=["sha"], **S)
F("sha256rnds2", "sha256rnds2 xmm2, xmm1, xmm0", feat=["sha"], **S)
for op in ("cvtsd2si", "cvttsd2si"):
    F(f"{op}32", f"{op} eax, xmm1", **S); F(f"{op}64", f"{op} rax, xmm1", **S)
for op in ("cvtss2si", "cvttss2si"):
    F(f"{op}64", f"{op} rax, xmm1", **S)
for op in ("cvtps2dq", "cvttps2dq", "cvtpd2dq", "cvttpd2dq", "cvtpd2ps", "cvtps2pd", "cvtdq2ps", "sqrtsd", "sqrtps",
           "minsd", "maxsd", "minps", "maxpd", "addsubpd", "haddps", "haddpd", "divsd", "mulps", "addps", "subsd",
           "pmulhrsw", "pmaddubsw", "pmaddwd", "psadbw", "pmuludq", "pmuldq", "pmulld", "packusdw", "packsswb",
           "phaddsw", "psignb", "pabsd", "pminsb", "pmaxuw", "pavgb", "pmulhuw", "psllq", "psrad", "psrlw", "cvtsd2ss",
           "cvtss2sd", "unpcklps", "punpckhbw", "pcmpgtq", "pcmpeqb", "andnpd"):
    F(op, f"{op} xmm0, xmm1", feat=["sse41" if op in ("pmuldq", "pmulld", "packusdw", "pminsb") else
                                     "sse42" if op == "pcmpgtq" else
                                     "ssse3" if op in ("pmulhrsw", "pmaddubsw", "phaddsw", "psignb", "pabsd") else "sse2"], **S)
F("cvtsi2sd64", "cvtsi2sd xmm0, rax", **S); F("cvtsi2ss64", "cvtsi2ss xmm0, rax", **S)
for imm in (0, 1, 2, 3, 4, 8, 9, 12):
    F(f"roundsd_{imm}", f"roundsd xmm0, xmm1, {imm}", feat=["sse41"], **S)
    F(f"roundps_{imm}", f"roundps xmm0, xmm1, {imm}", feat=["sse41"], **S)
for imm in (0x31, 0xff, 0x7f):
    F(f"dpps_{imm:x}", f"dpps xmm0, xmm1, 0x{imm:x}", feat=["sse41"], **S)
F("dppd_33", "dppd xmm0, xmm1, 0x33", feat=["sse41"], **S)
for imm in (0, 1, 2, 3, 4, 5, 6, 7):
    F(f"cmpsd_{imm}", f"cmpsd xmm0, xmm1, {imm}", **S)
for op in ("comisd", "ucomisd", "comiss", "ucomiss", "ptest"):
    F(op, f"{op} xmm0, xmm1", 0, 0, ALL, feat=["sse41"] if op == "ptest" else [], **S)
for imm in (1, 5, 15, 17):
    F(f"palignr_{imm}", f"palignr xmm0, xmm1, {imm}", feat=["ssse3"], **S)
F("pshufd_1b", "pshufd xmm0, xmm1, 0x1b", **S); F("shufps_e4", "shufps xmm0, xmm1, 0x72", **S)
F("pblendvb", "pblendvb xmm2, xmm1, xmm0", feat=["sse41"], **S)
F("blendvpd", "blendvpd xmm2, xmm1, xmm0", feat=["sse41"], **S)
F("insertps_9c", "insertps xmm0, xmm1, 0x9c", feat=["sse41"], **S)
F("mpsadbw_5", "mpsadbw xmm0, xmm1, 5", feat=["sse41"], **S)
F("pmovmskb", "pmovmskb eax, xmm1", **S); F("movmskpd", "movmskpd eax, xmm1", **S)
F("pextrw", "pextrw eax, xmm1, 5", **S); F("pinsrb", "pinsrb xmm0, ebx, 13", feat=["sse41"], **S)
F("pextrq", "pextrq rax, xmm1, 1", feat=["sse41"], **S)
F("psllq_imm", "psllq xmm0, 63", **S); F("psrldq", "psrldq xmm0, 7", **S)
F("ldmxcsr_cvt", ["ldmxcsr dword ptr [r15+0x400]", "cvtsd2si rax, xmm1"], cons=["mxcsr"], **S)
F("ldmxcsr_add", ["ldmxcsr dword ptr [r15+0x400]", "addsd xmm0, xmm1"], cons=["mxcsr"], **S)

# ---- random sequences of register-only integer forms ----
def seqgen(n, rng):
    pool = [f for f in forms if f["seq"] and f["cls"] == "int" and not f["cons"] and not any(
        "ret" in l for l in f["asm"])]
    out = []
    tries = 0
    while len(out) < n and tries < n * 50:
        tries += 1
        k = rng.randint(2, 8)
        picks = [rng.choice(pool) for _ in range(k)]
        undef = 0
        ok = True
        feats = set()
        for p in picks:
            if p["reads"] & undef:
                ok = False; break
            undef = (undef & ~p["writes"]) | p["undef"]
            feats |= set(p["feat"])
        if not ok:
            continue
        asm = []
        for p in picks:
            asm += p["asm"]
        out.append(dict(name=f"seq{len(out):04d}:" + "|".join(p["name"] for p in picks), asm=asm, undef=undef,
                        reads=0, writes=0, cons=[], feat=sorted(feats), cls="seq", seq=False))
    return out

nseq = int(sys.argv[1]) if len(sys.argv) > 1 else 600
forms += seqgen(nseq, random.Random(20261017))

with open("forms.S", "w") as f:
    f.write(".intel_syntax noprefix\n.text\n")
    for i, fm in enumerate(forms):
        f.write(f".globl form_{i}\nform_{i}:\n")
        for l in fm["asm"]:
            f.write(f"\t{l}\n" if not l.endswith(":") else f"{l}\n")
        f.write("\tret\n")
    f.write(".section .rodata\n.globl form_table\n.balign 8\nform_table:\n")
    for i in range(len(forms)):
        f.write(f"\t.quad form_{i}\n")
    f.write(f".globl form_count\nform_count: .quad {len(forms)}\n")
FEATS = ["bmi1", "bmi2", "adx", "lzcnt", "popcnt", "sse42", "sse41", "ssse3", "sse2", "aes", "pclmul", "sha", "movbe", "cx16"]
CONS = ["count", "count16", "div8", "div16", "div32", "div64", "idiv8", "idiv16", "idiv32", "idiv64", "btoff", "bextr",
        "cmpeq", "cmpeqm", "cx16eq", "str", "idx64", "cld", "mdouble", "mfloat", "m80", "mbcd", "mcw", "strxmm", "mxcsr"]
with open("forms.h", "w") as f:
    f.write("/* generated by gen.py */\n")
    f.write("static const struct { unsigned feat; unsigned cons; } form_meta[] = {\n")
    for fm in forms:
        fe = sum(1 << FEATS.index(x) for x in fm["feat"])
        co = sum(1 << CONS.index(x) for x in fm["cons"])
        f.write(f"  {{0x{fe:x}, 0x{co:x}}},\n")
    f.write("};\n")
    for i, x in enumerate(FEATS): f.write(f"#define FEAT_{x.upper()} (1u<<{i})\n")
    for i, x in enumerate(CONS): f.write(f"#define CONS_{x.upper()} (1u<<{i})\n")
json.dump([dict(name=fm["name"], undef=fm["undef"], cls=fm["cls"], asm=fm["asm"]) for fm in forms],
          open("forms.json", "w"), indent=0)
print(len(forms), "forms", file=sys.stderr)
