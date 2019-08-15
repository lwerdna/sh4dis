#!/usr/bin/env python

def int8(i):
    """ get 8-bit signed int """
    result = i
    if i & 0x80:
        result = -(128 - (i&0x7F))
    return result

def int12(i):
    """ get 12-bit signed int """
    result = i
    if i & 0x800:
        result = -(2048 - (i&0x7FF))
    return result

def displ2ea(scale, disp, base):
    """ displacement to effective address """
    #print('displ2ea(%d, %d, %X)' % (scale, disp, base))

    dest = (base+4) + scale*disp

    if dest < 0:
        dest = -dest
        dest = dest ^ 0xFFFFFFFFFFFFFFFF
        dest = dest + 1

    return dest

# about 231 cases follow
# so worst case: 230 checks
# average case: 165 checks
# TODO: order these so most common opcodes near the top
def disasm(insword, addr):
    """ disassemble instruction word at given address """

    # 0111nnnniiiiiiii "add #imm,Rn"
    if (insword & 0xf000) == 0x7000:
        i = int8(insword & 0xff)
        n = (insword & 0xf00)>>8
        return "add #%d,r%d" % (i,n)

    # 0011nnnnmmmm1100 "add Rm,Rn"
    if (insword & 0xf00f) == 0x300c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "add r%d,r%d" % (m, n)

    # 0011nnnnmmmm1110 "addc Rm,Rn"
    if (insword & 0xf00f) == 0x300e:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "addc r%d,r%d" % (m, n)

    # 0011nnnnmmmm1111 "addv Rm,Rn"
    if (insword & 0xf00f) == 0x300f:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "addv r%d,r%d" % (m, n)

    # 11001001iiiiiiii "and #imm,r0"
    if (insword & 0xff00) == 0xc900:
        i = int8(insword & 0xff)
        return "and #%d,r0" % (i)

    # 0010nnnnmmmm1001 "and Rm,Rn"
    if (insword & 0xf00f) == 0x2009:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "and r%d,r%d" % (m, n)

    # 11001101iiiiiiii "and.b #imm,@(r0,gbr)"
    if (insword & 0xff00) == 0xcd00:
        i = int8(insword & 0xff)
        return "and.b #%d,@(r0,gbr)" % (i)

    # 10001011dddddddd "bf label"
    if (insword & 0xff00) == 0x8b00:
        d = displ2ea(2, int8(insword & 0xff), addr)
        return "bf 0x%016x" % d

    # 10001111dddddddd "bf/s label"
    if (insword & 0xff00) == 0x8f00:
        d = displ2ea(2, int8(insword & 0xff), addr)
        return "bf.s 0x%016x" % d

    # 1010dddddddddddd "bra label"
    if (insword & 0xf000) == 0xa000:
        d = displ2ea(2, int12(insword & 0xfff), addr)
        return "bra 0x%016x" % d

    # 0000mmmm00100011 "braf Rm"
    if (insword & 0xf0ff) == 0x23:
        m = (insword & 0xf00)>>8
        return "braf r%d" % (m)

    # 1011dddddddddddd "bsr label"
    if (insword & 0xf000) == 0xb000:
        d = displ2ea(2, int12(insword & 0xfff), addr)
        return "bsr 0x%016x" % d

    # 0000mmmm00000011 "bsrf Rm"
    if (insword & 0xf0ff) == 0x3:
        m = (insword & 0xf00)>>8
        return "bsrf r%d" % (m)

    # 10001001dddddddd "bt label"
    if (insword & 0xff00) == 0x8900:
        d = displ2ea(2, int8(insword & 0xff), addr)
        return "bt 0x%016x" % d

    # 10001101dddddddd "bt/s label"
    if (insword & 0xff00) == 0x8d00:
        d = displ2ea(2, int8(insword & 0xff), addr)
        return "bt.s 0x%016x" % d

    # 0000000000101000 "clrmac"
    if insword == 0x28:
        return "clrmac"

    # 0000000001001000 "clrs"
    if insword == 0x48:
        return "clrs"

    # 0000000000001000 "clrt"
    if insword == 0x8:
        return "clrt"

    # 10001000iiiiiiii "cmp/eq #imm,r0"
    if (insword & 0xff00) == 0x8800:
        i = int8(insword & 0xff)
        return "cmp/eq #%d,r0" % (i)

    # 0011nnnnmmmm0000 "cmp/eq Rm,Rn"
    if (insword & 0xf00f) == 0x3000:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "cmp/eq r%d,r%d" % (m, n)

    # 0011nnnnmmmm0011 "cmp/ge Rm,Rn"
    if (insword & 0xf00f) == 0x3003:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "cmp/ge r%d,r%d" % (m, n)

    # 0011nnnnmmmm0111 "cmp/gt Rm,Rn"
    if (insword & 0xf00f) == 0x3007:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "cmp/gt r%d,r%d" % (m, n)

    # 0011nnnnmmmm0110 "cmp/hi Rm,Rn"
    if (insword & 0xf00f) == 0x3006:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "cmp/hi r%d,r%d" % (m, n)

    # 0011nnnnmmmm0010 "cmp/hs Rm,Rn"
    if (insword & 0xf00f) == 0x3002:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "cmp/hs r%d,r%d" % (m, n)

    # 0100nnnn00010101 "cmp/pl Rn"
    if (insword & 0xf0ff) == 0x4015:
        n = (insword & 0xf00)>>8
        return "cmp/pl r%d" % (n)

    # 0100nnnn00010001 "cmp/pz Rn"
    if (insword & 0xf0ff) == 0x4011:
        n = (insword & 0xf00)>>8
        return "cmp/pz r%d" % (n)

    # 0010nnnnmmmm1100 "cmp/str Rm,Rn"
    if (insword & 0xf00f) == 0x200c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "cmp/str r%d,r%d" % (m, n)

    # 0010nnnnmmmm0111 "div0s Rm,Rn"
    if (insword & 0xf00f) == 0x2007:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "div0s r%d,r%d" % (m, n)

    # 0000000000011001 "div0u"
    if insword == 0x19:
        return "div0u"

    # 0011nnnnmmmm0100 "div1 Rm,Rn"
    if (insword & 0xf00f) == 0x3004:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "div1 r%d,r%d" % (m, n)

    # 0011nnnnmmmm1101 "dmuls.l Rm,Rn"
    if (insword & 0xf00f) == 0x300d:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "dmuls.l r%d,r%d" % (m, n)

    # 0011nnnnmmmm0101 "dmulu.l Rm,Rn"
    if (insword & 0xf00f) == 0x3005:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "dmulu.l r%d,r%d" % (m, n)

    # 0100nnnn00010000 "dt Rn"
    if (insword & 0xf0ff) == 0x4010:
        n = (insword & 0xf00)>>8
        return "dt r%d" % (n)

    # 0110nnnnmmmm1110 "exts.b Rm,Rn"
    if (insword & 0xf00f) == 0x600e:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "exts.b r%d,r%d" % (m, n)

    # 0110nnnnmmmm1111 "exts.w Rm,Rn"
    if (insword & 0xf00f) == 0x600f:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "exts.w r%d,r%d" % (m, n)

    # 0110nnnnmmmm1100 "extu.b Rm,Rn"
    if (insword & 0xf00f) == 0x600c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "extu.b r%d,r%d" % (m, n)

    # 0110nnnnmmmm1101 "extu.w Rm,Rn"
    if (insword & 0xf00f) == 0x600d:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "extu.w r%d,r%d" % (m, n)

    # 1111nnn001011101 "fabs DRn"
    if (insword & 0xf1ff) == 0xf05d:
        n = (insword & 0xf00)>>8
        return "fabs fr%d" % (n)

    # 1111nnnn01011101 "fabs FRn"
    if (insword & 0xf0ff) == 0xf05d:
        n = (insword & 0xf00)>>8
        return "fabs fr%d" % (n)

    # 1111nnn0mmmm0000 "fadd DRm,DRn"
    if (insword & 0xf10f) == 0xf000:
        m = (insword & 0xF0)>>4
        n = (insword & 0xf00)>>8
        return "fadd fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm0000 "fadd FRm,FRn"
    if (insword & 0xf00f) == 0xf000:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fadd fr%d,fr%d" % (m, n)

    # 1111nnn0mmmm0100 "fcmp/eq DRm,DRn"
    if (insword & 0xf11f) == 0xf004:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fcmp/eq fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm0100 "fcmp/eq FRm,FRn"
    if (insword & 0xf00f) == 0xf004:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fcmp/eq fr%d,fr%d" % (m, n)

    # 1111nnn0mmm00101 "fcmp/gt DRm,DRn"
    if (insword & 0xf11f) == 0xf005:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fcmp/gt fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm0101 "fcmp/gt FRm,FRn"
    if (insword & 0xf00f) == 0xf005:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fcmp/gt fr%d,fr%d" % (m, n)

    # 1111mmm010111101 "fcnvds DRm,fpul"
    if (insword & 0xf1ff) == 0xf0bd:
        m = (insword & 0xf00)>>8
        return "fcnvds dr%d,fpul" % (m)

    # 1111nnn010101101 "fcnvsd fpul,DRn"
    if (insword & 0xf1ff) == 0xf0ad:
        n = (insword & 0xf00)>>8
        return "fcnvsd fpul,dr%d" % (n)

    # 1111nnn0mmmm0011 "fdiv DRm,DRn"
    if (insword & 0xf10f) == 0xf003:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fdiv fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm0011 "fdiv FRm,FRn"
    if (insword & 0xf00f) == 0xf003:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fdiv fr%d,fr%d" % (m, n)

    # 1111nnmm11101101 "fipr fvm,fvn"
    if (insword & 0xf0ff) == 0xf0ed:
        m = (insword & 0x300)>>8
        n = (insword & 0xc00)>>10
        return "fipr fv%d,fv%d" % (4*m,4*n)

    # 1111nnnn10001101 "fldi0 FRn"
    if (insword & 0xf0ff) == 0xf08d:
        n = (insword & 0xf00)>>8
        return "fldi0 fr%d" % (n)

    # 1111nnnn10011101 "fldi1 FRn"
    if (insword & 0xf0ff) == 0xf09d:
        n = (insword & 0xf00)>>8
        return "fldi1 fr%d" % (n)

    # 1111mmmm00011101 "flds FRm,fpul"
    if (insword & 0xf0ff) == 0xf01d:
        m = (insword & 0xf00)>>8
        return "flds fr%d,fpul" % (m)

    # 1111nnn000101101 "float fpul,DRn"
    if (insword & 0xf1ff) == 0xf02d:
        n = (insword & 0xf00)>>8
        return "float fpul,fr%d" % (n)

    # 1111nnnn00101101 "float fpul,FRn"
    if (insword & 0xf0ff) == 0xf02d:
        n = (insword & 0xf00)>>8
        return "float fpul,fr%d" % (n)

    # 1111nnnnmmmm1110 "fmac fr0,FRm,FRn"
    if (insword & 0xf00f) == 0xf00e:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmac fr0,fr%d,fr%d" % (m, n)

    # 1111nnn0mmm01100 "fmov DRm,DRn"
    if (insword & 0xf11f) == 0xf00c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,fr%d" % (m, n)

    # 1111nnn1mmm01100 "fmov DRm,XDn"
    if (insword & 0xf11f) == 0xf10c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm1100 "fmov FRm,FRn"
    if (insword & 0xf00f) == 0xf00c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,fr%d" % (m, n)

    # 1111nnn0mmm11100 "fmov XDm,DRn"
    if (insword & 0xf11f) == 0xf01c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov XD%d,fr%d" % (m, n)

    # 1111nnn1mmm11100 "fmov XDm,XDn"
    if (insword & 0xf11f) == 0xf11c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov XD%d,fr%d" % (m, n)

    # 1111nnn0mmmm0110 "fmov @(r0,Rm),DRn"
    if (insword & 0xf10f) == 0xf006:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov @(r0,r%d),fr%d" % (m, n)

    # 1111nnnnmmmm0110 "fmov @(r0,Rm),XDn"
    if (insword & 0xf10f) == 0xf106:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov @(r0,r%d),fr%d" % (m, n)

    # 1111nnn0mmmm1001 "fmov @Rm+,DRn"
    if (insword & 0xf10f) == 0xf009:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov @r%d+,fr%d" % (m, n)

    # 1111nnnnmmmm1001 "fmov @Rm+,XDn"
    if (insword & 0xf10f) == 0xf109:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov @r%d+,fr%d" % (m, n)

    # 1111nnn0mmmm1000 "fmov @Rm,DRn"
    if (insword & 0xf10f) == 0xf008:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov @r%d,fr%d" % (m, n)

    # 1111nnnnmmmm1000 "fmov @Rm,XDn"
    if (insword & 0xf10f) == 0xf108:
        m = (insword & 0xf0)>>4
        n = (insword & 0xF00)>>8
        return "fmov @r%d,fr%d" % (m, n)

    # 1111nnnnmmm00111 "fmov DRm,@(r0,Rn)"
    if (insword & 0xf01f) == 0xf007:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,@(r0,r%d)" % (m, n)

    # 1111nnnnmmm01011 "fmov DRm,@-Rn"
    if (insword & 0xf01f) == 0xf00b:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,@-r%d" % (m, n)

    # 1111nnnnmmm01010 "fmov DRm,@Rn"
    if (insword & 0xf01f) == 0xf00a:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,@r%d" % (m, n)

    # 1111nnnnmmmm0111 "fmov XDm,@(r0,Rn)"
    if (insword & 0xf00f) == 0xf007:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,@(r0,r%d)" % (m, n)

    # 1111nnnnmmm11011 "fmov XDm,@-Rn"
    if (insword & 0xf00f) == 0xf00b:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,@-r%d" % (m, n)

    # 1111nnnnmmmm1010 "fmov XDm,@Rn"
    if (insword & 0xf00f) == 0xf00a:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov fr%d,@r%d" % (m, n)

    # 1111nnnnmmmm0110 "fmov.s @(r0,Rm),FRn"
    if (insword & 0xf00f) == 0xf006:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov.s @(r0,r%d),fr%d" % (m, n)

    # 1111nnnnmmmm1001 "fmov.s @Rm+,FRn"
    if (insword & 0xf00f) == 0xf009:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov.s @r%d+,fr%d" % (m, n)

    # 1111nnnnmmmm1000 "fmov.s @Rm,FRn"
    if (insword & 0xf00f) == 0xf008:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov.s @r%d,fr%d" % (m, n)

    # 1111nnnnmmmm0111 "fmov.s FRm,@(r0,Rn)"
    if (insword & 0xf00f) == 0xf007:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov.s fr%d,@(r0,r%d)" % (m, n)

    # 1111nnnnmmmm1011 "fmov.s FRm,@-Rn"
    if (insword & 0xf00f) == 0xf00b:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov.s fr%d,@-r%d" % (m, n)

    # 1111nnnnmmmm1010 "fmov.s FRm,@Rn"
    if (insword & 0xf00f) == 0xf00a:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmov.s fr%d,@r%d" % (m, n)

    # 1111nnn0mmmm0010 "fmul DRm,DRn"
    if (insword & 0xf10f) == 0xf002:
        m = (insword & 0xF0)>>4
        n = (insword & 0xf00)>>8
        return "fmul fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm0010 "fmul FRm,FRn"
    if (insword & 0xf00f) == 0xf002:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fmul fr%d,fr%d" % (m, n)

    # 1111nnn001001101 "fneg DRn"
    if (insword & 0xf1ff) == 0xf04d:
        n = (insword & 0xf00)>>8
        return "fneg fr%d" % (n)

    # 1111nnnn01001101 "fneg FRn"
    if (insword & 0xf0ff) == 0xf04d:
        n = (insword & 0xf00)>>8
        return "fneg fr%d" % (n)

    # 1111101111111101 "frchg"
    if insword == 0xfbfd:
        return "frchg"

    # 1111001111111101 "fschg"
    if insword == 0xf3fd:
        return "fschg"

    # 1111nnn001101101 "fsqrt DRn"
    if (insword & 0xf1ff) == 0xf06d:
        n = (insword & 0xf00)>>8
        return "fsqrt fr%d" % (n)

    # 1111nnnn01101101 "fsqrt FRn"
    if (insword & 0xf0ff) == 0xf06d:
        n = (insword & 0xf00)>>8
        return "fsqrt fr%d" % (n)

    # 1111nnnn00001101 "fsts fpul,FRn"
    if (insword & 0xf0ff) == 0xf00d:
        n = (insword & 0xf00)>>8
        return "fsts fpul,fr%d" % (n)

    # 1111nnn0mmmm0001 "fsub DRm,DRn"
    if (insword & 0xf10f) == 0xf001:
        m = (insword & 0xF0)>>4
        n = (insword & 0xf00)>>8
        return "fsub fr%d,fr%d" % (m, n)

    # 1111nnnnmmmm0001 "fsub FRm,FRn"
    if (insword & 0xf00f) == 0xf001:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "fsub fr%d,fr%d" % (m, n)

    # 1111mmm000111101 "ftrc DRm,fpul"
    if (insword & 0xf1ff) == 0xf03d:
        m = (insword & 0xf00)>>8
        return "ftrc fr%d,fpul" % (m)

    # 1111mmmm00111101 "ftrc FRm,fpul"
    if (insword & 0xf0ff) == 0xf03d:
        m = (insword & 0xf00)>>8
        return "ftrc fr%d,fpul" % (m)

    # 1111nn0111111101 "ftrv xmtrx,fvn"
    if (insword & 0xf3ff) == 0xf1fd:
        n = (insword & 0xc00)>>10
        return "ftrv xmtrx,fv%d" % (4*n)

    # 0100mmmm00101011 "jmp @Rm"
    if (insword & 0xf0ff) == 0x402b:
        m = (insword & 0xf00)>>8
        return "jmp @r%d" % (m)

    # 0100mmmm00001011 "jsr @Rm"
    if (insword & 0xf0ff) == 0x400b:
        m = (insword & 0xf00)>>8
        return "jsr @r%d" % (m)

    # 0100mmmm11110110 "ldc Rm,dbr"
    if (insword & 0xf0ff) == 0x40f6:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,dbr" % (m)

    # MANUAL
    if (insword & 0xf0ff) == 0x40fa:
        m = (insword & 0xf00)>>8
        return "ldc r%d,dbr" % (m)

    # 0100mmmm00011110 "ldc Rm,gbr"
    if (insword & 0xf0ff) == 0x401e:
        m = (insword & 0xf00)>>8
        return "ldc r%d,gbr" % (m)

    # 0100mmmm1nnn1110 "ldc Rm,Rn_bank"
    if (insword & 0xf08f) == 0x408e:
        m = (insword & 0xf00)>>8
        n = (insword & 0x70)>>4
        return "ldc r%d,r%d_bank" % (m, n)

    # 0100mmmm01001110 "ldc Rm,spc"
    if (insword & 0xf0ff) == 0x404e:
        m = (insword & 0xf00)>>8
        return "ldc r%d,spc" % (m)

    # 0100mmmm00001110 "ldc Rm,sr"
    if (insword & 0xf0ff) == 0x400e:
        m = (insword & 0xf00)>>8
        return "ldc r%d,sr" % (m)

    # 0100mmmm00111110 "ldc Rm,ssr"
    if (insword & 0xf0ff) == 0x403e:
        m = (insword & 0xf00)>>8
        return "ldc r%d,ssr" % (m)

    # MANUAL
    # 0100mmmm00111010 "ldc Rm,sgr"
    if (insword & 0xf0ff) == 0x403A:
        m = (insword & 0xf00)>>8
        return "ldc r%d,sgr" % (m)

    # 0100mmmm00101110 "ldc Rm,vbr"
    if (insword & 0xf0ff) == 0x402e:
        m = (insword & 0xf00)>>8
        return "ldc r%d,vbr" % (m)

    # 0100mmmm11110110 "ldc.l @Rm+,dbr"
    if (insword & 0xf0ff) == 0x40f6:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,dbr" % (m)

    # MANUAL
    # 0100mmmmnnnn1110
    if (insword & 0xf00f) == 0x400E:
        m = (insword & 0xf00)>>8
        n = (insword & 0xf0)>>4
        if n < 5:
            return "ldc r%d,%s" % (m, ['sr','gbr','vbr','ssr','spc'][n])
        return "ldc r%d,r%d_bank" % (m, n)

    # 0100mmmm00010111 "ldc.l @Rm+,gbr"
    if (insword & 0xf0ff) == 0x4017:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,gbr" % (m)

    # 0100mmmm1nnn0111 "ldc.l @Rm+,Rn_bank"
    if (insword & 0xf08f) == 0x4087:
        m = (insword & 0xf00)>>8
        n = (insword & 0x70)>>4
        return "ldc.l @r%d+,r%d_bank" % (m, n)

    # 0100mmmm01000111 "ldc.l @Rm+,spc"
    if (insword & 0xf0ff) == 0x4047:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,spc" % (m)

    # 0100mmmm00000111 "ldc.l @Rm+,sr"
    if (insword & 0xf0ff) == 0x4007:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,sr" % (m)

    # 0100mmmm00110111 "ldc.l @Rm+,ssr"
    if (insword & 0xf0ff) == 0x4037:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,ssr" % (m)

    # MANUAL
    # 0100mmmm00110110 "ldc.l @Rm+,sgr"
    if (insword & 0xf0ff) == 0x4036:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,sgr" % (m)

    # 0100mmmm00100111 "ldc.l @Rm+,vbr"
    if (insword & 0xf0ff) == 0x4027:
        m = (insword & 0xf00)>>8
        return "ldc.l @r%d+,vbr" % (m)

    # MANUAL
    # 0100mmmmnnnn0111 "ldc.l @Rm+,vbr"
    if (insword & 0xf00f) == 0x4007:
        m = (insword & 0xf00)>>8
        n = (insword & 0xf0)>>4
        if n < 5:
            return "ldc.l @r%d+,%s" % (m, ['sr','gbr','vbr','ssr','spc'][n])
        return "ldc.l @r%d+,r%d_bank" % (m, n)

    # 0100mmmm01101010 "lds Rm,fpscr"
    if (insword & 0xf0ff) == 0x406a:
        m = (insword & 0xf00)>>8
        return "lds r%d,fpscr" % (m)

    # 0100mmmm01011010 "lds Rm,fpul"
    if (insword & 0xf0ff) == 0x405a:
        m = (insword & 0xf00)>>8
        return "lds r%d,fpul" % (m)

    # 0100mmmm00001010 "lds Rm,mach"
    if (insword & 0xf0ff) == 0x400a:
        m = (insword & 0xf00)>>8
        return "lds r%d,mach" % (m)

    # 0100mmmm00011010 "lds Rm,macl"
    if (insword & 0xf0ff) == 0x401a:
        m = (insword & 0xf00)>>8
        return "lds r%d,macl" % (m)

    # 0100mmmm00101010 "lds Rm,pr"
    if (insword & 0xf0ff) == 0x402a:
        m = (insword & 0xf00)>>8
        return "lds r%d,pr" % (m)

    # 0100mmmm01100110 "lds.l @Rm+,fpscr"
    if (insword & 0xf0ff) == 0x4066:
        m = (insword & 0xf00)>>8
        return "lds.l @r%d+,fpscr" % (m)

    # 0100mmmm01010110 "lds.l @Rm+,fpul"
    if (insword & 0xf0ff) == 0x4056:
        m = (insword & 0xf00)>>8
        return "lds.l @r%d+,fpul" % (m)

    # 0100mmmm00000110 "lds.l @Rm+,mach"
    if (insword & 0xf0ff) == 0x4006:
        m = (insword & 0xf00)>>8
        return "lds.l @r%d+,mach" % (m)

    # 0100mmmm00010110 "lds.l @Rm+,macl"
    if (insword & 0xf0ff) == 0x4016:
        m = (insword & 0xf00)>>8
        return "lds.l @r%d+,macl" % (m)

    # 0100mmmm00100110 "lds.l @Rm+,pr"
    if (insword & 0xf0ff) == 0x4026:
        m = (insword & 0xf00)>>8
        return "lds.l @r%d+,pr" % (m)

    # 0000000000111000 "ldtlb"
    if insword == 0x38:
        return "ldtlb"

    # 0000nnnnmmmm1111 "mac.l @Rm+,@Rn+"
    if (insword & 0xf00f) == 0xf:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mac.l @r%d+,@r%d+" % (m, n)

    # 0100nnnnmmmm1111 "mac.w @Rm+,@Rn+"
    if (insword & 0xf00f) == 0x400f:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mac.w @r%d+,@r%d+" % (m, n)

    # 1110nnnniiiiiiii "mov #imm,Rn"
    if (insword & 0xf000) == 0xe000:
        i = int8(insword & 0xff)
        n = (insword & 0xf00)>>8
        return "mov #%d,r%d" % (i,n)

    # 0110nnnnmmmm0011 "mov Rm,Rn"
    if (insword & 0xf00f) == 0x6003:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov r%d,r%d" % (m, n)

    # 0000nnnnmmmm1100 "mov.b @(r0,Rm),Rn"
    if (insword & 0xf00f) == 0xc:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.b @(r0,r%d),r%d" % (m, n)

    # 11000100dddddddd "mov.b @(disp,gbr),r0"
    if (insword & 0xff00) == 0xc400:
        d = insword & 0xff
        return "mov.b @(%d,gbr),r0" % (d)

    # 10000100mmmmdddd "mov.b @(disp,Rm),r0"
    if (insword & 0xff00) == 0x8400:
        d = insword & 0xf
        m = (insword & 0xf0)>>4
        return "mov.b @(%d,r%d),r0" % (d,m)

    # 0110nnnnmmmm0100 "mov.b @Rm+,Rn"
    if (insword & 0xf00f) == 0x6004:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.b @r%d+,r%d" % (m, n)

    # 0110nnnnmmmm0000 "mov.b @Rm,Rn"
    if (insword & 0xf00f) == 0x6000:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.b @r%d,r%d" % (m, n)

    # 11000000dddddddd "mov.b r0,@(disp,gbr)"
    if (insword & 0xff00) == 0xc000:
        d = insword & 0xff
        return "mov.b r0,@(%d,gbr)" % (d)

    # 10000000nnnndddd "mov.b r0,@(disp,Rn)"
    if (insword & 0xff00) == 0x8000:
        d = insword & 0xf
        n = (insword & 0xf0)>>4
        return "mov.b r0,@(%d,r%d)" % (d,n)

    # 0000nnnnmmmm0100 "mov.b Rm,@(r0,Rn)"
    if (insword & 0xf00f) == 0x4:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.b r%d,@(r0,r%d)" % (m, n)

    # 0010nnnnmmmm0100 "mov.b Rm,@-Rn"
    if (insword & 0xf00f) == 0x2004:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.b r%d,@-r%d" % (m, n)

    # 0010nnnnmmmm0000 "mov.b Rm,@Rn"
    if (insword & 0xf00f) == 0x2000:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.b r%d,@r%d" % (m, n)

    # 0000nnnnmmmm1110 "mov.l @(r0,Rm),Rn"
    if (insword & 0xf00f) == 0xe:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l @(r0,r%d),r%d" % (m, n)

    # 11000110dddddddd "mov.l @(disp,gbr),r0"
    if (insword & 0xff00) == 0xc600:
        d = insword & 0xff
        return "mov.l @(%d,gbr),r0" % (4*d)

    # 1101nnnndddddddd "mov.l @(disp,PC),Rn"
    if (insword & 0xf000) == 0xd000:
        displ = insword & 0xff
        eaddr = ((addr >> 2)<<2) + 4 + 4*displ
        n = (insword & 0xf00)>>8
        return "mov.l 0x%016x,r%d" % (eaddr, n)

    # 0101nnnnmmmmdddd "mov.l @(disp,Rm),Rn"
    if (insword & 0xf000) == 0x5000:
        d = insword & 0xf
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l @(%d,r%d),r%d" % (4*d,m,n)

    # 0110nnnnmmmm0110 "mov.l @Rm+,Rn"
    if (insword & 0xf00f) == 0x6006:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l @r%d+,r%d" % (m, n)

    # 0110nnnnmmmm0010 "mov.l @Rm,Rn"
    if (insword & 0xf00f) == 0x6002:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l @r%d,r%d" % (m, n)

    # 11000010dddddddd "mov.l r0,@(disp,gbr)"
    if (insword & 0xff00) == 0xc200:
        d = insword & 0xff
        return "mov.l r0,@(%d,gbr)" % (4*d)

    # 0000nnnnmmmm0110 "mov.l Rm,@(r0,Rn)"
    if (insword & 0xf00f) == 0x6:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l r%d,@(r0,r%d)" % (m, n)

    # 0001nnnnmmmmdddd "mov.l Rm,@(disp,Rn)"
    if (insword & 0xf000) == 0x1000:
        d = insword & 0xf
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l r%d,@(%d,r%d)" % (m,4*d,n)

    # 0010nnnnmmmm0110 "mov.l Rm,@-Rn"
    if (insword & 0xf00f) == 0x2006:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l r%d,@-r%d" % (m, n)

    # 0010nnnnmmmm0010 "mov.l Rm,@Rn"
    if (insword & 0xf00f) == 0x2002:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.l r%d,@r%d" % (m, n)

    # 0000nnnnmmmm1101 "mov.w @(r0,Rm),Rn"
    if (insword & 0xf00f) == 0xd:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.w @(r0,r%d),r%d" % (m, n)

    # 11000101dddddddd "mov.w @(disp,gbr),r0"
    if (insword & 0xff00) == 0xc500:
        d = insword & 0xff
        return "mov.w @(%d,gbr),r0" % (2*d)

    # 1001nnnndddddddd "mov.w @(disp,PC),Rn"
    if (insword & 0xf000) == 0x9000:
        d = (addr+4) + 2*(insword & 0xff)
        n = (insword & 0xf00)>>8
        return "mov.w 0x%016x,r%d" % (d,n)

    # 10000101mmmmdddd "mov.w @(disp,Rm),r0"
    if (insword & 0xff00) == 0x8500:
        d = insword & 0xf
        m = (insword & 0xf0)>>4
        return "mov.w @(%d,r%d),r0" % (2*d,m)

    # 0110nnnnmmmm0101 "mov.w @Rm+,Rn"
    if (insword & 0xf00f) == 0x6005:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.w @r%d+,r%d" % (m, n)

    # 0110nnnnmmmm0001 "mov.w @Rm,Rn"
    if (insword & 0xf00f) == 0x6001:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.w @r%d,r%d" % (m, n)

    # 11000001dddddddd "mov.w r0,@(disp,gbr)"
    if (insword & 0xff00) == 0xc100:
        d = insword & 0xff
        return "mov.w r0,@(%d,gbr)" % (2*d)

    # 10000001nnnndddd "mov.w r0,@(disp,Rn)"
    if (insword & 0xff00) == 0x8100:
        d = insword & 0xf
        n = (insword & 0xf0)>>4
        return "mov.w r0,@(%d,r%d)" % (2*d,n)

    # 0000nnnnmmmm0101 "mov.w Rm,@(r0,Rn)"
    if (insword & 0xf00f) == 0x5:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.w r%d,@(r0,r%d)" % (m, n)

    # 0010nnnnmmmm0101 "mov.w Rm,@-Rn"
    if (insword & 0xf00f) == 0x2005:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.w r%d,@-r%d" % (m, n)

    # 0010nnnnmmmm0001 "mov.w Rm,@Rn"
    if (insword & 0xf00f) == 0x2001:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mov.w r%d,@r%d" % (m, n)

    # 11000111dddddddd "mova @(disp,PC),r0"
    if (insword & 0xff00) == 0xc700:
        displ = insword & 0xff
        eaddr = ((addr >> 2)<<2) + 4 + 4*displ
        return "mova 0x%016x,r0" % eaddr

    # 0000nnnn11000011 "movca.l r0,@Rn"
    if (insword & 0xf0ff) == 0xc3:
        n = (insword & 0xf00)>>8
        return "movca.l r0,@r%d" % (n)

    # 0000nnnn00101001 "movt Rn"
    if (insword & 0xf0ff) == 0x29:
        n = (insword & 0xf00)>>8
        return "movt r%d" % (n)

    # 0000nnnnmmmm0111 "mul.l Rm,Rn"
    if (insword & 0xf00f) == 0x7:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mul.l r%d,r%d" % (m, n)

    # 0010nnnnmmmm1111 "muls.w Rm,Rn"
    if (insword & 0xf00f) == 0x200f:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "muls.w r%d,r%d" % (m, n)

    # 0010nnnnmmmm1110 "mulu.w Rm,Rn"
    if (insword & 0xf00f) == 0x200e:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "mulu.w r%d,r%d" % (m, n)

    # 0110nnnnmmmm1011 "neg Rm,Rn"
    if (insword & 0xf00f) == 0x600b:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "neg r%d,r%d" % (m, n)

    # 0110nnnnmmmm1010 "negc Rm,Rn"
    if (insword & 0xf00f) == 0x600a:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "negc r%d,r%d" % (m, n)

    # 0000000000001001 "nop"
    if insword == 0x9:
        return "nop"

    # 0110nnnnmmmm0111 "not Rm,Rn"
    if (insword & 0xf00f) == 0x6007:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "not r%d,r%d" % (m, n)

    # 0000nnnn10010011 "ocbi @Rn"
    if (insword & 0xf0ff) == 0x93:
        n = (insword & 0xf00)>>8
        return "ocbi @r%d" % (n)

    # 0000nnnn10100011 "ocbp @Rn"
    if (insword & 0xf0ff) == 0xa3:
        n = (insword & 0xf00)>>8
        return "ocbp @r%d" % (n)

    # 0000nnnn10110011 "ocbwb @Rn"
    if (insword & 0xf0ff) == 0xb3:
        n = (insword & 0xf00)>>8
        return "ocbwb @r%d" % (n)

    # 11001011iiiiiiii "or #imm,r0"
    if (insword & 0xff00) == 0xcb00:
        i = int8(insword & 0xff)
        return "or #%d,r0" % (i)

    # 0010nnnnmmmm1011 "or Rm,Rn"
    if (insword & 0xf00f) == 0x200b:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "or r%d,r%d" % (m, n)

    # 11001111iiiiiiii "or.b #imm,@(r0,gbr)"
    if (insword & 0xff00) == 0xcf00:
        i = int8(insword & 0xff)
        return "or.b #%d,@(r0,gbr)" % (i)

    # 0000nnnn10000011 "pref @Rn"
    if (insword & 0xf0ff) == 0x83:
        n = (insword & 0xf00)>>8
        return "pref @r%d" % (n)

    # 0100nnnn00100100 "rotcl Rn"
    if (insword & 0xf0ff) == 0x4024:
        n = (insword & 0xf00)>>8
        return "rotcl r%d" % (n)

    # 0100nnnn00100101 "rotcr Rn"
    if (insword & 0xf0ff) == 0x4025:
        n = (insword & 0xf00)>>8
        return "rotcr r%d" % (n)

    # 0100nnnn00000100 "rotl Rn"
    if (insword & 0xf0ff) == 0x4004:
        n = (insword & 0xf00)>>8
        return "rotl r%d" % (n)

    # 0100nnnn00000101 "rotr Rn"
    if (insword & 0xf0ff) == 0x4005:
        n = (insword & 0xf00)>>8
        return "rotr r%d" % (n)

    # 0000000000101011 "rte"
    if insword == 0x2b:
        return "rte"

    # 0000000000001011 "rts"
    if insword == 0xb:
        return "rts"

    # 0000000000011000 "sett"
    if insword == 0x18:
        return "sett"

    # 0000000001011000 "sett"
    if insword == 0x58:
        return "sets"

    # 0100nnnnmmmm1100 "shad Rm,Rn"
    if (insword & 0xf00f) == 0x400c:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "shad r%d,r%d" % (m, n)

    # 0100nnnn00100000 "shal Rn"
    if (insword & 0xf0ff) == 0x4020:
        n = (insword & 0xf00)>>8
        return "shal r%d" % (n)

    # 0100nnnn00100001 "shar Rn"
    if (insword & 0xf0ff) == 0x4021:
        n = (insword & 0xf00)>>8
        return "shar r%d" % (n)

    # 0100nnnnmmmm1101 "shld Rm,Rn"
    if (insword & 0xf00f) == 0x400d:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "shld r%d,r%d" % (m, n)

    # 0100nnnn00000000 "shll Rn"
    if (insword & 0xf0ff) == 0x4000:
        n = (insword & 0xf00)>>8
        return "shll r%d" % (n)

    # 0100nnnn00101000 "shll16 Rn"
    if (insword & 0xf0ff) == 0x4028:
        n = (insword & 0xf00)>>8
        return "shll16 r%d" % (n)

    # 0100nnnn00001000 "shll2 Rn"
    if (insword & 0xf0ff) == 0x4008:
        n = (insword & 0xf00)>>8
        return "shll2 r%d" % (n)

    # 0100nnnn00011000 "shll8 Rn"
    if (insword & 0xf0ff) == 0x4018:
        n = (insword & 0xf00)>>8
        return "shll8 r%d" % (n)

    # 0100nnnn00000001 "shlr Rn"
    if (insword & 0xf0ff) == 0x4001:
        n = (insword & 0xf00)>>8
        return "shlr r%d" % (n)

    # 0100nnnn00101001 "shlr16 Rn"
    if (insword & 0xf0ff) == 0x4029:
        n = (insword & 0xf00)>>8
        return "shlr16 r%d" % (n)

    # 0100nnnn00001001 "shlr2 Rn"
    if (insword & 0xf0ff) == 0x4009:
        n = (insword & 0xf00)>>8
        return "shlr2 r%d" % (n)

    # 0100nnnn00011001 "shlr8 Rn"
    if (insword & 0xf0ff) == 0x4019:
        n = (insword & 0xf00)>>8
        return "shlr8 r%d" % (n)

    # 0000000000011011 "sleep"
    if insword == 0x1b:
        return "sleep"

    # 0000nnnn1mmm0010 "stc Rn,Rm_bank"
    if (insword & 0xF08F) == 0x0082:
        n = (insword & 0xf00)>>8
        m = (insword & 0x70)>>4
        return "stc r%d_bank,r%d" % (m, n)

    # 0000nnnn11111010 "stc dbr,Rn"
    if (insword & 0xf0ff) == 0xfa:
        n = (insword & 0xf00)>>8
        return "stc dbr,r%d" % (n)

    # 0000nnnn00010010 "stc gbr,Rn"
    if (insword & 0xf0ff) == 0x12:
        n = (insword & 0xf00)>>8
        return "stc gbr,r%d" % (n)

    # 0000nnnn00111010 "stc sgr,Rn"
    if (insword & 0xf0ff) == 0x3a:
        n = (insword & 0xf00)>>8
        return "stc sgr,r%d" % (n)

    # 0000nnnn01000010 "stc spc,Rn"
    if (insword & 0xf0ff) == 0x42:
        n = (insword & 0xf00)>>8
        return "stc spc,r%d" % (n)

    # 0000nnnn00000010 "stc sr,Rn"
    if (insword & 0xf0ff) == 0x2:
        n = (insword & 0xf00)>>8
        return "stc sr,r%d" % (n)

    # 0000nnnn00110010 "stc ssr,Rn"
    if (insword & 0xf0ff) == 0x32:
        n = (insword & 0xf00)>>8
        return "stc ssr,r%d" % (n)

    # 0000nnnn00100010 "stc vbr,Rn"
    if (insword & 0xf0ff) == 0x22:
        n = (insword & 0xf00)>>8
        return "stc vbr,r%d" % (n)

    # MANUAL
    # 0000nnnn1mmm0010 "stc Rm_bank,Rn"
    if (insword & 0xf08f) == 0x82:
        m = (insword & 0x70)>>4
        n = (insword & 0xf00)>>8
        return "stc r%d_bank,r%d" % (m, n)

    # MANUAL
    # 0000nnnn0mmm0010 "stc Rm_bank,Rn"
    if (insword & 0xf08f) == 0x2:
        m = (insword & 0x70)>>4
        n = (insword & 0xf00)>>8
        if m < 5:
            return "stc %s,r%d" % (['sr','gbr','vbr','ssr','spc'][m],n)
        return "stc r%d_bank,r%d" % (m, n)

    # 0100nnnn11110010 "stc.l dbr,@-Rn"
    if (insword & 0xf0ff) == 0x40f2:
        n = (insword & 0xf00)>>8
        return "stc.l dbr,@-r%d" % (n)

    # 0100nnnn00010011 "stc.l gbr,@-Rn"
    if (insword & 0xf0ff) == 0x4013:
        n = (insword & 0xf00)>>8
        return "stc.l gbr,@-r%d" % (n)

    # 0100nnnn1mmm0011 "stc.l Rm_bank,@-Rn"
    if (insword & 0xf08f) == 0x4083:
        m = (insword & 0x70)>>4
        n = (insword & 0xf00)>>8
        return "stc.l r%d_bank,@-r%d" % (m, n)

    # MANUAL
    # 0100nnnn0mmm0011 "stc.l Rm_bank,@-Rn"
    if (insword & 0xf08f) == 0x4003:
        m = (insword & 0x70)>>4
        n = (insword & 0xf00)>>8
        if m < 5:
            return "stc.l %s,@-r%d" % (['sr','gbr','vbr','ssr','spc'][m],n)
        return "stc.l r%d_bank,@-r%d" % (m, n)

    # 0100nnnn00110010 "stc.l sgr,@-Rn"
    if (insword & 0xf0ff) == 0x4032:
        n = (insword & 0xf00)>>8
        return "stc.l sgr,@-r%d" % (n)

    # 0100nnnn01000011 "stc.l spc,@-Rn"
    if (insword & 0xf0ff) == 0x4043:
        n = (insword & 0xf00)>>8
        return "stc.l spc,@-r%d" % (n)

    # 0100nnnn00000011 "stc.l sr,@-Rn"
    if (insword & 0xf0ff) == 0x4003:
        n = (insword & 0xf00)>>8
        return "stc.l sr,@-r%d" % (n)

    # 0100nnnn00110011 "stc.l ssr,@-Rn"
    if (insword & 0xf0ff) == 0x4033:
        n = (insword & 0xf00)>>8
        return "stc.l ssr,@-r%d" % (n)

    # 0100nnnn00100011 "stc.l vbr,@-Rn"
    if (insword & 0xf0ff) == 0x4023:
        n = (insword & 0xf00)>>8
        return "stc.l vbr,@-r%d" % (n)

    # 0000nnnn01101010 "sts fpscr,Rn"
    if (insword & 0xf0ff) == 0x6a:
        n = (insword & 0xf00)>>8
        return "sts fpscr,r%d" % (n)

    # 0000nnnn01011010 "sts fpul,Rn"
    if (insword & 0xf0ff) == 0x5a:
        n = (insword & 0xf00)>>8
        return "sts fpul,r%d" % (n)

    # 0000nnnn00001010 "sts mach,Rn"
    if (insword & 0xf0ff) == 0xa:
        n = (insword & 0xf00)>>8
        return "sts mach,r%d" % (n)

    # 0000nnnn00011010 "sts macl,Rn"
    if (insword & 0xf0ff) == 0x1a:
        n = (insword & 0xf00)>>8
        return "sts macl,r%d" % (n)

    # 0000nnnn00101010 "sts pr,Rn"
    if (insword & 0xf0ff) == 0x2a:
        n = (insword & 0xf00)>>8
        return "sts pr,r%d" % (n)

    # 0100nnnn01100010 "sts.l fpscr,@-Rn"
    if (insword & 0xf0ff) == 0x4062:
        n = (insword & 0xf00)>>8
        return "sts.l fpscr,@-r%d" % (n)

    # 0100nnnn01010010 "sts.l fpul,@-Rn"
    if (insword & 0xf0ff) == 0x4052:
        n = (insword & 0xf00)>>8
        return "sts.l fpul,@-r%d" % (n)

    # 0100nnnn00000010 "sts.l mach,@-Rn"
    if (insword & 0xf0ff) == 0x4002:
        n = (insword & 0xf00)>>8
        return "sts.l mach,@-r%d" % (n)

    # 0100nnnn00010010 "sts.l macl,@-Rn"
    if (insword & 0xf0ff) == 0x4012:
        n = (insword & 0xf00)>>8
        return "sts.l macl,@-r%d" % (n)

    # 0100nnnn00100010 "sts.l pr,@-Rn"
    if (insword & 0xf0ff) == 0x4022:
        n = (insword & 0xf00)>>8
        return "sts.l pr,@-r%d" % (n)

    # 0011nnnnmmmm1000 "sub Rm,Rn"
    if (insword & 0xf00f) == 0x3008:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "sub r%d,r%d" % (m, n)

    # 0011nnnnmmmm1010 "subc Rm,Rn"
    if (insword & 0xf00f) == 0x300a:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "subc r%d,r%d" % (m, n)

    # 0011nnnnmmmm1011 "subv Rm,Rn"
    if (insword & 0xf00f) == 0x300b:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "subv r%d,r%d" % (m, n)

    # 0110nnnnmmmm1000 "swap.b Rm,Rn"
    if (insword & 0xf00f) == 0x6008:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "swap.b r%d,r%d" % (m, n)

    # 0110nnnnmmmm1001 "swap.w Rm,Rn"
    if (insword & 0xf00f) == 0x6009:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "swap.w r%d,r%d" % (m, n)

    # 0100nnnn00011011 "tas.b @Rn"
    if (insword & 0xf0ff) == 0x401b:
        n = (insword & 0xf00)>>8
        return "tas.b @r%d" % (n)

    # 11000011iiiiiiii "trapa #imm"
    if (insword & 0xff00) == 0xc300:
        i = int8(insword & 0xff)
        return "trapa #%d" % (i)

    # 11001000iiiiiiii "tst #imm,r0"
    if (insword & 0xff00) == 0xc800:
        i = int8(insword & 0xff)
        return "tst #%d,r0" % (i)

    # 0010nnnnmmmm1000 "tst Rm,Rn"
    if (insword & 0xf00f) == 0x2008:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "tst r%d,r%d" % (m, n)

    # 11001100iiiiiiii "tst.b #imm,@(r0,gbr)"
    if (insword & 0xff00) == 0xcc00:
        i = int8(insword & 0xff)
        return "tst.b #%d,@(r0,gbr)" % (i)

    # 11001010iiiiiiii "xor #imm,r0"
    if (insword & 0xff00) == 0xca00:
        i = int8(insword & 0xff)
        return "xor #%d,r0" % (i)

    # 0010nnnnmmmm1010 "xor Rm,Rn"
    if (insword & 0xf00f) == 0x200a:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "xor r%d,r%d" % (m, n)

    # 11001110iiiiiiii "xor.b #imm,@(r0,gbr)"
    if (insword & 0xff00) == 0xce00:
        i = int8(insword & 0xff)
        return "xor.b #%d,@(r0,gbr)" % (i)

    # 0010nnnnmmmm1101 "xtrct Rm,Rn"
    if (insword & 0xf00f) == 0x200d:
        m = (insword & 0xf0)>>4
        n = (insword & 0xf00)>>8
        return "xtrct r%d,r%d" % (m, n)

    # 1111nnnn01111101 "fsrra Rn"
    if (insword & 0xf0ff) == 0xf07d:
        m = (insword & 0xf00)>>8
        return "fsrra fr%d" % (m)

    # 1111nnn011111101 "fsca fpul, drn"
    if (insword & 0xf1ff) == 0xf0fd:
        m = (insword & 0xE00)>>9
        return "fsca fpul,dr%d" % (2*m)

    # didn't disassemble!
    return ".word 0x%04x" % insword
