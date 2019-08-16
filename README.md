# sh4dis

A python disassembler library for SH4

# Use

```
>>> from sh4dis import sh4
>>> sh4.disasm(0x1234, 0)
'mov.l r3,@(16,r2)'
```

Or, if you'd like access to the instruction internals, like opcode identifier and operands:

```
>>> decoded = sh4.decode(0x1234, 0)
>>> decoded.op
<OP.MOV: 53>
>>> decoded.operands[0]
(<OPER_TYPE.GPREG: 10>, <REG.R3: 4>)
>>> decoded.operands[1]
(<OPER_TYPE.DEREF_REG_IMM: 7>, <REG.R2: 3>, 16)
2
```

The decoded structure can still be made into a string:

```
>>> sh4.disasm(decoded)
'mov.l r3,@(16,r2)'
```
