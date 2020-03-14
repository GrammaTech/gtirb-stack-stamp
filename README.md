# gtirb-stack-stamp

The goal of the stack stamp transform is to encode the return address on the
stack and decode it just before it is used.  This technique can mitigate some
ROP style attacks.

To accomplish this, for each function, instructions are added on entry and at
each exit, that encode the return address.  The location of the return address
is known relative to the current stack pointer at entry and exit.  We will use
a simple XOR operation to do this, meaning the encoding and decoding
instructions will be the same and just need to XOR the return address with some
value.  We will select a random value for each function, making this harder to
defeat than if we selected the same value for the entire binary.

On function entry, rsp points to the return address, so the indirect access
[rsp] will access the return address.  We want to encode all 8 bytes of the
return address, but there is no 64-bit immediate version of xor, so we will do
it with two instructions, 4 bytes each.  Since XOR is symmetric, the same
instructions will decode the return address on exit.

  xorl 00112233, [rsp-8]
  xorl 44556677, [rsp-4]

When changing instructions (including adding or removing) one must be careful to
consider if flags or registers are live and if they will be affected by your
changes.  In our case flags will be affected, but the ABI (application binary
interface) states that flags are not preserved across function calls so this
should not be a problem.  We are not using any registers so that should be fine
as well.

In addition to considering that functions may have multiple exits, there is
another case that need to be considered.  Tail calls are cases where a function
exits by jumping to another function, rather than returning or calling.  This
needs special attention, since a jmp instruction does not always indicate an
function boundary, but if it does, we would need to decode the return address
before the jump.

  1. Identify basic blocks that encompass a function
  2. Identify entry and exit basic blocks for each function
  3. Insert encoding instructions at the start of each entry block
  4. Insert decoding instructions in each exit block, just before the return or
      jump instruction.

## Identify function blocks (1)

This first part is done for us.  GTIRB contains an auxdata table that lists the
basic blocks that encompass each function, along with the entry block for each.

TDB - call out auxdata names

## Identify entry/exit blocks (2)

As mentioned in the previous section, the entry block for each function is
identified for us already in TBD.

The exit blocks can be identified by looking at the cfg edges.  Any block that
has an edge with a target block that is not within the set of blocks
encompassing this function, is likely an exit block.

## Insert entry instructions (3)

Entry instructions should be placed immediately on entry, i.e. before all
instructions in the entry block for the function.

GTIRB only includes the raw bytes for each basic block with no instruction
semantics or mnemonics.  To insert new instructions, we modify the byte sequence
of the basic block.  For entry we don't care and can just insert the new
instruction bytes before the existing bytes.

We do this using the Keystone assembler package.  Given instructions in string
form, it will give us a sequence of assembled bytes we can insert in the block.

## Insert exit instructions (4)

Exit instructions need to be placed immediately before the last instruction of
each entry block.  To identify the last instruction we can use the Capstone
disassembler package.  Given the bytes in a basic block we can disassemble the
block, identify the last instruction to confirm it is what we expect, and see
how many bytes it is so we know where to insert our new bytes.  Again we'll do
so using the Keystone assembler.

# Getting started

To start, make sure gtirb, keystone, and capstone are installed in python.

```
pip3 install keystone-engine capstone TBD-GTIRB

git clone https://github.com/keystone-engine/keystone.git
cd keystone
mkdir build
cd build
../make-share.sh
make install
```

## Rewriting steps

gtirb-pprinter:jrobbins/use-symbol-type
ddisasm:jrobbins/use-symbol-type

  1. Build IR
    `ddisasm factorial -i factorial.gtirb`
  2. Stack stamp it
    `python3 stack_stamp.py factorial.gtirb -o factorial.stamp.gtirb`
  3. Rebuild it
    `gtirb-binary-printer factorial.stamp.gtirb -b factorial.stamp -c -no-pie`
