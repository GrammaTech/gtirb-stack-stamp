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
it with two instructions, 4 bytes each.  Since XOR is symetric, the same
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

## Identify entry/exit blocks (2)

## Insert entry instructions (3)

## Insert exit instructions (4)



