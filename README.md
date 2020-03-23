# Stack Stamp

Transform to apply 'stack stamping' protections to a binary.

# Abstract

Stack stamping is a technique to help mitigate ROP style attacks.  This is done
by 'stamping' the return address on the stack, thus encrypting it.  Before it is
popped off the stack and used, it is decrypted by 'unstamping' it.  This can be
an efficient protection, as no registers are needed, and while flags are affected,
they are only affected at function entry/exits where they do not need to be
preserved.  By encoding and decoding this return address, an attacker has a more
difficult task, since the replacement data would need to be properly encoded,
such that when it is unstamped, it results in the desired address.
