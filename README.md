Stack Stamp
===========

TRL: 6

Transform to apply 'stack stamping' protections to a binary.

![stack-stamp signature graphic.](.stack-stamp.svg)

# Abstract

Stack stamping is a technique to help mitigate ROP style attacks.  This is done
by 'stamping' the return address on the stack, thus encrypting it.  Before it is
popped off the stack and used, it is decrypted by 'unstamping' it.  This can be
an efficient protection, as no registers are needed, and while flags are affected,
they are only affected at function entry/exits where they do not need to be
preserved.  By encoding and decoding this return address, an attacker has a more
difficult task, since the replacement data would need to be properly encoded,
such that when it is unstamped, it results in the desired address.

## Copyright and Acknowledgments

Copyright (C) 2020 GrammaTech, Inc.

This code is licensed under the MIT license. See the LICENSE file in
the project root for license terms.

This project is sponsored by the Office of Naval Research, One Liberty
Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
N68335-17-C-0700.  The content of the information does not necessarily
reflect the position or policy of the Government and no official
endorsement should be inferred.
