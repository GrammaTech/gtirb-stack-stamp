#!/usr/bin/python3

from gtirb import *
import random
import logging
from .rewriting import Function,RewritingContext

def get_function_stamp_value(func):
    # Just choose a random value for the stamp values.  An option for a
    # deterministic value is to take a hash of the function name or beginning
    # EA.
    random.seed(func.get_name())
    return (random.randint(0,2**32), random.randint(0,2**32))

def apply_stack_stamp(ir, logger=logging.Logger("null"), context=None):
    logger.info("Preparing IR for rewriting...")
    ctx = RewritingContext(ir) if context is None else context
    for m in ctx.ir.modules:
        functions = Function.build_functions(m)
        for f in functions:
            stamp_function(m, f, ctx, logger=logger)

def stamp_function(module, func, ctx, logger=logging.Logger("null")):
    logger.debug('\nStamping function: %s'%func.get_name())
    if len(func.get_exit_blocks()) == 0:
        logger.debug("- No function returns, skipping")
        return
    if len(func.get_entry_blocks()) == 0:
        logger.debug("- No function entry blocks, skipping")
        return

    (w1,w2) = get_function_stamp_value(func)
    asm = "xorl $0x{:X},(%rsp);".format(w1) + \
          "xorl $0x{:X},4(%rsp);".format(w2)
    encoding, count = ctx.ks.asm(asm)

    logger.debug('- Entry blocks')
    for b in func.get_entry_blocks():
        bytes = b.byte_interval.contents[b.offset:b.offset+b.size]
        new_bytes = bytearray(encoding) + bytes
        ctx.modify_block_insert(module, b, encoding, 0, logger=logger)

    logger.debug('- Exit blocks')
    for b in func.get_exit_blocks():
        bytes = b.byte_interval.contents[b.offset:b.offset+b.size]
        offset = 0
        # Find the offset of the ret instruction, and insert our bytes just
        # before.
        for i in ctx.cp.disasm(bytes, 0):
            if i.mnemonic == 'ret':
                ctx.modify_block_insert(module, b, encoding, offset,
                        logger=logger)
                break
            else:
                offset += i.size





