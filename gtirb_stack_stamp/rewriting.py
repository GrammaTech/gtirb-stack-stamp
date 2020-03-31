import capstone
from gtirb import ByteInterval
import keystone
import logging


# Simple class to carry around our ir and associated capstone/keystone objects
# for use in rewriting that IR
class RewritingContext(object):
    cp = None
    ks = None
    ir = None

    def __init__(self, ir, cp=None, ks=None):
        self.ir = ir
        # Setup capstone
        if cp is None:
            self.cp = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            self.cp = cp
        if ks is None:
            # Setup keystone
            self.ks = keystone.Ks(keystone.KS_ARCH_X86, keystone.KS_MODE_64)
            self.ks.syntax = keystone.KS_OPT_SYNTAX_ATT
        else:
            self.ks = ks
        self.prepare_for_rewriting()

    # Split byte-intervals such that each CodeBlock has it's own byte_interval
    # This is neccessary to facilitate proper layout of fallthrough edges when
    # we start modifying byte_intervals
    def prepare_for_rewriting(self):
        # Split byte intervals such that there is a single interval per
        # codeblock.  This allows each to be updated independently.
        for m in self.ir.modules:
            code_blocks = [b for b in m.code_blocks]
            for b in code_blocks:
                if b.offset != 0 or b.size != b.byte_interval.size:
                    self.isolate_byte_interval(m, b)
        # Remove CFI directives for now since we will most likely be
        # invalidating most (or all) of them.
        m.aux_data.pop("cfiDirectives")

    def isolate_byte_interval(self, module, block):
        section = block.byte_interval.section
        bi = block.byte_interval
        new_bi = ByteInterval(
            contents=bi.contents[block.offset : block.offset + block.size],
            address=bi.address + block.offset,
        )
        new_bi.section = section

        # Move symbolic expressions over
        ses = filter(
            lambda item: item[0] >= block.offset
            and item[0] < block.offset + block.size,
            block.byte_interval.symbolic_expressions.items(),
        )
        for se in ses:
            new_bi.symbolic_expressions[se[0] - block.offset] = se[1]

        # Remove this block from the old byte_interval
        bi.blocks.remove(block)
        # Update the block
        block.byte_interval = new_bi
        block.offset = 0

    def modify_block_insert(
        self, module, block, new_bytes, offset, logger=logging.Logger("null")
    ):
        logger.debug("  Before:")
        self.show_block_asm(block, logger=logger)

        bi = block.byte_interval
        sect = block.byte_interval.section
        new_contents = (
            bi.contents[:offset] + bytes(new_bytes) + bi.contents[offset:]
        )
        new_bi = ByteInterval(
            contents=new_contents, address=bi.address + block.offset
        )
        new_bi.section = sect
        for se_offset, se in bi.symbolic_expressions.items():
            if se_offset < offset:
                new_bi.symbolic_expressions[se_offset] = se
            else:
                new_bi.symbolic_expressions[se_offset + len(new_bytes)] = se

        block.byte_interval = new_bi
        block.offset = 0
        block.size = new_bi.size

        logger.debug("  After:")
        self.show_block_asm(block, logger=logger)

    def show_block_asm(self, block, logger=logging.Logger("null")):
        bytes = block.byte_interval.contents[
            block.offset : block.offset + block.size
        ]
        for i in self.cp.disasm(
            bytes, block.byte_interval.address + block.offset
        ):
            logger.debug("\t0x%x:\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
