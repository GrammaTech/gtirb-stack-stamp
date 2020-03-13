from capstone import *
from gtirb import *
from keystone import *
import logging

class Function(object):
    def __init__(self, uuid, entryBlocks=None, blocks=None, name_symbols=None):
        self._uuid = uuid
        self._entryBlocks = entryBlocks
        self._exit_blocks = None
        self._blocks = blocks
        self._name_symbols = name_symbols

    @classmethod
    def build_functions(cls, module):
        functions = []
        for uuid,entryBlocks in module.aux_data['functionEntries'].data.items():
            entryBlocksUUID = set([e.uuid for e in entryBlocks])
            blocks = module.aux_data['functionBlocks'].data[uuid]
            syms = [x for x in \
                    filter(lambda s: s.referent and \
                    s.referent.uuid in entryBlocksUUID, module.symbols)]
            exit_blocks = None
            functions.append(
                    Function( uuid,
                        entryBlocks=entryBlocks,
                        blocks=blocks,
                        name_symbols=syms))
        return functions

    def get_name(self):
        names = [ s.name for s in self._name_symbols ]
        if len(names) == 1:
            return names[0]
        elif len(names) > 2:
            return "{} (a.k.a. {}".format(names[0], ",".join(names[1:]))
        else:
            return "<unknown>"

    def get_entry_blocks(self):
        return self._entryBlocks

    def get_exit_blocks(self):
        if self._exit_blocks is None:
            self._exit_blocks = set()
            for b in self.get_all_blocks():
                for e in b.outgoing_edges:
                    # TODO Handle tail calls (jmp)
                    if e.label.type == Edge.Type.Return:
                        self._exit_blocks.add(b)

        return self._exit_blocks

    def get_all_blocks(self):
        return self._blocks

    def __repr__(self):
        return "[UUID={}, Name={}, Entry={}, Blocks={}]".\
                format(self._uuid, self.get_name(), self._entryBlocks, self._blocks)

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
            self.cp = Cs(CS_ARCH_X86, CS_MODE_64)
        else:
            self.cp = cp
        if ks is None:
            # Setup keystone
            self.ks = Ks(KS_ARCH_X86, KS_MODE_64)
            self.ks.syntax = KS_OPT_SYNTAX_ATT
        else:
            ks = ks
        self.prepare_for_rewriting()

    # Split byte-intervals such that each CodeBlock has it's own byte_interval
    # This is neccessary to facilitate proper layout of fallthrough edges when we
    # start modifying byte_intervals
    def prepare_for_rewriting(self):
        # Split byte intervals such that there is a single interval per codeblock.
        # This allows each to be updated independently.
        for m in self.ir.modules:
            code_blocks = [b for b in m.code_blocks]
            for b in code_blocks:
                if b.offset != 0 or b.size != b.byte_interval.size:
                    self.isolate_byte_interval(m, b)
        # Remove CFI directives for now since we will most likely be invalidating
        # most (or all) of them.
        m.aux_data.pop('cfiDirectives')

    def isolate_byte_interval(self, module, block):
        section = block.byte_interval.section
        bi = block.byte_interval
        new_bi = ByteInterval(
                    contents= bi.contents[block.offset:block.offset+block.size],
                    address=bi.address+block.offset)
        new_bi.section = section

        # Move symbolic expressions over
        ses = filter(
                lambda item: item[0] >= block.offset and \
                        item[0] < block.offset+block.size,
                block.byte_interval.symbolic_expressions.items())
        for se in ses:
            new_bi.symbolic_expressions[se[0] - block.offset] = se[1]

        # Remove this block from the old byte_interval
        bi.blocks.remove(block)
        # Update the block
        block.byte_interval = new_bi
        block.offset = 0

    def modify_block_insert(self, module, block, new_bytes, offset,
                            logger=logging.Logger("null")):
        logger.debug("  Before:")
        self.show_block_asm(block, logger=logger)

        bi = block.byte_interval
        sect = block.byte_interval.section
        new_contents = bi.contents[:offset] + bytes(new_bytes) + bi.contents[offset:]
        new_bi = ByteInterval(
                contents=new_contents,
                address = bi.address + block.offset)
        new_bi.section = sect
        for se_offset,se in bi.symbolic_expressions.items():
            if se_offset < offset:
                new_bi.symbolic_expressions[se_offset] = se
            else:
                new_bi.symbolic_expressions[se_offset+len(new_bytes)] = se

        block.byte_interval = new_bi
        block.offset = 0
        block.size = new_bi.size

        logger.debug("  After:")
        self.show_block_asm(block, logger=logger)

    def show_block_asm(self, block, logger=logging.Logger("null")):
        bytes = block.byte_interval.contents[block.offset:block.offset+block.size]
        for i in self.cp.disasm(bytes, block.byte_interval.address+block.offset):
            logger.debug("\t0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
