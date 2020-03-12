#!/usr/bin/python3

import argparse
import sys
from capstone import *
import gtirb
from gtirb import *
from keystone import *
import subprocess

def progress(msg, **kwargs):
    if sys.stdout.isatty():
        print(msg, **kwargs)


ap = argparse.ArgumentParser(description="Show (un)reachable code in GTIRB")
ap.add_argument("infile")
ap.add_argument("-o", "--outfile", default=None, help="Specification output")
ap.add_argument("--rebuild", default=None, help="rebuild binary as NAME")
ap.add_argument(
    "-q",
    "--quiet",
    default=False,
    action="store_true",
    help="Do not show progress info.",
)
args = ap.parse_args()

if not args.quiet:
    progress("Loading IR...")
ir = IR.load_protobuf(args.infile)

md = Cs(CS_ARCH_X86, CS_MODE_64)

ks = Ks(KS_ARCH_X86, KS_MODE_64)
ks.syntax = KS_OPT_SYNTAX_ATT

class Function(object):
    def __init__(self, uuid, entryBlocks=None, blocks=None, name_symbols=None):
        self._uuid = uuid
        self._entryBlocks = entryBlocks
        self._exit_blocks = None
        self._blocks = blocks
        self._name_symbols = name_symbols

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
                    if e.label.type == gtirb.cfg.Edge.Type.Return:
                        self._exit_blocks.add(b)

        return self._exit_blocks

    def get_all_blocks(self):
        return self._blocks

    def __repr__(self):
        return "[UUID={}, Name={}, Entry={}, Blocks={}]".\
                format(self._uuid, self.get_name(), self._entryBlocks, self._blocks)

def build_functions(module):
    functions = []
    for uuid,entryBlocks in m.aux_data['functionEntries'].data.items():
        entryBlocksUUID = set([e.uuid for e in entryBlocks])
        blocks = m.aux_data['functionBlocks'].data[uuid]
        syms = [x for x in \
                filter(lambda s: s.referent and \
                s.referent.uuid in entryBlocksUUID, module.symbols)]
        for b in blocks:
            if isinstance(b, DataBlock):
                print(b.outgoing_edges)
        exit_blocks = None
        functions.append(
                Function( uuid,
                    entryBlocks=entryBlocks,
                    blocks=blocks,
                    name_symbols=syms))
    return functions

def show_block_asm(block):
    bytes = block.byte_interval.contents[block.offset:block.offset+block.size]
    for i in md.disasm(bytes, block.byte_interval.address+block.offset):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def stamp_it(module, func):
    print('Stamping function: %s'%func.get_name())
    encoding, count = ks.asm(b"xorl $0x26344873,(%rsp);"+
                             b"xorl $0x899322a4,4(%rsp);")

    if len(func.get_exit_blocks()) == 0:
        print("* No function returns, skipping")
        return

    print('* Entries')
    for b in func.get_entry_blocks():
        bytes = b.byte_interval.contents[b.offset:b.offset+b.size]
        new_bytes = bytearray(encoding) + bytes
        modify_block_insert(module, b, encoding, 0, debug=True)

    print('* Exits')
    for b in func.get_exit_blocks():
        bytes = b.byte_interval.contents[b.offset:b.offset+b.size]
        offset = 0
        for i in md.disasm(bytes, 0):
            if i.mnemonic == 'ret':
                modify_block_insert(module, b, encoding, offset, debug=True)
                break
            else:
                offset += i.size

def modify_block_insert(module, block, new_bytes, offset, debug=False):
    if debug:
        print("Before:")
        show_block_asm(block)
    bi = block.byte_interval
    sect = block.byte_interval.section
    new_contents = bi.contents[:offset] + bytes(new_bytes) + bi.contents[offset:]
    new_bi = ByteInterval(
            contents=new_contents,
            address = bi.address + block.offset,
            )
    new_bi.section = sect
    for se_offset,se in bi.symbolic_expressions.items():
        if se_offset < offset:
            new_bi.symbolic_expressions[se_offset] = se
        else:
            new_bi.symbolic_expressions[se_offset+len(new_bytes)] = se

    block.byte_interval = new_bi
    block.offset = 0
    block.size = new_bi.size
    if debug:
        print("After:")
        show_block_asm(block)

def isolate_byte_interval(module, block):
    section = block.byte_interval.section
    bi = block.byte_interval

    new_bi = ByteInterval(
                contents= bi.contents[block.offset:block.offset+block.size],
                address=block.offset+bi.address)
    new_bi.section = section

    # Move symbolic expressions over
    ses = filter(
            lambda item: item[0] >= block.offset and \
                    item[0] < block.offset+block.size,
            block.byte_interval.symbolic_expressions.items())
    bi.blocks.remove(block)

    for se in ses:
        new_bi.symbolic_expressions[se[0] - block.offset] = se[1]

    block.byte_interval = new_bi
    block.offset = 0

# Split byte-intervals such that each CodeBlock has it's own byte_interval
# This is neccessary to facilitate proper layout of fallthrough edges when we
# start modifying byte_intervals
def prepare_for_rewriting(ir):
    for m in ir.modules:
        code_blocks = [b for b in m.code_blocks]
        for b in code_blocks:
            if b.offset != 0 or b.size != b.byte_interval.size:
                isolate_byte_interval(m, b)
    m.aux_data.pop('cfiDirectives')

progress('Preparing IR for rewriting...')
prepare_for_rewriting(ir)
progress('Stamping functions...')
for m in ir.modules:
    functions = build_functions(m)
    for f in functions:
        # if f.get_name()=="main":
        stamp_it(m, f)
progress('Saving new IR...')
ir.save_protobuf(args.outfile)
progress('Done.')

if args.rebuild is not None:
    args_pp = ['gtirb-pprinter', args.outfile, '-a', args.rebuild+'.s',
            '--skip-section', '.eh_frame']
    args_build = ['gcc', args.rebuild+'.s', '-o', args.rebuild]
    progress("Pretty printing...")
    subprocess.call(args_pp)
    progress("Rebuilding...")
    subprocess.call(args_build)

def test_keystone():
    try:
        # encoding, count = ks.asm(b"xor  0x012340,(%rsp)")
        encoding, count = ks.asm(b"xorl $0x26344873,(%rsp);")
        print("%s = %s (num stmts: %u)"%('xor', [ '%x'%e for e in encoding], count))
    except KsError as e:
        print("ERROR: %s"%e)

def test_capstone():
    CODE = b"\xc3"
    for i in md.disasm(CODE, 0x1000):
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

def stack_stamp(ir):
    for function in functions:
        entries, exits = identify_entry_exit(function)
        stamp_value = select_stamp_value(function)
        for e in entries:
            apply_entry_stamp(e, stamp_value)
        for e in exits:
            apply_exit_stamp(e, stamp_value)

def apply_entry_stamp(block, stamp_value):
    bi = get_byte_interval_bytes()


def set_block_bytes(block, bytes):
    if len(bytes) == sizeof(block.byte_interval):
        block.byte_interval.set_bytes(bytes)
    else:
        block.byte_interval = ByteInterval(bytes)

# test_capstone()
# test_keystone()
