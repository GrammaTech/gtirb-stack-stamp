from gtirb import Edge


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
        for uuid, entryBlocks in module.aux_data[
            "functionEntries"
        ].data.items():
            entryBlocksUUID = set([e.uuid for e in entryBlocks])
            blocks = module.aux_data["functionBlocks"].data[uuid]
            syms = [
                x
                for x in filter(
                    lambda s: s.referent
                    and s.referent.uuid in entryBlocksUUID,
                    module.symbols,
                )
            ]
            functions.append(
                Function(
                    uuid,
                    entryBlocks=entryBlocks,
                    blocks=blocks,
                    name_symbols=syms,
                )
            )
        return functions

    def get_name(self):
        names = [s.name for s in self._name_symbols]
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
        return "[UUID={}, Name={}, Entry={}, Blocks={}]".format(
            self._uuid, self.get_name(), self._entryBlocks, self._blocks
        )
