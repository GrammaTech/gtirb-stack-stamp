#
# Copyright (C) 2020 GrammaTech, Inc.
#
# This code is licensed under the MIT license. See the LICENSE file in
# the project root for license terms.
#
# This project is sponsored by the Office of Naval Research, One Liberty
# Center, 875 N. Randolph Street, Arlington, VA 22203 under contract #
# N68335-17-C-0700.  The content of the information does not necessarily
# reflect the position or policy of the Government and no official
# endorsement should be inferred.
#
import random
import logging

from gtirb_rewriting import (
    SingleBlockScope,
    BlockPosition,
    Pass,
    PassManager,
    Patch,
    patch_constraints,
)


class StampPass(Pass):
    """Add stack stamping instructions to every function."""

    def begin_module(self, module, functions, context):
        """Register insertions and replacements for the given functions."""
        for function in functions:
            # When the entry point function runs, there is no return address
            # on the stack, so we shouldn't stamp it.
            if module.entry_point not in function.get_all_blocks():
                for block in function.get_entry_blocks():
                    context.register_insert(
                        SingleBlockScope(block, BlockPosition.ENTRY),
                        Patch.from_function(self.get_function_stamp_value),
                    )
                for block in function.get_exit_blocks():
                    context.register_insert(
                        SingleBlockScope(block, BlockPosition.EXIT),
                        Patch.from_function(self.get_function_stamp_value),
                    )

    @patch_constraints(clobbers_flags=True)
    def get_function_stamp_value(self, context):
        # Use the same seed every time this is called for the same function so
        # that each entrance and exit uses the same stamp.
        random.seed(context.function.uuid.int)
        w1 = random.randint(0, 2 ** 32)
        w2 = random.randint(0, 2 ** 32)
        return f"""
            xorl $0x{w1:X},{context.stack_adjustment}(%rsp)
            xorl $0x{w2:X},{context.stack_adjustment+4}(%rsp)
        """


def apply_stack_stamp(ir, logger=logging.Logger("null")):
    manager = PassManager(logger=logger)
    manager.add(StampPass())
    manager.run(ir)
