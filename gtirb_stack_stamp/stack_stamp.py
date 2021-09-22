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
    AllFunctionsScope,
    BlockPosition,
    FunctionPosition,
    Pass,
    PassManager,
    Patch,
    patch_constraints,
)


class StampPass(Pass):
    """Add stack stamping instructions to every function."""

    def __init__(self):
        pass

    def begin_module(self, module, functions, context):
        """Register insertions and replacements for the given functions."""
        # Stamp the return address at the entry point of every function.
        context.register_insert(
            AllFunctionsScope(FunctionPosition.ENTRY, BlockPosition.ENTRY),
            Patch.from_function(self.get_function_stamp_value),
        )
        # Stamp the return address at the exit of every function.
        context.register_insert(
            AllFunctionsScope(FunctionPosition.EXIT, BlockPosition.EXIT),
            Patch.from_function(self.get_function_stamp_value),
        )

    @patch_constraints(clobbers_flags=True)
    def get_function_stamp_value(self, context):
        # Just choose a random value for the stamp values.  An option for a
        # deterministic value is to take a hash of the function name or
        # beginning EA.
        random.seed(context.function.get_name())
        w1 = random.randint(0, 2 ** 32)
        w2 = random.randint(0, 2 ** 32)
        # gtirb-rewriting saves the flags to the top of the stack, so we need
        # to stamp at offsets 8 and 12 from the top.
        return f"""
            xorl $0x{w1:X},8(%rsp)
            xorl $0x{w2:X},12(%rsp)
        """


def apply_stack_stamp(ir, logger=logging.Logger("null")):
    manager = PassManager(logger=logger)
    manager.add(StampPass())
    manager.run(ir)
