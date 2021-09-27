#!/usr/bin/python3
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
import argparse
import logging
from gtirb import IR
from .stack_stamp import apply_stack_stamp
import subprocess


def main():
    ap = argparse.ArgumentParser(
        description="Show (un)reachable code in GTIRB"
    )
    ap.add_argument("infile")
    ap.add_argument(
        "-o", "--outfile", default=None, help="GTIRB output filename"
    )
    ap.add_argument(
        "--rebuild",
        metavar="FILENAME",
        default=None,
        help="Rebuild binary as FILENAME",
    )
    ap.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )
    ap.add_argument("-q", "--quiet", action="store_true", help="No output")
    args = ap.parse_args()

    logging.basicConfig(format="%(message)s")
    logger = logging.getLogger("gtirb.stackstamp")
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif not args.quiet:
        logger.setLevel(logging.INFO)

    if args.rebuild is not None and args.outfile is None:
        logger.error("Error: with --rebuild, --outfile is required")
        exit(1)

    logger.info("Loading IR... " + args.infile)
    ir = IR.load_protobuf(args.infile)

    logger.info("Stamping functions...")
    apply_stack_stamp(ir, logger=logger)

    if args.outfile is not None:
        logger.info("Saving new IR...")
        ir.save_protobuf(args.outfile)

    logger.info("Done.")

    if args.rebuild is not None:
        logger.info("Pretty printing...")
        args_pp = [
            "gtirb-pprinter",
            args.outfile,
            "--policy",
            "complete",
            "-b",
            args.rebuild,
        ]
        ec = subprocess.call(args_pp)
        return ec
    return 0


if __name__ == "__main__":
    exit(main())
