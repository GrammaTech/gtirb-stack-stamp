#!/usr/bin/python3
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

    logger.info("Loading IR...")
    ir = IR.load_protobuf(args.infile)

    logger.info("Stamping functions...")
    apply_stack_stamp(ir, logger=logger)

    logger.info("Saving new IR...")
    ir.save_protobuf(args.outfile)

    logger.info("Done.")

    if args.rebuild is not None:
        args_pp = [
            "gtirb-pprinter",
            args.outfile,
            "-a",
            args.rebuild + ".s",
            "--skip-section",
            ".eh_frame",
        ]
        args_build = ["gcc", args.rebuild + ".s", "-o", args.rebuild]
        logger.info("Pretty printing...")
        subprocess.call(args_pp)
        logger.info("Rebuilding...")
        subprocess.call(args_build)


if __name__ == "__main__":
    main()
