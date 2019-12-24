import os, sys
from argparse import ArgumentParser

from bpf_program import BPFProgram

DESCRIPTION="""
System-wide runtime bounds checking with eBPF... eventually.
Right now, it just shows stack allocations. Which is kind of cool I guess.
"""

EPILOG="""
"""

def main(args):
    bpf = BPFProgram(args)
    bpf.main()

def is_root():
    return os.geteuid() == 0

def parse_args(args=sys.argv[1:]):
    parser = ArgumentParser(prog="bpf-rbc", description=DESCRIPTION, epilog=EPILOG)

    # Filter by a specific comm
    parser.add_argument("--comm", type=str,
            help="Only trace programs that begin with <COMM>.")
    # Print debug info
    parser.add_argument("--debug", action="store_true",
            help="Print debugging info.")

    args = parser.parse_args(args)

    # Check UID
    if not is_root():
        parser.error("You must run this script with root privileges.")

    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
