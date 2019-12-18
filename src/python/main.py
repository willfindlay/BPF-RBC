import os, sys
from argparse import ArgumentParser

from bpf_program import BPFProgram

DESCRIPTION="""
"""

EPILOG="""
"""

def main(args):
    bpf = BPFProgram()
    bpf.main()

def is_root():
    return os.geteuid() == 0

def parse_args(args=sys.argv[1:]):
    parser = ArgumentParser(prog="bpf-rbc", description=DESCRIPTION, epilog=EPILOG)

    # Arguments here

    args = parser.parse_args(args)

    # Check UID
    if not is_root():
        parser.error("You must run this script with root privileges.")

    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
