import os, sys
import atexit
import signal
import time

from bcc import BPF

from defs import project_path

class BPFProgram():
    def __init__(self, args):
        self.bpf = None

        self.comm = args.comm
        self.debug = args.debug

    def register_exit_hooks(self):
        # Catch signals so we still invoke atexit
        signal.signal(signal.SIGTERM, lambda x, y: sys.exit(0))
        signal.signal(signal.SIGINT, lambda x, y: sys.exit(0))

        # Unregister self.cleanup if already registered
        atexit.unregister(self.cleanup)
        # Register self.cleanup
        atexit.register(self.cleanup)

    def cleanup(self):
        self.bpf = None

    def load_bpf(self):
        assert self.bpf == None

        # Set flags
        flags = []
        if self.comm:
            flags.append(f'-DRBC_COMM="{self.comm}"')
        if self.debug:
            flags.append(f'-DRBC_DEBUG')

        with open(os.path.join(project_path, "src/bpf/bpf_program.c"), "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=flags)
        self.register_exit_hooks()

    def main(self):
        self.load_bpf()

        #for v in self.bpf["rbc_tasks"].itervalues():
        #    print(v.comm)

        while True:
            time.sleep(1)
            if self.debug:
                self.bpf.trace_print()
