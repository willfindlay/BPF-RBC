import os, sys
import atexit
import signal

from bcc import BPF

from defs import project_path

class BPFProgram():
    def __init__(self, args):
        self.bpf = None
        self.register_exit_hooks()

        self.executable = args.executable

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
        with open(os.path.join(project_path, "src/bpf/bpf_program.c"), "r") as f:
            text = f.read()
            self.bpf = BPF(text=text, cflags=[f'-DEXECUTABLE="{os.path.basename(os.path.normpath(self.executable))}"'])

    def main(self):
        self.load_bpf()

        while True:
            self.bpf.trace_print()
