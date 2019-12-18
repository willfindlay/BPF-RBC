import os, sys
import atexit
import signal

from bcc import BPF

class BPFProgram():
    def __init__(self):
        self.bpf = None
        self.register_exit_hooks()

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

    def main(self):
        self.load_bpf()

        while True:
            pass
