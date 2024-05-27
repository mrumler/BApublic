import argparse
from enum import Enum
import struct
import sys
from typing import Literal, Optional, Union
import logging
import json
import random
import os

from unicornafl import *
from unicorn.x86_const import *
from unicorn import UC_HOOK_INSN, UC_HOOK_CODE

DATA_SIZE_MAX=2000
LOGGER = logging.getLogger(__name__)


def place_input_callback(uc, input, persistent_round, data):
    if len(input) > DATA_SIZE_MAX:
        LOGGER.debug("input too long")
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Speedtest afl unicorn")
    parser.add_argument("--memsize", type=int, help="size of mapped memory in mb")
    parser.add_argument("input_file", nargs="?", default=None, help="path to file with mutated input")
    args = parser.parse_args()
    MEMSIZE: int = args.memsize

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    uc.mem_map(0, MEMSIZE * 1024 * 1024)
    uc.mem_write(0, b"\x90"*MEMSIZE * 1024 * 1024)

    sys.stdout.flush()
    sys.stderr.flush()
    uc_afl_fuzz(uc=uc, input_file=args.input_file[0], place_input_callback=place_input_callback, exits=[1])
    