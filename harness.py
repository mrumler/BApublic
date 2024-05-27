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
OPS = 0

class Mode(Enum):
    fuzz = "fuzz"
    emu = "emu"

    def __str__(self):
        return self.value

def hook_code(uc, address, size, user_data):
    global OPS
    OPS = OPS + 1
    insn = uc.mem_read(address, size)
    insn_hex = ''.join('{:02x}'.format(x) for x in insn)
    LOGGER.debug(f"Executing instruction at 0x{address:016x} ({size} bytes, {insn_hex})")
    if COUNT > 0 and OPS > COUNT:
        LOGGER.warning("Stopping emu")
        uc.emu_stop()
        return False

def hook_mem(uc, access, address, size, value, user_data):
    LOGGER.error(f"memory access at 0x{address:016x}")
    #if random.randint(0, 10) == 0:
    #    raise Exception("dummy crash")

def hook_mem_invalid(uc, access, address, size, value, user_data):
    rip = uc.reg_read(UC_X86_REG_RIP)
    LOGGER.error(f"### hook_mem_invalid: Invalid memory access at 0x{rip:016x} (0x{address:016x}, {size}) after {OPS} instructions ({user_data})")
    raise Exception()

def read_register(reg: str):
    try:
        with open(f"{DUMP}/{reg}.rv", "r") as f:
            return int(f.read())
    except:
        LOGGER.warning(f"Failed to read {reg}, falling back to 0")
        return 0

def read_memory():
    with open(f"{DUMP}/mem.dump", "rb") as f:
        return f.read()

def read_data_address():
    with open(f"{DUMP}/metadata.json", "r") as f:
        data = json.loads(f.read())
        for k,v in data["data"].items():
            return data["data"][k]
    raise Exception("could not find data ptr")

def place_input_callback(uc, input, persistent_round, data):
    if len(input) > DATA_SIZE_MAX:
        LOGGER.debug("input too long")
        return False

    uc.mem_write(DATA_ADDRESS, input)

def load_vdumps(uc):
    LOGGER.debug("loading vdumps")
    files = os.listdir(DUMP)
    for file in files:
        if not file.endswith(".vdump"):
            continue
        with open(f"{DUMP}/{file}", "rb") as f:
            blob = f.read()
        start = int(file.split(".")[0], 16)
        uc.mem_map(start, len(blob))
        uc.mem_write(start, blob)
    LOGGER.debug("loading vdumps done")

def load_registers(uc):
    # https://github.com/unicorn-engine/unicorn/blob/d4b92485b1a228fb003e1218e42f6c778c655809/bindings/python/unicorn/x86_const.py#L48
    uc.reg_write(UC_X86_REG_RAX, read_register("rax"))
    uc.reg_write(UC_X86_REG_RBP, read_register("rbp"))
    uc.reg_write(UC_X86_REG_RBX, read_register("rbx"))
    uc.reg_write(UC_X86_REG_RCX, read_register("rcx"))
    uc.reg_write(UC_X86_REG_RDI, read_register("rdi"))
    uc.reg_write(UC_X86_REG_RDX, read_register("rdx"))
    uc.reg_write(UC_X86_REG_RIP, read_register("rip"))
    uc.reg_write(UC_X86_REG_RSI, read_register("rsi"))
    uc.reg_write(UC_X86_REG_RSP, read_register("rsp"))

    #uc.reg_write(UC_X86_REG_CR0, read_register("cr0"))
    #uc.reg_write(UC_X86_REG_CR1, read_register("cr1"))
    #uc.reg_write(UC_X86_REG_CR2, read_register("cr2"))
    #uc.reg_write(UC_X86_REG_CR3, read_register("cr3"))
    #uc.reg_write(UC_X86_REG_CR4, read_register("cr4"))
    #uc.reg_write(UC_X86_REG_CR8, read_register("cr8"))

    # debug registers

    # fp registers

    # k registers

    # MM registers
    uc.reg_write(UC_X86_REG_XMM0, read_register("xmm0"))
    uc.reg_write(UC_X86_REG_XMM1, read_register("xmm1"))
    uc.reg_write(UC_X86_REG_XMM2, read_register("xmm2"))
    uc.reg_write(UC_X86_REG_XMM3, read_register("xmm3"))
    uc.reg_write(UC_X86_REG_XMM4, read_register("xmm4"))
    uc.reg_write(UC_X86_REG_XMM5, read_register("xmm5"))
    uc.reg_write(UC_X86_REG_XMM6, read_register("xmm6"))
    uc.reg_write(UC_X86_REG_XMM7, read_register("xmm7"))
    uc.reg_write(UC_X86_REG_XMM8, read_register("xmm8"))
    uc.reg_write(UC_X86_REG_XMM9, read_register("xmm9"))
    uc.reg_write(UC_X86_REG_XMM10, read_register("xmm10"))
    uc.reg_write(UC_X86_REG_XMM11, read_register("xmm11"))
    uc.reg_write(UC_X86_REG_XMM12, read_register("xmm12"))
    uc.reg_write(UC_X86_REG_XMM13, read_register("xmm13"))
    uc.reg_write(UC_X86_REG_XMM14, read_register("xmm14"))
    uc.reg_write(UC_X86_REG_XMM15, read_register("xmm15"))

    uc.reg_write(UC_X86_REG_R8, read_register("r8"))
    uc.reg_write(UC_X86_REG_R9, read_register("r9"))
    uc.reg_write(UC_X86_REG_R10, read_register("r10"))
    uc.reg_write(UC_X86_REG_R11, read_register("r11"))
    uc.reg_write(UC_X86_REG_R12, read_register("r12"))
    uc.reg_write(UC_X86_REG_R13, read_register("r13"))
    uc.reg_write(UC_X86_REG_R14, read_register("r14"))
    uc.reg_write(UC_X86_REG_R15, read_register("r15"))
    
    uc.reg_write(UC_X86_REG_EFLAGS, read_register("eflags"))
    uc.reg_write(UC_X86_REG_DS, read_register("ds"))
    uc.reg_write(UC_X86_REG_CS, read_register("cs"))
    uc.reg_write(UC_X86_REG_ES, read_register("es"))
    uc.reg_write(UC_X86_REG_FS, read_register("fs"))
    uc.reg_write(UC_X86_REG_FS, read_register("gs"))
    uc.reg_write(UC_X86_REG_SS, read_register("ss"))
    uc.reg_write(UC_X86_REG_FS_BASE, read_register("fs_base"))
    uc.reg_write(UC_X86_REG_GS_BASE, read_register("gs_base"))

def read_ret(uc):
    rsp = uc.reg_read(UC_X86_REG_RSP)
    ret = struct.unpack("<Q", (uc.mem_read(rsp, 8)))[0]
    return ret

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run a dump in Unicorn or aflunicorn")
    parser.add_argument("--debug", action='store_true', help="verbose output")
    parser.add_argument("--dump", type=str, help="dump to load")
    parser.add_argument("--timeout", type=int, default=0, help="count paramameter for unicorn")
    parser.add_argument("--count", type=int, default=0, help="count parameter for unicorn")
    parser.add_argument("mode", type=Mode, choices=list(Mode), help="harness mode")
    parser.add_argument("input_file", nargs="?", default=None, help="path to file with mutated input")
    args = parser.parse_args()
    DEBUG = args.debug
    DUMP: str = args.dump
    mode: Mode = args.mode
    TIMEOUT: int = args.timeout
    COUNT: int = args.count
    if DEBUG:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)


    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    
    if DEBUG or (COUNT and mode == Mode.fuzz):
        uc.hook_add(UC_HOOK_CODE, hook_code)
        

    if DEBUG:
        uc.hook_add(UC_HOOK_MEM_READ_PROT
            | UC_HOOK_MEM_WRITE_PROT
            | UC_HOOK_MEM_FETCH_PROT
            | UC_HOOK_MEM_READ
            | UC_HOOK_MEM_WRITE 
            | UC_HOOK_MEM_FETCH,
            hook_mem)

    if DEBUG:
        uc.hook_add(
            UC_HOOK_MEM_READ_UNMAPPED 
            | UC_HOOK_MEM_FETCH_UNMAPPED
            | UC_HOOK_MEM_WRITE_UNMAPPED,
            hook_mem_invalid)

    #mem = read_memory()
    #uc.mem_map(0, len(mem))
    #uc.mem_write(0, mem)

    load_vdumps(uc)
    load_registers(uc)

    if mode == Mode.emu:
        LOGGER.info("Starting emulation")
        uc.emu_start(uc.reg_read(UC_X86_REG_RIP), read_ret(uc), timeout=TIMEOUT, count=COUNT)
    else:
        DATA_ADDRESS = read_data_address()
        LOGGER.info(f"Starting fuzzing {args.input_file}")
        sys.stdout.flush()
        sys.stderr.flush()
        uc_afl_fuzz(uc=uc, input_file=args.input_file[0], place_input_callback=place_input_callback, exits=[read_ret(uc)])
