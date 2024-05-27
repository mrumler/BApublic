
import uuid
import logging
import json
import os
import sys

import gdb

LOGGER = logging.getLogger(__name__)
POIS = []
REGISTERS = [
    "rax", "rbp", "rbx", "rcx", "rdi", "rdx", "rip", "rsi", "rsp",
    "cr0", "cr2", "cr3", "cr4", "cr8",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eflags", "ds", "cs", "es", "fs", "gs", "ss", "fs_base", "gs_base"
]


def break_pois():
    POIS.clear()
    LOGGER.warning("Loading all breakpoints from ./stage1_pois")
    # Load all pois from file system
    for poi_file in os.listdir("stage1_pois"):
        if not poi_file.endswith(".poi.json"):
            continue
        
        with open(f"stage1_pois/{poi_file}", "r") as f:
            poi = json.loads(f.read())
            print(f"loaded {poi}")
            POIS.append(poi)

    # Break on all pois
    for poi in POIS:
        function_name = poi["function"]
        print(f"breaking on {function_name}")

        symbol = gdb.lookup_static_symbol(function_name)
        print(f"symbol: {symbol}")
        bp = gdb.Breakpoint(poi["bp_target"])
        bp.commands = f"python handle_poi_bp({json.dumps(poi)})"


def handle_poi_bp(poi):
    print("handle_poi_bp")
    metadata = {}
    metadata["data"] = {}
    metadata["poi"] = poi

    for poi_arg in poi["poi_args"]:
        # Needs to be modified per search, offsets to interesting stuff are unguessable
        ptr = int(gdb.newest_frame().read_var(poi_arg)["data"])
        metadata["data"][poi_arg] = ptr

    id = str(uuid.uuid4())
    os.makedirs(f"stage2_dumps/{id}")

    # write metadata
    with open(f"stage2_dumps/{id}/metadata.json", "w") as f:
        f.write(json.dumps(metadata))

    # write memory
    gdb.execute(f"monitor pmemsave 0 {512 * 1024 * 1024} stage2_dumps/{id}/mem.dump")

    mem = str(gdb.execute(f"monitor info mem", to_string=True))
    with open(f"stage2_dumps/{id}/mem.txt", "w") as f:
        f.write(mem)
    mtree = str(gdb.execute(f"monitor info mtree", to_string=True))
    with open(f"stage2_dumps/{id}/mtree.txt", "w") as f:
        f.write(mtree)
    for line in mem.split("\n"):
        if line == "":
            continue
        start = line.split("-")[0]
        length = line.split(" ")[1]
        if int(length, 16) >= 0x4000:
            memsave = f"monitor memsave 0x{start} 0x{length} stage2_dumps/{id}/{start}.vdump"
            print(memsave)
            gdb.execute(memsave)

    # write registers
    for reg in REGISTERS:
        with open(f"stage2_dumps/{id}/{reg}.rv", "w") as f:
            print(f"reading reg {reg}")
            f.write(str(int(gdb.newest_frame().read_register(reg)) & 0xffffffffffffffff))
