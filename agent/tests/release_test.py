"""Verify the ELF properties of the exact artifact installed by install-release."""
import os
import pathlib
import re
import struct
import subprocess
import sys
import zlib

binary, debug = map(pathlib.Path, sys.argv[1:])


def readelf(*args):
    return subprocess.check_output(["readelf", "--wide", *args], text=True, env={**os.environ, "LC_ALL": "C"})


header = readelf("-h", str(binary))
assert re.search(r"Type:\s+DYN\b", header), "executable is not PIE"
program = readelf("-l", str(binary))
assert "GNU_RELRO" in program, "RELRO missing"
stack = next(line for line in program.splitlines() if "GNU_STACK" in line)
assert "RW" in stack and "RWE" not in stack, "executable stack"
dynamic = readelf("-d", str(binary))
assert "BIND_NOW" in dynamic or re.search(r"Flags:.*\bNOW\b", dynamic), "lazy binding enabled"
assert re.search(r"Flags:.*\bPIE\b", dynamic), "PIE dynamic flag missing"
symbols = readelf("--dyn-syms", str(binary))
assert "__stack_chk_fail" in symbols, "stack protector missing"
assert re.search(r"__\w+_chk\b", symbols), "fortified libc calls missing"
assert not any("hp_" in line and " UND " not in line for line in symbols.splitlines()), "agent exports public symbols"
assert readelf("-x", ".text", str(binary)) == readelf("-x", ".text", str(binary.with_name(binary.name + ".full"))), "stripping changed executable code"
sections = readelf("-S", str(binary))
assert ".debug_info" not in sections and ".symtab" not in sections, "binary contains diagnostic symbols"
# objdump handles the intentionally empty interpreter segment in split debug files.
debug_sections = subprocess.check_output(["objdump", "-h", str(debug)], text=True)
assert ".debug_info" in debug_sections, "separate debug info missing"
build_id = re.search(r"Build ID: (\w+)", readelf("-n", str(binary))).group(1)
debug_note = subprocess.check_output(["objdump", "-s", "-j", ".note.gnu.build-id", str(debug)], text=True)
note = bytearray()
for line in debug_note.splitlines():
    words = line.split()
    if words and re.fullmatch(r"[0-9a-fA-F]+", words[0]):
        for word in words[1:5]:
            if not re.fullmatch(r"[0-9a-fA-F]{8}", word):
                break
            note.extend(bytes.fromhex(word))
assert bytes.fromhex(build_id) in note, "debug file build ID mismatch"
# Validate the debuglink filename and CRC, not just the presence of the section.
dump = readelf("-x", ".gnu_debuglink", str(binary))
raw = bytearray()
for line in dump.splitlines():
    if line.strip().startswith("0x"):
        for word in line.split()[1:5]:
            if not re.fullmatch(r"[0-9a-fA-F]{8}", word):
                break
            raw.extend(bytes.fromhex(word))
end = raw.index(0)
assert raw[:end].decode() == debug.name
crc_offset = (end + 4) & ~3
byteorder = "<" if "little endian" in header else ">"
assert struct.unpack_from(byteorder + "I", raw, crc_offset)[0] == zlib.crc32(debug.read_bytes())
for args in (("--id", "x", "--ip", "bad", "--port", "443"), ("--port", "0")):
    assert subprocess.run([str(binary.resolve()), *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 2
print("PASS release: PIE, full RELRO, NX stack, stack protector/FORTIFY, hidden exports, split debug/build ID/CRC, unchanged code, CLI")
