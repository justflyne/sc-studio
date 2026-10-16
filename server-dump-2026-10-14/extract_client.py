"""Extract this APK's Gadget resources without executing JavaScript.
Dependencies: pyelftools, cryptography. Offsets refer to the recorded libback.so.
"""
import argparse
import hashlib
import re
import struct
from pathlib import Path
from cryptography.hazmat.decrepit.ciphers.algorithms import ARC4
from cryptography.hazmat.primitives.ciphers import Cipher
from elftools.elf.elffile import ELFFile

EXPECTED_SHA256 = "a65ed41136f2d327ec38ea8bc91dafd691bfeb19ec70f392cc792503e610fe4c"

def extract(library: Path, output: Path):
    raw = library.read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA256:
        raise ValueError("libback.so differs from the APK used for this analysis")
    with library.open("rb") as stream:
        elf = ELFFile(stream)
        segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        relocations = {r["r_offset"]: r["r_addend"] for r in elf.get_section_by_name(".rela.dyn").iter_relocations()}
        def read(address, size):
            for segment in segments:
                if segment["p_vaddr"] <= address and address + size <= segment["p_vaddr"] + segment["p_filesz"]:
                    offset = segment["p_offset"] + address - segment["p_vaddr"]
                    return raw[offset:offset + size]
            raise ValueError(f"Address outside ELF file-backed segments: {address:#x}")
        def pointer(address):
            return relocations.get(address, struct.unpack("<Q", read(address, 8))[0])
        def decode(table, count, size, key_address, chunk_size):
            ciphertext = b"".join(read(pointer(table + i * 8), min(chunk_size, max(0, size - i * chunk_size))) for i in range(count))
            key = hashlib.sha256(read(pointer(key_address), 16)).digest()
            cipher = Cipher(ARC4(key), mode=None).decryptor()
            cipher.update(bytes(3072))
            return cipher.update(ciphertext) + cipher.finalize()
        config = decode(0x183e540, 12, 113, 0x183e5a0, 10)
        bundle = decode(0x183e238, 96, 0xa7131, 0x183e538, 0x1bd9)
    output.mkdir(parents=True, exist_ok=True)
    (output / "gadget-config.json").write_bytes(config)
    (output / "embedded-bootstrap.bin").write_bytes(bundle)
    (output / "embedded-bootstrap.js").write_text(bundle.decode("utf-8"))
    marker = "\n✄\n".encode()
    boundary = bundle.index(marker)
    cursor = boundary + len(marker)
    entries = []
    for line in bundle[:boundary].decode().splitlines():
        match = re.fullmatch(r"(\d+) (/.+)", line)
        if match:
            entries.append((int(match[1]), match[2]))
    for i, (size, name) in enumerate(entries):
        relative = Path(name.lstrip("/"))
        if ".." in relative.parts:
            raise ValueError("Unsafe module path")
        target = output / "modules" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(bundle[cursor:cursor + size])
        cursor += size
        if i + 1 < len(entries):
            if bundle[cursor:cursor + len(marker)] != marker:
                raise ValueError("Unexpected module separator")
            cursor += len(marker)
    if cursor != len(bundle):
        raise ValueError("Bundle module lengths do not match input")
    print(f"Extracted configuration and {len(entries)} modules ({len(bundle)} bundle bytes)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    extract(args.library, args.output)
