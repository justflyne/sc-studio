"""Prepare the three files needed under lib/arm64-v8a in the APK."""
import argparse
import hashlib
import json
import lzma
import struct
import urllib.request
from pathlib import Path

from build import make_bundle

HERE = Path(__file__).resolve().parent
VERSION = "17.23.3"
ASSET = f"frida-gadget-{VERSION}-android-arm64.so.xz"
URL = f"https://github.com/frida/frida/releases/download/{VERSION}/{ASSET}"
XZ_SHA256 = "aeb3109844d69f5745438597667841a9141e8701a174341999e1479a4c97925f"


def prepare(output: Path):
    output.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(URL, headers={"User-Agent": "Frida-Gadget-setup/1.0"})
    with urllib.request.urlopen(request, timeout=45) as response:
        compressed = response.read(32 * 1024 * 1024 + 1)
    if len(compressed) > 32 * 1024 * 1024:
        raise ValueError("Gadget archive too large")
    if hashlib.sha256(compressed).hexdigest() != XZ_SHA256:
        raise ValueError("Gadget archive differs from the official release digest")
    library = lzma.decompress(compressed)
    if library[:4] != b"\x7fELF" or struct.unpack_from("<H", library, 18)[0] != 183:
        raise ValueError("Expected an AArch64 ELF Gadget")
    bundle = make_bundle((HERE / "loader.js").read_bytes())
    (HERE / "loader.bundle.js").write_bytes(bundle)
    files = {
        "libback.so": library,
        "libback.config.so": (HERE / "libback.config.so").read_bytes(),
        "libback.script.so": bundle,
    }
    for name, data in files.items():
        (output / name).write_bytes(data)
    metadata = {
        "version": VERSION,
        "release_url": f"https://github.com/frida/frida/releases/tag/{VERSION}",
        "asset_url": URL,
        "asset_sha256": XZ_SHA256,
        "files": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in files.items()},
    }
    (output.parent / "gadget-info.json").write_text(json.dumps(metadata, indent=2))
    print(f"Prepared {output}: libback.so + libback.config.so + libback.script.so")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=HERE / "apk-libs/arm64-v8a")
    args = parser.parse_args()
    prepare(args.output)
