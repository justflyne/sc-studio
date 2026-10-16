"""Repack a raw, unzipped APK with the prepared ARM64 Gadget files.

Output is unsigned and must be zipaligned and signed before installing.
The original directory is only read. This is not an apktool project builder.
"""
import argparse
import json
import re
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
TRIPLET = ("libback.so", "libback.config.so", "libback.script.so")


def pack(source: Path, output: Path):
    source, output = source.resolve(), output.resolve()
    if not source.is_dir():
        raise ValueError("Source must be a raw unzipped APK directory")
    if output.is_relative_to(source):
        raise ValueError("Output APK must be outside the source directory")
    if (source / "AndroidManifest.xml").read_bytes()[:4] != b"\x03\x00\x08\x00":
        raise ValueError("Expected compiled binary AndroidManifest.xml, not apktool-decoded XML")
    if not (source / "resources.arsc").is_file() or not (source / "classes.dex").is_file():
        raise ValueError("Compiled resources and classes.dex are required")
    if not (source / "lib/arm64-v8a/libback.so").is_file():
        raise ValueError("This helper expects the APK with an existing loadLibrary('back')")
    prepared = HERE / "apk-libs/arm64-v8a"
    replacement_paths = {f"lib/arm64-v8a/{name}" for name in TRIPLET}
    for name in TRIPLET:
        if not (prepared / name).is_file():
            raise ValueError("Run prepare_gadget.py first")
    config = json.loads((prepared / "libback.config.so").read_text())
    if config["interaction"]["path"] != "libback.script.so":
        raise ValueError("Configuration does not point to the packaged script")
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(source.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(source).as_posix()
            if relative in replacement_paths:
                continue
            upper = relative.upper()
            if upper == "META-INF/MANIFEST.MF" or re.fullmatch(r"META-INF/[^/]+\.(SF|RSA|DSA|EC)", upper):
                continue
            archive.write(path, relative)
            count += 1
        for name in TRIPLET:
            archive.write(prepared / name, f"lib/arm64-v8a/{name}")
            count += 1
    print(f"Packed {output} ({count} files, {output.stat().st_size} bytes); unsigned")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    pack(args.source, args.output)
