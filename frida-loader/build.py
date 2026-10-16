"""Build a loadable Frida ESM bundle using modules already extracted from the APK."""
import re
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE_BUNDLE = HERE.parent / "server-dump-2026-10-14/client-analysis/embedded-bootstrap.bin"
if not SOURCE_BUNDLE.exists():
    SOURCE_BUNDLE = HERE / "loader.bundle.js"


def make_bundle(entry: bytes) -> bytes:
    raw = SOURCE_BUNDLE.read_bytes()
    marker = "\n✄\n".encode()
    boundary = raw.index(marker)
    header = raw[:boundary].decode()
    cursor = boundary + len(marker)
    lines = []
    modules = []
    for line in header.splitlines():
        match = re.fullmatch(r"(\d+) (/.+)", line)
        if match is None:
            lines.append(line)
            continue
        size, name = int(match[1]), match[2]
        content = raw[cursor:cursor + size]
        cursor += size
        if raw[cursor:cursor + len(marker)] == marker:
            cursor += len(marker)
        if name in ("/src/bootstrap.js", "/src/loader.js"):
            content, name = entry, "/src/loader.js"
        lines.append(f"{len(content)} {name}")
        modules.append(content)
    if cursor != len(raw):
        raise ValueError("Source bundle lengths do not match input")
    return "\n".join(lines).encode() + marker + marker.join(modules)


if __name__ == "__main__":
    destination = HERE / "loader.bundle.js"
    bundle = make_bundle((HERE / "loader.js").read_bytes())
    destination.write_bytes(bundle)
    staged = HERE / "apk-libs/arm64-v8a/libback.script.so"
    if staged.parent.exists():
        staged.write_bytes(bundle)
        info_path = HERE / "apk-libs/gadget-info.json"
        if info_path.exists():
            info = json.loads(info_path.read_text())
            info["files"][staged.name] = {"bytes": len(bundle), "sha256": hashlib.sha256(bundle).hexdigest()}
            info_path.write_text(json.dumps(info, indent=2))
    print(f"Built {destination} ({destination.stat().st_size} bytes)")
