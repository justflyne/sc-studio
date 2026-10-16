"""SC1 tag streams adapted to the editor's resource model.

Format references: SC Workshop/SupercellFlash, xcoder-tool/sc-py and
ToxicLand/SCEditor. Original tag bytes and container metadata remain available
for lossless writes of untouched resources. SC2 uses the same editor tables.
"""

import array
import hashlib
import lzma
import os
import pickle
import struct
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import zstandard

MKEYS = ("a", "b", "c", "d", "tx", "ty")
CKEYS = ("r_mul", "g_mul", "b_mul", "alpha", "r_add", "g_add", "b_add")
TEXTURES = {1, 16, 19, 24, 27, 28, 29, 34, 45, 47}
TEXTFIELDS = {7, 15, 20, 21, 25, 33, 43, 44, 46}
CLIPS = {3, 10, 12, 14, 35, 49}
MAX_UNPACKED = 512 * 1024 * 1024
END = b"\0" * 5


class Reader:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, n):
        if n < 0 or self.pos + n > len(self.data):
            raise ValueError(f"Truncated SC1 data at byte {self.pos}")
        result = self.data[self.pos:self.pos + n]
        self.pos += n
        return result

    def unpack(self, fmt):
        size = struct.calcsize("<" + fmt)
        if self.pos + size > len(self.data):
            raise ValueError(f"Truncated SC1 field at byte {self.pos}")
        values = struct.unpack_from("<" + fmt, self.data, self.pos)
        self.pos += size
        return values[0] if len(values) == 1 else values

    def string(self):
        size = self.unpack("B")
        return "" if size == 255 else self.take(size).decode("utf-8", "surrogateescape")

    def tags(self):
        while self.pos < len(self.data):
            start = self.pos
            tag, size = self.unpack("BI")
            body = self.take(size)
            yield tag, body, start, self.pos
            if tag == 0:
                return
        raise ValueError("SC1 tag stream has no end tag")


def string_bytes(value):
    value = value.encode("utf-8", "surrogateescape")
    if len(value) >= 255:
        raise ValueError("SC1 strings must contain at most 254 UTF-8 bytes")
    return bytes([len(value)]) + value


def tag_bytes(tag, body=b""):
    return struct.pack("<BI", tag, len(body)) + body


@dataclass
class Container:
    original: bytes
    version: int = 0
    subversion: int = 1
    codec: str = "raw"
    props: bytes = b"\x5d\x00\x00\x04\x00"
    suffix: bytes = b""
    wrapped: bool = False

    @classmethod
    def decode(cls, data):
        result = cls(data)
        payload = data
        if data.startswith(b"SIG:"):
            raise ValueError("Signed SIG containers are not supported; use an unsigned SC1 asset")
        if data.startswith(b"SC"):
            if len(data) < 10:
                raise ValueError("Truncated SC1 container header")
            result.wrapped = True
            result.version = struct.unpack_from(">I", data, 2)[0]
            if result.version not in (1, 2, 3, 4):
                raise ValueError(f"Unsupported SC container version {result.version}")
            offset = 6
            if result.version == 4:
                result.subversion = struct.unpack_from(">I", data, offset)[0]
                offset += 4
            hash_size = struct.unpack_from(">I", data, offset)[0]
            offset += 4
            if hash_size not in (0, 16) or offset + hash_size > len(data):
                raise ValueError("Invalid SC1 container hash header")
            offset += hash_size
            payload = data[offset:]
        def decode_with_suffix(decompress):
            # START can also occur inside compressed literal data. Accept a
            # metadata boundary only after a complete successful decompression.
            marker = payload.find(b"START") if result.wrapped else -1
            while marker >= 0:
                try:
                    decoded = decompress(payload[:marker])
                except (ValueError, lzma.LZMAError, RuntimeError):
                    marker = payload.find(b"START", marker + 5)
                    continue
                result.suffix = payload[marker:]
                return decoded
            return decompress(payload)
        if payload.startswith(b"\x28\xb5\x2f\xfd"):
            result.codec = "zstd"
            size = zstandard.get_frame_parameters(payload).content_size
            if size == zstandard.CONTENTSIZE_UNKNOWN:
                raise ValueError("SC1 Zstandard frame must declare its decompressed size")
            if size > MAX_UNPACKED:
                raise ValueError("SC1 decompressed data exceeds 512 MiB")
            decoder = zstandard.ZstdDecompressor().decompressobj()
            raw = decoder.decompress(payload)
            if not decoder.eof:
                raise ValueError("Truncated SC1 Zstandard payload")
            result.suffix = decoder.unused_data
        elif payload.startswith(b"SCLZ"):
            result.codec = "lzham"
            try:
                import lzham
            except ImportError as exc:
                raise ValueError("This SC1 asset uses LZHAM; install pylzham to open it") from exc
            size = struct.unpack_from("<I", payload, 5)[0]
            if size > MAX_UNPACKED:
                raise ValueError("SC1 decompressed data exceeds 512 MiB")
            def decompress_lzham(value):
                decoded = lzham.decompress(value[9:], size, {"dict_size_log2": value[4]})
                if len(decoded) != size:
                    raise ValueError("Truncated SC1 LZHAM payload")
                return decoded
            raw = decode_with_suffix(decompress_lzham)
        elif result.wrapped or (len(payload) >= 9 and payload[0] in (0x5d, 0x5e)):
            result.codec = "lzma"
            result.props = payload[:5]
            if len(payload) < 9:
                raise ValueError("Truncated SC1 LZMA header")
            size = struct.unpack_from("<I", payload, 5)[0]
            if size > MAX_UNPACKED:
                raise ValueError("SC1 decompressed data exceeds 512 MiB")
            prop = payload[0]
            rest = prop // 9
            filters = [{"id": lzma.FILTER_LZMA1,
                        "dict_size": struct.unpack_from("<I", payload, 1)[0],
                        "lc": prop % 9, "lp": rest % 5, "pb": rest // 5}]
            def decompress_lzma(value):
                decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                decoded = decoder.decompress(value[9:], max_length=size)
                if len(decoded) != size:
                    raise ValueError("Truncated SC1 LZMA payload")
                return decoded
            raw = decode_with_suffix(decompress_lzma)
        else:
            raw = payload
        if len(raw) > MAX_UNPACKED:
            raise ValueError("SC1 decompressed data exceeds 512 MiB")
        return raw, result

    def encode(self, raw):
        if self.codec == "raw":
            return raw
        if self.codec == "zstd":
            compressed = zstandard.ZstdCompressor(level=6).compress(raw)
        elif self.codec == "lzham":
            import lzham
            compressed = b"SCLZ" + bytes([18]) + struct.pack("<I", len(raw)) + lzham.compress(raw, {"dict_size_log2": 18})
        else:
            prop = self.props[0]
            rest = prop // 9
            filters = [{"id": lzma.FILTER_LZMA1,
                        "dict_size": struct.unpack_from("<I", self.props, 1)[0],
                        "lc": prop % 9, "lp": rest % 5, "pb": rest // 5}]
            compressed = self.props + struct.pack("<I", len(raw)) + lzma.compress(raw, format=lzma.FORMAT_RAW, filters=filters)
        header = b""
        if self.wrapped:
            header = b"SC" + struct.pack(">I", self.version)
            if self.version == 4:
                header += struct.pack(">I", self.subversion)
            header += struct.pack(">I", 16) + hashlib.md5(raw).digest()
        return header + compressed + self.suffix


class MatrixValues(Sequence):
    """Six floats per matrix without a million resident Python dictionaries."""
    def __init__(self, values):
        self.values = values

    def __len__(self):
        return len(self.values) // 6

    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        if index < 0:
            index += len(self)
        if not 0 <= index < len(self):
            raise IndexError(index)
        return list(self.values[index * 6:index * 6 + 6])


class MatrixRows(MatrixValues):
    def __getitem__(self, index):
        if isinstance(index, slice):
            return [self[i] for i in range(*index.indices(len(self)))]
        return dict(zip(MKEYS, super().__getitem__(index)))

    def as_values(self):
        return MatrixValues(self.values)

    def append(self, row):
        self.values.extend(row)


@dataclass
class Record:
    kind: str
    key: object
    tag: int
    start: int
    end: int


@dataclass
class State:
    container: Container
    raw: bytes
    texture_only: bool = False
    records: list = field(default_factory=list)
    extras: dict = field(default_factory=dict)
    signatures: dict = field(default_factory=dict)
    bank_signatures: list = field(default_factory=list)
    bank_counts: list = field(default_factory=list)
    textures: dict = field(default_factory=dict)
    texture_files: dict = field(default_factory=dict)
    padding: bytes = bytes(5)
    trailing: bytes = b""
    external: bool = False
    lowres: bool = False
    multi: bool = False
    suffixes: tuple = ("_highres", "_lowres")


def strip_order(count):
    order, lo, hi = [], 0, count - 1
    if count:
        order.append(lo)
        lo += 1
    while lo <= hi:
        order.append(lo)
        lo += 1
        if lo <= hi:
            order.append(hi)
            hi -= 1
    return order


def tiled_pixels(raw, width, height, bpp, encode=False):
    """SC1 raw atlases use 32x32 tiles; expose ordinary scanlines to SC2 panels."""
    out = bytearray(len(raw))
    source = 0
    for top in range(0, height, 32):
        for left in range(0, width, 32):
            row_size = min(32, width - left) * bpp
            for y in range(top, min(top + 32, height)):
                target = (y * width + left) * bpp
                if encode:
                    out[source:source + row_size] = raw[target:target + row_size]
                else:
                    out[target:target + row_size] = raw[source:source + row_size]
                source += row_size
    return bytes(out)


def read_texture(tag, body, has_pixels):
    r = Reader(body)
    external = r.string() if tag == 47 else None
    ktx_size = r.unpack("I") if tag == 45 and has_pixels else None
    pixel, width, height = r.unpack("BHH")
    data = r.take(len(body) - r.pos)
    if has_pixels and not external:
        if ktx_size is not None:
            if len(data) != ktx_size:
                raise ValueError("Truncated SC1 KTX texture")
        else:
            bpp = {0: 4, 1: 4, 2: 2, 3: 2, 4: 2, 5: 4, 6: 2, 7: 4, 8: 4, 9: 2, 10: 1}.get(pixel)
            if bpp is None or len(data) != width * height * bpp:
                raise ValueError(f"SC1 texture dimensions/pixel type do not match payload ({width}x{height}, type {pixel})")
            if tag in (27, 28, 29):
                data = tiled_pixels(data, width, height, bpp)
            if pixel == 3:
                # SC1 RGB5_A1 has red in bits 11..15 and alpha in bit 0;
                # Pillow's RGBA;15 decoder has a different bit layout.
                values = array.array("H")
                values.frombytes(data)
                if __import__("sys").byteorder != "little":
                    values.byteswap()
                converted = bytearray(width * height * 4)
                for i, value in enumerate(values):
                    converted[i * 4:i * 4 + 4] = bytes(((value >> 11) * 255 // 31, ((value >> 6) & 31) * 255 // 31,
                                                       ((value >> 1) & 31) * 255 // 31, (value & 1) * 255))
                data, pixel = bytes(converted), 0
            else:
                pixel = {5: 0, 7: 0, 8: 0, 9: 2}.get(pixel, pixel)
    return {"texture_format": 8 if ktx_size is not None else 0,
            "pixel_type": pixel, "width": width, "height": height,
            "data": data, "external_texture": external or None}


def read_shape(doc, tag, body, state):
    r = Reader(body)
    id, count = r.unpack("HH")
    vertices_count = r.unpack("H") if tag == 18 else 4 * count
    commands, nested, points = [], [], bytearray()
    base = len(doc.storage["shapes_bitmap_poins"]) // 12
    known_vertices = 0
    for ct, cb, start, end in r.tags():
        if ct in (4, 17, 22):
            cr = Reader(cb)
            texture = cr.unpack("B")
            n = 4 if ct == 4 else cr.unpack("B")
            xy = [tuple(v / 20 for v in cr.unpack("ii")) for _ in range(n)]
            uv = [cr.unpack("HH") for _ in range(n)]
            if cr.pos != len(cb):
                raise ValueError(f"Unrecognized SC1 bitmap command fields in shape {id}")
            offset = base + len(points) // 12
            for i in strip_order(n):
                points.extend(struct.pack("<ffHH", *xy[i], *uv[i]))
            commands.append({"unk1": 0, "texture_index": texture, "points_count": n, "points_offset": offset})
            nested.append(("command", len(commands) - 1, ct, body[start:end]))
            known_vertices += n
        elif ct != 0:
            nested.append(("opaque", None, ct, body[start:end]))
    # A mutable buffer during loading avoids O(n^2) copies for thousands of shapes.
    doc.storage["shapes_bitmap_poins"].extend(points)
    obj = {"id": id, "commands": commands}
    state.extras[id] = {"nested": nested, "unknown_commands": max(0, count - len(commands)), "unknown_vertices": max(0, vertices_count - known_vertices),
                        "tail": body[r.pos:], "tag": tag}
    return obj


def read_clip(doc, tag, body, state):
    if tag in (3, 14):
        raise ValueError(f"Deprecated SC1 movieclip tag {tag} is not supported")
    r = Reader(body)
    id, fps, frame_count = r.unpack("HBH")
    custom = b""
    if tag == 49:
        begin = r.pos
        count = r.unpack("B")
        for _ in range(count):
            if r.unpack("B") != 0:
                raise ValueError("Unknown SC1 custom property type")
            r.take(1)
        custom = body[begin:r.pos]
    n = r.unpack("I")
    values = array.array("H")
    values.frombytes(r.take(6 * n))
    if __import__("sys").byteorder != "little":
        values.byteswap()
    offset = len(doc.storage["movieclips_frame_elements"])
    doc.storage["movieclips_frame_elements"].extend(values)
    child_count = r.unpack("H")
    ids = array.array("H", (r.unpack("H") for _ in range(child_count)))
    blends = r.take(child_count) if tag in (12, 35, 49) else bytes(child_count)
    names = array.array("I", (doc.intern(r.string()) for _ in range(child_count)))
    frames, nested, bank, grid = [], [], 0, None
    for ft, fb, start, end in r.tags():
        fr = Reader(fb)
        if ft == 11:
            frames.append({"used_transform": fr.unpack("H"), "label_ref_id": doc.intern(fr.string())})
        elif ft == 31:
            left, top, width, height = (v / 20 for v in fr.unpack("4i"))
            grid = len(doc.storage["rectangles"])
            doc.storage["rectangles"].append(dict(left=left, top=top, right=left + width, bottom=top + height))
        elif ft == 41:
            bank = fr.unpack("B")
        elif ft != 0:
            nested.append(body[start:end])
    if len(frames) != frame_count or sum(f["used_transform"] for f in frames) != n:
        raise ValueError(f"SC1 movieclip {id}: inconsistent frame/element count")
    obj = {"id": id, "framerate": fps, "frames_count": frame_count, "unknown_bool": int(tag == 35),
           "children_ids": ids, "children_name_ref_ids": names, "children_blending": blends,
           "frames": frames, "short_frames": [], "frame_elements_offset": offset,
           "matrix_bank_index": bank, "scaling_grid_index": grid, "export_name_ref_id": None}
    state.extras[id] = {"tag": tag, "nested": nested, "custom": custom, "tail": body[r.pos:]}
    return obj


def read_text(doc, tag, body, state):
    r = Reader(body)
    id = r.unpack("H")
    font = doc.intern(r.string())
    color = r.unpack("I")
    bold, italic, multiline, dynamic, align, size = r.unpack("6B")
    left, top, right, bottom = r.unpack("4h")
    outlined = r.unpack("B")
    text = doc.intern(r.string())
    device = r.unpack("B") if tag != 7 else 0
    outline = r.unpack("I") if tag not in (7, 15, 20) else 0
    angle = r.unpack("i") if tag in (33, 43, 44, 46) else -65536
    bend = r.unpack("h") if tag in (43, 44, 46) else 0
    kern = r.unpack("B") if tag in (44, 46) else 0
    typography = doc.intern(r.string()) if tag == 46 else 0
    styles = int(bool(device)) | (int(bool(outlined)) << 1) | (int(bool(bold)) << 2) | (int(bool(italic)) << 3)
    styles |= int(bool(multiline)) << 4 | int(tag in (20, 21, 33, 43, 44, 46)) << 5 | int(bool(kern)) << 6
    obj = dict(id=id, unused1=0, font_name_ref_id=font, left=left, top=top, right=right, bottom=bottom,
               font_color=color, outline_color=outline, text_ref_id=text, typography_ref_id=typography,
               styles=styles, align=align, font_size=size, unused2=dynamic, outline_angle=angle)
    state.extras[id] = {"tag": tag, "bend": bend, "tail": body[r.pos:]}
    return obj


def resource_signature(doc, kind, obj):
    h = hashlib.sha256(pickle.dumps(obj, protocol=4))
    if kind == "shapes":
        buf = doc.storage["shapes_bitmap_poins"]
        for c in obj["commands"]:
            start = c["points_offset"] * 12
            h.update(buf[start:start + c["points_count"] * 12])
    elif kind == "movieclips":
        start = obj["frame_elements_offset"]
        size = 3 * sum(f["used_transform"] for f in obj["frames"])
        h.update(doc.storage["movieclips_frame_elements"][start:start + size].tobytes())
        refs = list(obj["children_name_ref_ids"]) + [f["label_ref_id"] for f in obj["frames"]]
        h.update(pickle.dumps([doc.string(i) for i in refs], protocol=4))
        grid = obj.get("scaling_grid_index")
        if grid is not None:
            h.update(pickle.dumps(doc.storage["rectangles"][grid], protocol=4))
    elif kind == "textfields":
        h.update(pickle.dumps([doc.string(obj[k + "_ref_id"]) for k in ("font_name", "text", "typography")], protocol=4))
    return h.digest()


def texture_signature(data):
    h = hashlib.sha256(pickle.dumps({k: v for k, v in data.items() if k != "data"}, protocol=4))
    h.update(data.get("data", b""))
    return h.digest()


def bank_signature(raw):
    matrices = raw["matrices"]
    if isinstance(matrices, MatrixRows):
        values = matrices.values.tobytes()
    else:
        values = b"".join(struct.pack("<6f", *(m[k] for k in MKEYS)) for m in matrices)
    return hashlib.sha256(values + pickle.dumps(raw["colors"], protocol=4)).digest()


def load(cls, path, data):
    doc = cls(version=5)
    doc.path = Path(path).resolve()
    raw, container = Container.decode(data)
    state = State(container, raw, texture_only=doc.path.name.endswith("_tex.sc"))
    doc.sc1 = state
    r = Reader(raw)
    doc.storage["shapes_bitmap_poins"] = bytearray()
    doc._sc1_strings = {"": 0}
    if state.texture_only:
        expected = None
    else:
        counts = r.unpack("6H")
        expected = dict(zip(("shapes", "movieclips", "textures", "textfields", "matrices", "colors"), counts))
        state.padding = r.take(5)
        n = r.unpack("H")
        ids = array.array("H", (r.unpack("H") for _ in range(n)))
        refs = array.array("I", (doc.intern(r.string()) for _ in range(n)))
        doc.tables["ExportNames"] = {"object_ids": ids, "name_ref_ids": refs}
    banks = doc.storage["matrix_banks"]
    banks.append({"matrices": MatrixRows(array.array("f")), "colors": [], "half_matrices": []})
    bank, texture_index = 0, 0
    for tag, body, start, end in r.tags():
        kind, key = "opaque", None
        if tag == 0:
            break
        if tag in (2, 18):
            obj = read_shape(doc, tag, body, state)
            doc.tables["Shapes"]["shapes"].append(obj)
            kind, key = "resource", obj["id"]
        elif tag in CLIPS:
            obj = read_clip(doc, tag, body, state)
            doc.tables["MovieClips"]["movieclips"].append(obj)
            kind, key = "resource", obj["id"]
        elif tag in TEXTFIELDS:
            obj = read_text(doc, tag, body, state)
            doc.tables["TextFields"]["textfields"].append(obj)
            kind, key = "resource", obj["id"]
        elif tag in (38, 39, 40):
            obj = {"id": Reader(body).unpack("H"), "type": tag}
            doc.tables["MovieClipModifiers"]["modifiers"].append(obj)
            kind, key = "resource", obj["id"]
        elif tag in (8, 36):
            v = struct.unpack_from("<6i", body)
            divider = 1024 if tag == 8 else 65535
            index = len(banks[bank]["matrices"])
            banks[bank]["matrices"].append([*(x / divider for x in v[:4]), v[4] / 20, v[5] / 20])
            kind, key = "matrices", (bank, index, 1)
        elif tag == 9:
            v = Reader(body).unpack("7B")
            banks[bank]["colors"].append(dict(zip(CKEYS, (v[4], v[5], v[6], v[3], v[0], v[1], v[2]))))
            kind, key = "colors", (bank, len(banks[bank]["colors"]) - 1, 1)
        elif tag == 42:
            matrix_count, color_count = Reader(body).unpack("HH")
            bank += 1
            banks.append({"matrices": MatrixRows(array.array("f")), "colors": [], "half_matrices": []})
            kind, key = "bank", (bank, matrix_count, color_count)
        elif tag in TEXTURES:
            texture = read_texture(tag, body, not state.external)
            doc.tables["Textures"]["textures"].append({"highres": texture, "lowres": None})
            kind, key = "texture", texture_index
            texture_index += 1
        elif tag == 23:
            state.lowres = True
        elif tag == 26:
            state.external = True
        elif tag == 30:
            state.multi = True
        elif tag == 32:
            sr = Reader(body)
            state.suffixes = (sr.string(), sr.string())
        elif tag == 37:
            kind = "modifier_count"
        if kind in ("matrices", "colors") and state.records and state.records[-1].kind == kind and state.records[-1].key[0] == bank and state.records[-1].end == start:
            previous = state.records[-1]
            previous.key = (bank, previous.key[1], previous.key[2] + 1)
            previous.end = end
        else:
            state.records.append(Record(kind, key, tag, start, end))
    state.trailing = raw[r.pos:]
    doc.storage["shapes_bitmap_poins"] = bytes(doc.storage["shapes_bitmap_poins"])
    del doc._sc1_strings
    if expected is not None:
        for name, table, key in (("shapes", "Shapes", "shapes"), ("movieclips", "MovieClips", "movieclips"), ("textfields", "TextFields", "textfields"), ("textures", "Textures", "textures")):
            if len(doc.tables[table][key]) != expected[name]:
                raise ValueError(f"SC1 {name} count does not match header")
        if len(banks[0]["matrices"]) != expected["matrices"] or len(banks[0]["colors"]) != expected["colors"]:
            raise ValueError("SC1 first matrix bank count does not match header")
        for rec in state.records:
            if rec.kind == "bank":
                index, mc, cc = rec.key
                if len(banks[index]["matrices"]) != mc or len(banks[index]["colors"]) != cc:
                    raise ValueError(f"SC1 bank {index} count does not match header")
    if state.external and not state.texture_only:
        load_texture_files(doc, state)
    for i, t in enumerate(doc.tables["Textures"]["textures"]):
        for variant in ("highres", "lowres"):
            if t.get(variant) is not None:
                state.textures[(i, variant)] = texture_signature(t[variant])
                name = t[variant].get("external_texture")
                if name:
                    rel = Path(name)
                    if rel.is_absolute() or ".." in rel.parts:
                        raise ValueError("Unsafe SC1 external texture path")
                    src = doc.path.parent / rel
                    if src.is_file():
                        doc.sidecars[rel.as_posix()] = src.read_bytes()
    doc._reindex()
    state.signatures = {id: resource_signature(doc, kind, obj) for id, (kind, obj) in doc.index.items()}
    state.bank_signatures = [bank_signature(b) for b in banks]
    state.bank_counts = [(len(b["matrices"]), len(b["colors"])) for b in banks]
    doc.dirty.clear()
    return doc


def load_texture_files(doc, state):
    base = doc.path.stem
    if any("/" in suffix or "\\" in suffix for suffix in state.suffixes):
        raise ValueError("Unsafe SC1 texture suffix")
    candidates = [("highres", state.suffixes[0] + "_tex.sc") if state.multi else ("highres", "_tex.sc")]
    if state.multi:
        candidates.append(("highres", "_tex.sc"))
    if state.lowres or state.multi:
        candidates.append(("lowres", state.suffixes[1] + "_tex.sc"))
    loaded = set()
    for variant, suffix in candidates:
        if variant in loaded:
            continue
        path = doc.path.parent / (base + suffix)
        if not path.is_file():
            continue
        original = path.read_bytes()
        raw, container = Container.decode(original)
        r = Reader(raw)
        records, index = [], 0
        for tag, body, start, end in r.tags():
            if tag == 0:
                break
            if tag in TEXTURES:
                if index >= len(doc.tables["Textures"]["textures"]):
                    raise ValueError(f"Too many textures in {path.name}")
                doc.tables["Textures"]["textures"][index][variant] = read_texture(tag, body, True)
                records.append(Record("texture", index, tag, start, end))
                index += 1
            else:
                records.append(Record("opaque", None, tag, start, end))
        if index != len(doc.tables["Textures"]["textures"]):
            raise ValueError(f"Texture count mismatch in {path.name}")
        state.texture_files[variant] = (suffix, container, raw, records, raw[r.pos:])
        loaded.add(variant)
    if not loaded:
        raise ValueError(f"SC1 texture file is missing: put {base}_tex.sc beside {doc.path.name}")
    if "highres" not in loaded:
        # Keep the main file's original dimensions for normalized UVs; preview
        # uses the available low-resolution image's actual dimensions.
        for texture in doc.tables["Textures"]["textures"]:
            texture["highres"] = texture["lowres"]


def write_shape(doc, obj, extra):
    vertices = doc.storage["shapes_bitmap_poins"]
    commands, encoded = obj["commands"], []
    for c in commands:
        n, start = c["points_count"], c["points_offset"] * 12
        if n > 255 or c["texture_index"] > 255:
            raise ValueError("SC1 bitmap commands allow at most 255 vertices/textures")
        strip = [struct.unpack_from("<ffHH", vertices, start + i * 12) for i in range(n)]
        fan = [None] * n
        for index, value in zip(strip_order(n), strip):
            fan[index] = value
        body = bytes([c["texture_index"], n])
        body += b"".join(struct.pack("<ii", round(v[0] * 20), round(v[1] * 20)) for v in fan)
        body += b"".join(struct.pack("<HH", *v[2:]) for v in fan)
        encoded.append(tag_bytes(22, body))
    nested, used, opaque = [], set(), 0
    for kind, index, tag, original in extra.get("nested", []):
        if kind == "opaque":
            nested.append(original)
            opaque += 1
        elif index < len(encoded):
            nested.append(encoded[index])
            used.add(index)
    nested.extend(value for i, value in enumerate(encoded) if i not in used)
    count = len(commands) + extra.get("unknown_commands", 0)
    n = sum(c["points_count"] for c in commands) + extra.get("unknown_vertices", 0)
    body = struct.pack("<HHH", obj["id"], count, n) + b"".join(nested) + END + extra.get("tail", b"")
    return tag_bytes(18, body)


def write_clip(doc, obj, extra):
    children, frames = obj["children_ids"], obj["frames"]
    if obj["matrix_bank_index"] > 255:
        raise ValueError("SC1 permits at most 256 matrix banks")
    tag = 49 if extra.get("tag") == 49 else 35 if obj["unknown_bool"] else 12
    body = struct.pack("<HBH", obj["id"], obj["framerate"], len(frames))
    if tag == 49:
        body += extra.get("custom", b"\0")
    n = sum(f["used_transform"] for f in frames)
    offset = obj["frame_elements_offset"]
    values = doc.storage["movieclips_frame_elements"][offset:offset + n * 3]
    if __import__("sys").byteorder != "little":
        values.byteswap()
    body += struct.pack("<I", n) + values.tobytes() + struct.pack("<H", len(children))
    body += b"".join(struct.pack("<H", id) for id in children)
    blends = bytes(obj.get("children_blending", b""))
    body += (blends + bytes(len(children)))[:len(children)]
    refs = obj.get("children_name_ref_ids", [])
    body += b"".join(string_bytes(doc.string(refs[i]) if i < len(refs) else "") for i in range(len(children)))
    if obj["matrix_bank_index"]:
        body += tag_bytes(41, bytes([obj["matrix_bank_index"]]))
    for frame in frames:
        body += tag_bytes(11, struct.pack("<H", frame["used_transform"]) + string_bytes(doc.string(frame["label_ref_id"])))
    grid = obj.get("scaling_grid_index")
    if grid is not None:
        rect = doc.storage["rectangles"][grid]
        values = (rect["left"], rect["top"], rect["right"] - rect["left"], rect["bottom"] - rect["top"])
        body += tag_bytes(31, struct.pack("<4i", *(round(v * 20) for v in values)))
    body += b"".join(extra.get("nested", [])) + END + extra.get("tail", b"")
    return tag_bytes(tag, body)


def write_text(doc, obj, extra):
    styles = obj["styles"]
    # Keep the original tag (including implicit unknown-style flags), upgrading
    # only when a newly edited property cannot be represented by it.
    tag = extra.get("tag", 7)
    required = 46 if doc.string(obj["typography_ref_id"]) else 44 if styles & 64 else 43 if extra.get("bend", 0) else 33 if obj["outline_angle"] != -65536 else 25 if obj["outline_color"] else 20 if styles & 32 else 15 if styles & 1 else 7
    tag = max(tag, required)
    body = struct.pack("<H", obj["id"]) + string_bytes(doc.string(obj["font_name_ref_id"]))
    body += struct.pack("<I6B4hB", obj["font_color"], bool(styles & 4), bool(styles & 8), bool(styles & 16),
                        obj["unused2"], obj["align"], obj["font_size"], obj["left"], obj["top"], obj["right"], obj["bottom"], bool(styles & 2))
    body += string_bytes(doc.string(obj["text_ref_id"]))
    if tag != 7:
        body += bytes([bool(styles & 1)])
    if tag not in (7, 15, 20):
        body += struct.pack("<I", obj["outline_color"])
    if tag in (33, 43, 44, 46):
        body += struct.pack("<i", obj["outline_angle"])
    if tag in (43, 44, 46):
        body += struct.pack("<h", extra.get("bend", 0))
    if tag in (44, 46):
        body += bytes([bool(styles & 64)])
    if tag == 46:
        body += string_bytes(doc.string(obj["typography_ref_id"]))
    return tag_bytes(tag, body + extra.get("tail", b""))


def write_resource(doc, kind, obj, extra):
    if kind == "shapes":
        return write_shape(doc, obj, extra)
    if kind == "movieclips":
        return write_clip(doc, obj, extra)
    if kind == "textfields":
        return write_text(doc, obj, extra)
    if obj["type"] not in (38, 39, 40):
        raise ValueError("Unsupported SC1 modifier type")
    return tag_bytes(obj["type"], struct.pack("<H", obj["id"]))


def write_texture(data, has_pixels, preferred=24):
    external = data.get("external_texture")
    prefix = struct.pack("<BHH", data["pixel_type"], data["width"], data["height"])
    if external:
        return tag_bytes(47, string_bytes(external) + prefix)
    raw = bytes(data.get("data", b""))
    if raw.startswith(b"\x28\xb5\x2f\xfd"):
        raw = zstandard.ZstdDecompressor().decompress(raw, max_output_size=MAX_UNPACKED)
    if has_pixels and raw.startswith(b"\xabKTX 11"):
        return tag_bytes(45, struct.pack("<I", len(raw)) + prefix + raw)
    tag = preferred if preferred in TEXTURES - {45, 47} else 24
    if has_pixels and tag in (27, 28, 29):
        bpp = {0: 4, 1: 4, 2: 2, 3: 2, 4: 2, 6: 2, 10: 1}[data["pixel_type"]]
        raw = tiled_pixels(raw, data["width"], data["height"], bpp, encode=True)
    return tag_bytes(tag, prefix + (raw if has_pixels else b""))


def bank_tags(bank, start=0, count=None, colors=False):
    rows = bank["colors" if colors else "matrices"]
    stop = len(rows) if count is None else start + count
    out = []
    for row in rows[start:stop]:
        if colors:
            out.append(tag_bytes(9, bytes(row[k] for k in ("r_add", "g_add", "b_add", "alpha", "r_mul", "g_mul", "b_mul"))))
        else:
            values = [round(row[k] * (65535 if i < 4 else 20)) for i, k in enumerate(MKEYS)]
            out.append(tag_bytes(36, struct.pack("<6i", *values)))
    return b"".join(out)


def serialize(doc):
    state = doc.sc1
    banks = doc.storage["matrix_banks"]
    atlases = doc.tables["Textures"]["textures"]
    if len(banks) > 256 or len(atlases) > 255:
        raise ValueError("SC1 allows at most 256 banks and 255 textures")
    bank_same = [i < len(state.bank_signatures) and bank_signature(b) == state.bank_signatures[i] for i, b in enumerate(banks)]
    resource_same = {id: resource_signature(doc, kind, obj) == state.signatures.get(id) for id, (kind, obj) in doc.index.items()}
    output, seen, texture_seen = [], set(), set()
    def extensions(index):
        if index < len(state.bank_counts):
            mc, cc = state.bank_counts[index]
            if len(banks[index]["matrices"]) > mc:
                output.append(bank_tags(banks[index], mc))
            if len(banks[index]["colors"]) > cc:
                output.append(bank_tags(banks[index], cc, colors=True))
    modifiers = len(doc.tables["MovieClipModifiers"]["modifiers"])
    if modifiers and not any(r.kind == "modifier_count" for r in state.records):
        output.append(tag_bytes(37, struct.pack("<H", modifiers)))
    for rec in state.records:
        original = state.raw[rec.start:rec.end]
        if rec.kind == "resource":
            if rec.key not in doc.index:
                continue
            kind, obj = doc.index[rec.key]
            output.append(original if resource_same[rec.key] else write_resource(doc, kind, obj, state.extras.get(rec.key, {})))
            seen.add(rec.key)
        elif rec.kind in ("matrices", "colors"):
            bank, start, count = rec.key
            if bank >= len(banks):
                raise ValueError("SC1 matrix banks cannot be removed or reordered")
            output.append(original if bank_same[bank] else bank_tags(banks[bank], start, count, colors=rec.kind == "colors"))
        elif rec.kind == "bank":
            index = rec.key[0]
            extensions(index - 1)
            output.append(tag_bytes(42, struct.pack("<HH", len(banks[index]["matrices"]), len(banks[index]["colors"]))))
        elif rec.kind == "modifier_count":
            output.append(tag_bytes(37, struct.pack("<H", modifiers)))
        elif rec.kind == "texture":
            if rec.key >= len(atlases):
                continue
            data = atlases[rec.key]["highres"]
            same = texture_signature(data) == state.textures.get((rec.key, "highres"))
            output.append(original if same else write_texture(data, not state.external, rec.tag))
            texture_seen.add(rec.key)
        else:
            output.append(original)
    if state.bank_counts:
        extensions(len(state.bank_counts) - 1)
    for i in range(len(state.bank_signatures), len(banks)):
        bank = banks[i]
        if i:
            output.append(tag_bytes(42, struct.pack("<HH", len(bank["matrices"]), len(bank["colors"]))))
        output.extend((bank_tags(bank), bank_tags(bank, colors=True)))
    for id, (kind, obj) in doc.index.items():
        if id not in seen:
            output.append(write_resource(doc, kind, obj, {}))
    for i, texture in enumerate(atlases):
        if i not in texture_seen:
            output.append(write_texture(texture["highres"], not state.external))
    header = b""
    if not state.texture_only:
        first = banks[0]
        counts = (len(doc.tables["Shapes"]["shapes"]), len(doc.tables["MovieClips"]["movieclips"]), len(atlases),
                  len(doc.tables["TextFields"]["textfields"]), len(first["matrices"]), len(first["colors"]))
        exports = doc.tables["ExportNames"]
        header = struct.pack("<6H", *counts) + state.padding + struct.pack("<H", len(exports["object_ids"]))
        header += b"".join(struct.pack("<H", id) for id in exports["object_ids"])
        header += b"".join(string_bytes(doc.string(ref)) for ref in exports["name_ref_ids"])
    return header + b"".join(output) + END + state.trailing


def atomic_write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".scstudio-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save(doc, path):
    state = doc.sc1
    raw = serialize(doc)
    main = state.container.original if raw == state.raw else state.container.encode(raw)
    path = Path(path).resolve()
    pending = []
    for texture in doc.tables["Textures"]["textures"]:
        for variant in ("highres", "lowres"):
            data = texture.get(variant)
            if data and data.get("external_texture"):
                rel = Path(data["external_texture"])
                if rel.is_absolute() or ".." in rel.parts:
                    raise ValueError("Unsafe SC1 external texture path")
                payload = doc.sidecars.get(rel.as_posix())
                if payload is None:
                    src = doc.path.parent / rel
                    if src.resolve() == (path.parent / rel).resolve():
                        continue
                    payload = src.read_bytes()
                dest = path.parent / rel
                if dest.is_file() and dest.read_bytes() != payload:
                    raise ValueError(f"External texture conflict: {rel}")
                pending.append((dest, payload))
    for variant, (suffix, container, original, records, tail) in state.texture_files.items():
        texture_records = [rec for rec in records if rec.kind == "texture"]
        atlases = doc.tables["Textures"]["textures"]
        if len(texture_records) == len(atlases) and all(t.get(variant) is not None and texture_signature(t[variant]) == state.textures.get((i, variant)) for i, t in enumerate(atlases)):
            pending.append((path.parent / (path.stem + suffix), container.original))
            continue
        parts, seen = [], set()
        for rec in records:
            if rec.kind == "texture":
                if rec.key >= len(doc.tables["Textures"]["textures"]):
                    continue
                data = doc.tables["Textures"]["textures"][rec.key].get(variant)
                if data is None:
                    raise ValueError(f"Missing SC1 {variant} texture {rec.key}")
                same = texture_signature(data) == state.textures.get((rec.key, variant))
                parts.append(original[rec.start:rec.end] if same else write_texture(data, True, rec.tag))
                seen.add(rec.key)
            else:
                parts.append(original[rec.start:rec.end])
        for i, texture in enumerate(doc.tables["Textures"]["textures"]):
            if i not in seen:
                data = texture.get(variant)
                if data is None:
                    raise ValueError(f"New SC1 texture {i} has no {variant} variant")
                parts.append(write_texture(data, True))
        payload = b"".join(parts) + END + tail
        encoded = container.original if payload == original else container.encode(payload)
        pending.append((path.parent / (path.stem + suffix), encoded))
    # Resolve all encodings before modifying any file; write companions first.
    for dest, encoded in pending:
        if not dest.is_file() or dest.read_bytes() != encoded:
            atomic_write(dest, encoded)
    atomic_write(path, main)
    doc.path = path
    doc.dirty.clear()
