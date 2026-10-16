"""SC1 integration tests use hand-authored tag streams, not game assets."""

import os
import struct
from pathlib import Path

import pytest
from test_gui import window

from sc_studio.document import Document
from sc_studio.sc1 import Container, END, Reader, tag_bytes
from sc_studio.textures import image


def s(value):
    raw = value.encode()
    return bytes([len(raw)]) + raw


def fixture_pair(folder, *, codec="lzma", version=4, custom=False):
    folder.mkdir(parents=True, exist_ok=True)
    # A four-corner perimeter in SC1 must become a triangle strip in the editor.
    command = b"\x00\x04" + struct.pack("<8i", 0, 0, 400, 0, 400, 400, 0, 400)
    command += struct.pack("<8H", 0, 0, 65535, 0, 65535, 65535, 0, 65535)
    shape = struct.pack("<HHH", 3, 1, 4) + tag_bytes(22, command) + tag_bytes(90, b"shape-extension") + END
    text = struct.pack("<H", 4) + s("Arial") + struct.pack("<I6B4hB", 0xffffffff, 1, 0, 1, 1, 2, 20, 0, 0, 100, 30, 1)
    text += s("Hello START") + b"\x01" + struct.pack("<Ii", 0xff000000, -65536) + b"text-extension"
    clip = struct.pack("<HBH", 7, 24, 2)
    if custom:
        clip += b"\x01\x00\x01"  # one bool custom property
    clip += struct.pack("<I6H", 2, 0, 0, 0, 1, 65535, 65535)
    clip += struct.pack("<H2H", 2, 3, 4) + b"\x00\x01" + s("sprite") + s("label")
    clip += tag_bytes(11, struct.pack("<H", 1) + s("start"))
    clip += tag_bytes(11, struct.pack("<H", 1) + s("end"))
    clip += tag_bytes(31, struct.pack("<4i", 0, 0, 400, 400))
    clip += tag_bytes(91, b"clip-extension") + END
    header = struct.pack("<6H", 1, 1, 1, 1, 1, 1) + b"abcde" + struct.pack("<HH", 1, 7) + s("demo")
    main = header + tag_bytes(26) + tag_bytes(1, struct.pack("<BHH", 0, 2, 2))
    main += tag_bytes(18, shape) + tag_bytes(33, text)
    main += tag_bytes(8, struct.pack("<6i", 1024, 0, 0, 1024, 800, 400))
    main += tag_bytes(9, bytes([1, 2, 3, 200, 255, 254, 253]))
    main += tag_bytes(49 if custom else 12, clip) + tag_bytes(92, b"global-extension") + END + b"payload-tail"
    pixels = bytes([255, 0, 0, 255, 0, 255, 0, 255, 0, 0, 255, 255, 255, 255, 0, 255])
    textures = tag_bytes(28, struct.pack("<BHH", 0, 2, 2) + pixels) + END
    container = Container(b"", version=version, codec=codec, wrapped=codec != "raw", suffix=b"STARTopaque-export-hashes")
    path = folder / "ui.sc"
    path.write_bytes(container.encode(main))
    path.with_name("ui_tex.sc").write_bytes(container.encode(textures))
    return path, pixels


@pytest.mark.parametrize("codec,version", [("raw", 0), ("lzma", 1), ("lzma", 4), ("zstd", 3), ("zstd", 4), ("lzham", 3)])
def test_sc1_pair_read_and_byte_identical_save(codec, version, tmp_path):
    if codec == "lzham":
        pytest.importorskip("lzham")
    source, pixels = fixture_pair(tmp_path / "source", codec=codec, version=version)
    doc = Document.load(source)
    assert doc.format_name == "SC1"
    assert doc.validate() == []
    assert set(doc.index) == {3, 4, 7}
    assert doc.names == {7: ["demo"]}
    assert doc.resource(3)["commands"][0]["vertices"] == [[0, 0, 0, 0], [20, 0, 65535, 0], [0, 20, 0, 65535], [20, 20, 65535, 65535]]
    assert list(doc.bank(0)["matrices"][0]) == [1, 0, 0, 1, 40, 20]
    assert doc.bank(0)["colors"][0] == [255, 254, 253, 200, 1, 2, 3]
    assert doc.resource(7)["frames"][1]["label"] == "end"
    assert doc.resource(4)["unused2"] == 1
    assert image(doc.tables["Textures"]["textures"][0]["highres"]).tobytes() == pixels
    target = tmp_path / "output" / "copy.sc"
    doc.save(target)
    assert target.read_bytes() == source.read_bytes()
    assert target.with_name("copy_tex.sc").read_bytes() == source.with_name("ui_tex.sc").read_bytes()


@pytest.mark.parametrize("custom", [False, True])
def test_sc1_edit_resources_and_preserve_extensions(tmp_path, custom):
    source, _ = fixture_pair(tmp_path / "source", custom=custom)
    doc = Document.load(source)
    shape = doc.resource(3)
    shape["commands"][0]["vertices"][0][0] = 1.25
    doc.update("shapes", shape)
    text = doc.resource(4)
    text["text"] = "Привет ✓"
    text["font_size"] = 23
    doc.update("textfields", text)
    clip = doc.resource(7)
    clip["framerate"] = 17
    clip["frames"][0]["label"] = "changed"
    clip["matrix_bank_index"] = doc.add_bank([[1, 0, 0, 1, 7.5, -2]], [[255] * 4 + [0] * 3])
    doc.update("movieclips", clip)
    doc.set_exports(7, ["renamed"])
    target = tmp_path / "output" / "edited.sc"
    doc.save(target)
    reopened = Document.load(target)
    assert reopened.validate() == []
    assert reopened.resource(3)["commands"][0]["vertices"][0][0] == 1.25
    assert reopened.resource(4)["text"] == "Привет ✓"
    assert reopened.resource(4)["font_size"] == 23
    assert reopened.resource(7)["framerate"] == 17
    assert reopened.resource(7)["frames"][0]["label"] == "changed"
    assert reopened.bank(1)["matrices"][0] == [1, 0, 0, 1, 7.5, -2]
    assert reopened.names == {7: ["renamed"]}
    for extension in (b"shape-extension", b"text-extension", b"clip-extension", b"global-extension", b"payload-tail"):
        assert extension in reopened.sc1.raw
    assert reopened.sc1.container.suffix == doc.sc1.container.suffix
    if custom:
        assert reopened.sc1.extras[7]["custom"] == b"\x01\x00\x01"


def test_sc1_replace_texture_and_open_texture_file(tmp_path):
    source, _ = fixture_pair(tmp_path / "source")
    doc = Document.load(source)
    atlas = doc.tables["Textures"]["textures"][0]["highres"]
    atlas["data"] = bytes([9, 8, 7, 255]) * 4
    doc.dirty.add("Textures")
    target = tmp_path / "edited.sc"
    doc.save(target)
    texture_path = target.with_name("edited_tex.sc")
    reopened = Document.load(target)
    assert image(reopened.tables["Textures"]["textures"][0]["highres"]).getpixel((0, 0)) == (9, 8, 7, 255)
    texture_doc = Document.load(texture_path)
    assert texture_doc.index == {}
    assert image(texture_doc.tables["Textures"]["textures"][0]["highres"]).getpixel((1, 1)) == (9, 8, 7, 255)
    # Preserve the original tiled/downscaling texture tag after a replacement.
    raw, _ = Container.decode(texture_path.read_bytes())
    assert raw[0] == 28


def test_sc1_missing_companion_and_truncated_data(tmp_path):
    source, _ = fixture_pair(tmp_path)
    source.with_name("ui_tex.sc").unlink()
    with pytest.raises(ValueError, match="texture file is missing"):
        Document.load(source)
    source.write_bytes(b"SC\x00\x00\x00\x04")
    with pytest.raises(ValueError, match="Truncated"):
        Document.load(source)


def test_sc1_partial_tiles_and_rgb5a1(tmp_path):
    from sc_studio.sc1 import read_texture, tiled_pixels

    width, height = 35, 33
    pixels = bytes(i % 251 for i in range(width * height * 4))
    tiled = tiled_pixels(pixels, width, height, 4, encode=True)
    assert tiled != pixels
    data = read_texture(28, struct.pack("<BHH", 0, width, height) + tiled, True)
    assert data["data"] == pixels
    packed = struct.pack("<BHH2H", 3, 2, 1, 0xf801, 0x003e)
    data = read_texture(24, packed, True)
    decoded = image(data)
    assert [decoded.getpixel((i, 0)) for i in range(2)] == [(255, 0, 0, 255), (0, 0, 255, 0)]


def test_create_sc1_and_duplicate_resource(tmp_path):
    doc = Document(version=1)
    clip = doc.resource(doc.new_resource("movieclips"))
    clip["exports"] = ["new symbol"]
    doc.update("movieclips", clip)
    copied = doc.duplicate_resources([clip["id"]])[clip["id"]]
    path = tmp_path / "created.sc"
    doc.save(path)
    reopened = Document.load(path)
    assert reopened.sc1 is not None and reopened.validate() == []
    assert len(reopened.index) == 2
    assert reopened.resource(copied)["exports"] == ["new symbol_copy2"]


def test_sc1_gui_preview_edit_undo_and_new(window, tmp_path):
    source, _ = fixture_pair(tmp_path / "source")
    doc = Document.load(source)
    window.add_doc(doc)
    editor = window.current()
    editor.go_to(7)
    assert editor.preview.scene().items()
    assert window.info.text().startswith("SC1")
    editor.go_to(4)
    editor.property_widgets["font_size"][0].setValue(27)
    editor.apply_properties()
    assert doc.resource(4)["font_size"] == 27
    editor.undo()
    assert doc.resource(4)["font_size"] == 20
    assert doc.sc1 is not None
    editor.redo()
    assert doc.resource(4)["font_size"] == 27
    editor.mark_saved()
    window.actions["new_sc1"].trigger()
    assert window.current().doc.sc1 is not None


def test_sc1_mcp_create_and_open(window, tmp_path):
    from sc_studio.agent_gateway import AgentGateway

    gateway = AgentGateway(window)
    created = gateway.execute("new_document", {"version": 1})
    assert created["version"] == 1
    source, _ = fixture_pair(tmp_path / "source")
    opened = gateway.execute("open_document", {"path": str(source)})
    assert opened["version"] == 1 and opened["resources"] == 3


def test_sc1_import_into_sc2(tmp_path):
    source, _ = fixture_pair(tmp_path / "source")
    original = Document.load(source)
    target = Document()
    mapping = target.import_resources(original, [7])
    path = tmp_path / "sc2.sc"
    target.save(path)
    reopened = Document.load(path)
    assert reopened.sc1 is None and reopened.version == 6
    assert reopened.resource(mapping[7])["exports"] == ["demo"]
    assert reopened.validate() == []


@pytest.mark.skipif(not os.environ.get("SC1_SAMPLE"), reason="Set SC1_SAMPLE to test an actual game pair")
def test_sc1_real_pair(tmp_path):
    source = Path(os.environ["SC1_SAMPLE"])
    doc = Document.load(source)
    assert doc.sc1 is not None and doc.validate() == []
    target = tmp_path / source.name
    doc.save(target)
    assert target.read_bytes() == source.read_bytes()
    for variant, (suffix, *_rest) in doc.sc1.texture_files.items():
        assert (tmp_path / (source.stem + suffix)).read_bytes() == source.with_name(source.stem + suffix).read_bytes()
