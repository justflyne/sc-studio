"""Download and verify the public script using the APK's protocol v3.

Dependencies: PyNaCl. Downloaded JavaScript is saved, never executed.
"""

import argparse
import base64
import datetime
import hashlib
import http.client
import json
import secrets
from pathlib import Path

from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import VerifyKey


HOST = "script.backtobs.xyz"
PORT = 8787
CHANNEL_PUBLIC_KEY = "02135409e2a48c5f00d74fb9669ca67c69d2e2f6120ff3c47455c28d95f08439"
RELEASE_PUBLIC_KEY = "14c46a10259df2be9baec6300bf83047fc1f0f284615d93cfa2e1d0765b49760"
MAX_RESPONSE = 8 * 1024 * 1024


def download(output: Path, have: str | None, have_epoch: int):
    ephemeral = PrivateKey.generate()
    cnonce = secrets.token_hex(16)
    request = {
        "protocol": 3,
        "client": "btb-v59-gadget",
        "platform": "linux",
        "arch": "arm64",
        "cnonce": cnonce,
        "eph_pub": bytes(ephemeral.public_key).hex(),
        "have": have,
        "have_epoch": have_epoch,
    }
    payload = json.dumps(request, separators=(",", ":")).encode()
    output.mkdir(parents=True, exist_ok=True)
    (output / "request.json").write_bytes(payload)
    connection = http.client.HTTPConnection(HOST, PORT, timeout=15)
    connection._http_vsn = 10
    connection._http_vsn_str = "HTTP/1.0"
    try:
        connection.request("POST", "/v1/script", payload, {
            "Host": f"{HOST}:{PORT}",
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "Connection": "close",
        })
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE + 1)
        (output / "response.body").write_bytes(body)
        headers = dict(response.getheaders())
        (output / "response.headers.json").write_text(json.dumps(headers, indent=2))
        if len(body) > MAX_RESPONSE:
            raise ValueError("Response exceeds the client's 8 MiB limit")
        if response.status != 200:
            raise ValueError(f"HTTP {response.status}: {body[:2000]!r}")
        raw = json.loads(body)
        if not isinstance(raw.get("protocol"), int) or raw["protocol"] < 3:
            raise ValueError("Protocol downgrade refused")
        nonce = base64.b64decode(raw["seal_nonce"], validate=True)
        ciphertext = base64.b64decode(raw["seal_box"], validate=True)
        if len(nonce) != 24 or len(ciphertext) < 16:
            raise ValueError("Invalid crypto_box framing")
        box = Box(ephemeral, PublicKey(bytes.fromhex(CHANNEL_PUBLIC_KEY)))
        plaintext = box.decrypt(ciphertext, nonce)
        envelope = json.loads(plaintext)
        if envelope.get("protocol") != 3 or envelope.get("cnonce") != cnonce:
            raise ValueError("Authenticated protocol/nonce mismatch")
        if envelope["epoch"] < max(1, have_epoch):
            raise ValueError("Release epoch rollback refused")
        release_message = (
            f"btb-rel-v2\n{envelope['version']}\n{envelope['epoch']}\n"
            f"{envelope['content_hash']}"
        ).encode()
        VerifyKey(bytes.fromhex(RELEASE_PUBLIC_KEY)).verify(
            release_message, base64.b64decode(envelope["rel_sig"], validate=True)
        )
        if envelope.get("not_modified") is True:
            if envelope["version"] != have or envelope["version"] != envelope["content_hash"][:16]:
                raise ValueError("Unchanged response does not match the requested cache")
        else:
            source = envelope["source"].encode("utf-8")
            if hashlib.sha256(source).hexdigest() != envelope["content_hash"]:
                raise ValueError("Script SHA-256 mismatch")
            if envelope["version"] != envelope["content_hash"][:16]:
                raise ValueError("Script version/hash mismatch")
            (output / "agent.bundle.js").write_bytes(source)
        (output / "envelope.json").write_bytes(plaintext)
        summary = {key: value for key, value in envelope.items() if key != "source"}
        summary.update({
            "captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "http_status": response.status,
            "request_body_bytes": len(payload),
            "response_body_bytes": len(body),
            "seal_nonce_bytes": len(nonce),
            "seal_box_bytes": len(ciphertext),
            "plaintext_bytes": len(plaintext),
            "source_bytes": len(envelope.get("source", "").encode("utf-8")),
            "channel_authentication_verified": True,
            "release_signature_verified": True,
        })
        (output / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2))
        return summary
    finally:
        connection.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--have", default=None)
    parser.add_argument("--have-epoch", type=int, default=0)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(download(args.output, args.have, args.have_epoch), ensure_ascii=False, indent=2))
