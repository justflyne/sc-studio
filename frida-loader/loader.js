// Protocol-v3 loader. For custom Frida embedding: python3 frida-loader/build_embedded.py
import ObjCBridge from "frida-objc-bridge";
import JavaBridge from "frida-java-bridge";
import nacl from "./vendor/tweetnacl.mjs";
import { fromBase64, fromHex, sha256, toHex, utf8Decode, utf8Encode } from "./remote/RemoteCrypto.js";

const CONFIG = {
  host: "script.backtobs.xyz",
  port: 8787,
  path: "/v1/script",
  timeoutMs: 10000,
  maxResponseBytes: 8 * 1024 * 1024,
  minEpoch: 1,
  channelKey: "02135409e2a48c5f00d74fb9669ca67c69d2e2f6120ff3c47455c28d95f08439",
  releaseKey: "14c46a10259df2be9baec6300bf83047fc1f0f284615d93cfa2e1d0765b49760",
  execute: true, // false: download and verify without executing the agent.
};

function secureRandom(length) {
  const address = Module.findGlobalExportByName("arc4random_buf");
  if (address === null) throw new Error("arc4random_buf unavailable");
  const buffer = Memory.alloc(length);
  new NativeFunction(address, "void", ["pointer", "size_t"])(buffer, length);
  return new Uint8Array(buffer.readByteArray(length));
}

async function postJSON(body) {
  let connection = null;
  let expired = false;
  let timer;
  const close = async () => {
    if (connection !== null) {
      try { await connection.close(); } catch { /* already closed */ }
    }
  };
  const work = (async () => {
    connection = await Socket.connect({ family: "ipv4", host: CONFIG.host, port: CONFIG.port });
    if (expired) { await close(); throw new Error("connection arrived after timeout"); }
    const request = `POST ${CONFIG.path} HTTP/1.0\r\n` +
      `Host: ${CONFIG.host}:${CONFIG.port}\r\n` +
      "Content-Type: application/json\r\n" +
      `Content-Length: ${utf8Encode(body).length}\r\n` +
      "Connection: close\r\n\r\n" + body;
    await connection.output.writeAll(Array.from(utf8Encode(request)));
    const chunks = [];
    let total = 0;
    for (;;) {
      const chunk = new Uint8Array(await connection.input.read(65536));
      if (chunk.length === 0) break;
      total += chunk.length;
      if (total > CONFIG.maxResponseBytes) throw new Error("response exceeds 8 MiB");
      chunks.push(chunk);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const response = utf8Decode(bytes);
    const separator = response.indexOf("\r\n\r\n");
    if (separator < 0) throw new Error("malformed HTTP response");
    const header = response.slice(0, separator);
    if (!/^HTTP\/1\.[01] 200\b/.test(header)) throw new Error(header.split("\r\n")[0]);
    return JSON.parse(response.slice(separator + 4));
  })();
  const deadline = new Promise((_, reject) => {
    timer = setTimeout(() => {
      expired = true;
      void close();
      reject(new Error("script download timed out"));
    }, CONFIG.timeoutMs);
  });
  try { return await Promise.race([work, deadline]); }
  finally { clearTimeout(timer); await close(); }
}

async function downloadVerified() {
  const privateKey = secureRandom(32);
  try {
    const cnonce = toHex(secureRandom(16));
    const request = {
      protocol: 3,
      client: "btb-v59-gadget",
      platform: Process.platform,
      arch: Process.arch,
      cnonce,
      eph_pub: toHex(nacl.scalarMult.base(privateKey)),
      have: null, // Always request full source; this loader has no cache.
      have_epoch: 0,
    };
    const raw = await postJSON(JSON.stringify(request));
    if (!Number.isInteger(raw.protocol) || raw.protocol < 3) throw new Error("protocol downgrade");
    const nonce = fromBase64(raw.seal_nonce);
    const boxed = fromBase64(raw.seal_box);
    if (nonce.length !== 24 || boxed.length < 16) throw new Error("invalid sealed framing");
    const plaintext = nacl.box.open(boxed, nonce, fromHex(CONFIG.channelKey), privateKey);
    if (plaintext === null) throw new Error("crypto_box authentication failed");
    const env = JSON.parse(utf8Decode(plaintext));
    if (env.protocol !== 3 || env.cnonce !== cnonce) throw new Error("response/request mismatch");
    if (!Number.isInteger(env.epoch) || env.epoch < CONFIG.minEpoch) throw new Error("epoch below minimum");
    if (env.not_modified !== false || typeof env.source !== "string" || env.source.length === 0) {
      throw new Error("full script expected; no cache is available");
    }
    const hash = toHex(sha256(utf8Encode(env.source)));
    if (hash !== env.content_hash || env.version !== hash.slice(0, 16)) throw new Error("script hash mismatch");
    const signed = utf8Encode(`btb-rel-v2\n${env.version}\n${env.epoch}\n${env.content_hash}`);
    if (!nacl.sign.detached.verify(signed, fromBase64(env.rel_sig), fromHex(CONFIG.releaseKey))) {
      throw new Error("release signature invalid");
    }
    return env;
  } finally { privateKey.fill(0); }
}

async function startLoader(stage) {
  try {
    console.log(`[loader] init(${stage}); requesting ${CONFIG.host}:${CONFIG.port}${CONFIG.path}`);
    const env = await downloadVerified();
    console.log(`[loader] verified ${env.version}, epoch ${env.epoch}, ${utf8Encode(env.source).length} bytes`);
    if (CONFIG.execute) {
      try {
        new Function("ObjC", "Java", env.source)(ObjCBridge, JavaBridge);
        const agentInit = rpc.exports.init;
        if (typeof agentInit !== "function" || agentInit === initLoader) {
          throw new Error("agent has no init export");
        }
        await agentInit("remote");
      } finally {
        // Keep Gadget's lifecycle entry idempotent, preserving other agent RPCs.
        rpc.exports.init = initLoader;
      }
      console.log("[loader] agent executed and initialized");
    }
    const result = { type: "loader-ready", version: env.version, epoch: env.epoch, executed: CONFIG.execute };
    send(result);
    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[loader] ${message}`);
    const result = { type: "loader-error", message };
    send(result);
    return result;
  }
}

let initialization = null;
function initLoader(stage, parameters = {}) {
  if (initialization === null) {
    if (typeof parameters.execute === "boolean") CONFIG.execute = parameters.execute;
    initialization = startLoader(stage);
  }
  return initialization;
}

// Gadget waits for this Promise before returning from its library constructor.
// A controller using the Python API should call script.exports_sync.init("early", {}).
rpc.exports.init = initLoader;
