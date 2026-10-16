import ObjCBridge from "frida-objc-bridge";
import JavaBridge from "frida-java-bridge";
import nacl from "./vendor/tweetnacl.mjs";
import { RemoteConfig } from "./remote/RemoteConfig.js";
import { verifyEd25519 } from "./remote/Ed25519.js";
import { fromBase64, fromHex, hmacSha256, rc4Drop3072, sha256, toHex, utf8Decode, utf8Encode } from "./remote/RemoteCrypto.js";
// error.message only — never error.stack. Reading .stack makes frida build a
// backtrace and resolve it through the script's source map; in the gadget
// runtime that path calls JS_NewString(NULL) and segfaults. We also compile the
// bootstrap with -S (no source maps) so the resolver has nothing to chew on,
// but keeping .stack out of the hot path is the belt to that suspenders.
function describe(error) {
    if (error instanceof Error)
        return error.message;
    return String(error);
}
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}
function nowSec() {
    return Math.floor(Date.now() / 1000);
}
function withTimeout(work, ms, label) {
    return Promise.race([
        work,
        delay(ms).then(() => { throw new Error(`${label} timeout`); })
    ]);
}
// ── best-effort observability ───────────────────────────────────────────────
// The bootstrap runs before the agent, so it has no RemoteLog. A fire-and-forget
// GET /log surfaces cache decisions off-device without blocking the launch.
function beacon(message) {
    try {
        Socket.connect({ family: "ipv4", host: RemoteConfig.host, port: RemoteConfig.port, tls: RemoteConfig.tls })
            .then(async (connection) => {
            const request = `GET /log?m=${encodeURIComponent(`[bootstrap] ${message}`)} HTTP/1.0\r\n` +
                `Host: ${RemoteConfig.host}:${RemoteConfig.port}\r\n` +
                "Connection: close\r\n\r\n";
            await connection.output.writeAll(Array.from(utf8Encode(request)));
            await connection.close();
        })
            .catch(() => { });
    }
    catch { /* ignore */ }
}
function note(message) {
    console.log(`[bootstrap] ${message}`);
    beacon(message);
}
// ── native + file helpers (all best-effort; a failure disables the cache) ─────
function tryNativeFunction(name, ret, args) {
    try {
        const address = Module.findGlobalExportByName(name);
        return address === null ? null : new NativeFunction(address, ret, args);
    }
    catch {
        return null;
    }
}
let _mkdir;
let _rename;
let _arc4;
function arc4() {
    if (_arc4 === undefined)
        _arc4 = tryNativeFunction("arc4random_buf", "void", ["pointer", "size_t"]);
    return _arc4;
}
function randomBytes(length) {
    const fn = arc4();
    if (fn !== null) {
        try {
            const buffer = Memory.alloc(length);
            fn(buffer, length);
            return new Uint8Array(buffer.readByteArray(length));
        }
        catch { /* fall through */ }
    }
    // Weak fallback: acceptable for a cnonce / cache tmp suffix, NEVER for a key.
    const out = new Uint8Array(length);
    let seed = Date.now() >>> 0;
    for (let index = 0; index < length; index++) {
        seed = (seed * 1103515245 + 12345) >>> 0;
        out[index] = (seed >>> 16) & 0xff;
    }
    return out;
}
// Key-agreement randomness must be real: if arc4random is unavailable we FAIL
// CLOSED rather than derive an X25519 private key from the Date-seeded LCG (a
// predictable ephemeral would collapse the whole sealed channel). (F2)
function secureRandomBytes(length) {
    const fn = arc4();
    if (fn === null)
        throw new Error("no secure RNG (arc4random_buf) for key agreement");
    const buffer = Memory.alloc(length);
    fn(buffer, length);
    return new Uint8Array(buffer.readByteArray(length));
}
// Fresh per-request X25519 ephemeral. Derives the public with scalarMult.base so
// tweetnacl's stripped PRNG (verify-only vendor) is never touched. (F2/F4)
function newEphemeral() {
    const priv = secureRandomBytes(32); // X25519 clamps internally; no pre-clamp
    const pub = nacl.scalarMult.base(priv);
    return { priv, pub };
}
function toArrayBuffer(bytes) {
    const out = new ArrayBuffer(bytes.length);
    new Uint8Array(out).set(bytes);
    return out;
}
function fileApiReady() {
    return typeof File !== "undefined"
        && typeof File.readAllBytes === "function"
        && typeof File.writeAllBytes === "function";
}
function readBytes(path) {
    try {
        return new Uint8Array(File.readAllBytes(path));
    }
    catch {
        return null;
    }
}
function mkdirp(path) {
    if (_mkdir === undefined)
        _mkdir = tryNativeFunction("mkdir", "int", ["pointer", "uint"]);
    if (_mkdir === null)
        return;
    const parts = path.split("/");
    let built = "";
    for (const part of parts) {
        if (part.length === 0) {
            built = "";
            continue;
        }
        built += "/" + part;
        try {
            _mkdir(Memory.allocUtf8String(built), 0o700);
        }
        catch { /* EEXIST etc. */ }
    }
}
function writeAtomic(path, bytes) {
    if (_rename === undefined)
        _rename = tryNativeFunction("rename", "int", ["pointer", "pointer"]);
    const tmp = `${path}.tmp.${toHex(randomBytes(4))}`;
    try {
        File.writeAllBytes(tmp, toArrayBuffer(bytes));
        if (_rename !== null) {
            const rc = _rename(Memory.allocUtf8String(tmp), Memory.allocUtf8String(path));
            if (rc === 0)
                return true;
        }
        // No rename available: fall back to a direct (non-atomic) write.
        File.writeAllBytes(path, toArrayBuffer(bytes));
        return true;
    }
    catch {
        return false;
    }
}
function resolveDirs() {
    if (!fileApiReady())
        return null;
    try {
        const sub = RemoteConfig.cacheSubdir;
        if (Process.platform === "darwin") {
            const fm = ObjCBridge.classes.NSFileManager.defaultManager();
            const dir = (domain) => fm.URLsForDirectory_inDomains_(domain, 1).objectAtIndex_(0).path().toString();
            const caches = dir(13); // NSCachesDirectory
            const support = dir(14); // NSApplicationSupportDirectory
            const dirs = { cacheDir: `${caches}/${sub}`, stateDir: `${support}/${sub}` };
            mkdirp(dirs.cacheDir);
            mkdirp(dirs.stateDir);
            return dirs;
        }
        // Android: derive the package from the process cmdline.
        const cmd = readBytes("/proc/self/cmdline");
        if (cmd === null || cmd.length === 0)
            return null;
        const pkg = utf8Decode(cmd).split("\0")[0].split(":")[0].trim();
        if (pkg.length === 0)
            return null;
        const dirs = {
            cacheDir: `/data/data/${pkg}/cache/${sub}`,
            stateDir: `/data/data/${pkg}/files/${sub}`
        };
        mkdirp(dirs.cacheDir);
        mkdirp(dirs.stateDir);
        return dirs;
    }
    catch (error) {
        console.log(`[bootstrap] cache dirs unavailable: ${describe(error)}`);
        return null;
    }
}
// ── release signature (offline Ed25519, unchanged) ───────────────────────────
function relMessage(version, epoch, contentHash) {
    return utf8Encode(`btb-rel-v2\n${version}\n${epoch}\n${contentHash}`);
}
function relSigOk(version, epoch, contentHash, relSigB64) {
    if (RemoteConfig.pubKeyHex.length === 0)
        return true; // dev: signing disabled
    try {
        return verifyEd25519(fromHex(RemoteConfig.pubKeyHex), relMessage(version, epoch, contentHash), fromBase64(relSigB64));
    }
    catch {
        return false;
    }
}
// ── epoch high-water (anti-rollback) ─────────────────────────────────────────
function readHighWater(dirs) {
    const bytes = readBytes(`${dirs.stateDir}/${RemoteConfig.highWaterFile}`);
    if (bytes === null)
        return 0;
    const value = Number.parseInt(utf8Decode(bytes).trim(), 10);
    return Number.isFinite(value) && value > 0 ? value : 0;
}
function writeHighWater(dirs, epoch) {
    if (epoch <= readHighWater(dirs))
        return;
    writeAtomic(`${dirs.stateDir}/${RemoteConfig.highWaterFile}`, utf8Encode(String(epoch)));
}
// ── on-device cache (encrypted at rest with the demoted master key) ──────────
function readCache(dirs) {
    try {
        const metaBytes = readBytes(`${dirs.cacheDir}/${RemoteConfig.metaFile}`);
        const body = readBytes(`${dirs.cacheDir}/${RemoteConfig.cacheFile}`);
        if (metaBytes === null || body === null)
            return null;
        const meta = JSON.parse(utf8Decode(metaBytes));
        const version = String(meta.version ?? "");
        const epoch = Number(meta.epoch ?? 0);
        const contentHash = String(meta.content_hash ?? "");
        const relSig = String(meta.rel_sig ?? "");
        const nonce = String(meta.nonce ?? "");
        if (version.length === 0 || contentHash.length === 0 || nonce.length === 0)
            return null;
        // The body is stored ENCRYPTED. Decrypt, then bind the plaintext to the
        // signed content hash and the offline release signature: a tampered .enc
        // decrypts to bytes whose hash will not match, and a swapped-in agent
        // will not carry a valid rel_sig, so neither can be run.
        const encryptionKey = hmacSha256(fromHex(RemoteConfig.keyHex), utf8Encode(`enc:${nonce}`));
        const plaintext = rc4Drop3072(body, encryptionKey);
        if (toHex(sha256(plaintext)) !== contentHash)
            return null;
        if (version !== contentHash.slice(0, 16))
            return null;
        if (!relSigOk(version, epoch, contentHash, relSig))
            return null;
        return {
            version, epoch, content_hash: contentHash, rel_sig: relSig, nonce,
            source: utf8Decode(plaintext),
            issued_at_seen: Number(meta.issued_at_seen ?? 0),
            max_age: Number(meta.max_age ?? RemoteConfig.maxOfflineAgeSec)
        };
    }
    catch {
        return null;
    }
}
function writeCacheMeta(dirs, fields) {
    return writeAtomic(`${dirs.cacheDir}/${RemoteConfig.metaFile}`, utf8Encode(JSON.stringify({ ...fields, issued_at_seen: nowSec() })));
}
// The wire no longer carries RC4 (v3 seals the whole response), so the client
// re-encrypts the plaintext locally with a fresh nonce before it ever hits disk.
function writeCacheEncrypted(dirs, env, source) {
    const localNonce = toHex(randomBytes(16));
    const encKey = hmacSha256(fromHex(RemoteConfig.keyHex), utf8Encode(`enc:${localNonce}`));
    const ciphertext = rc4Drop3072(utf8Encode(source), encKey);
    const okBody = writeAtomic(`${dirs.cacheDir}/${RemoteConfig.cacheFile}`, ciphertext);
    const okMeta = writeCacheMeta(dirs, {
        version: env.version, epoch: env.epoch, content_hash: env.content_hash,
        rel_sig: env.rel_sig, nonce: localNonce, max_age: env.max_age ?? RemoteConfig.maxOfflineAgeSec
    });
    if (okBody && okMeta)
        console.log(`[bootstrap] cached agent ${env.version} (epoch ${env.epoch}, encrypted)`);
}
// not_modified: the body is unchanged; only advance the offline freshness window
// (and carry the server's fresh epoch/max_age), reusing the stored nonce.
function refreshCacheMeta(dirs, env, cache) {
    writeCacheMeta(dirs, {
        version: env.version, epoch: env.epoch, content_hash: env.content_hash,
        rel_sig: env.rel_sig, nonce: cache.nonce, max_age: env.max_age ?? cache.max_age
    });
}
function cacheStillFresh(cache) {
    if (cache.issued_at_seen <= 0)
        return false;
    const ttl = Math.min(cache.max_age > 0 ? cache.max_age : RemoteConfig.maxOfflineAgeSec, RemoteConfig.maxOfflineAgeSec);
    return nowSec() - cache.issued_at_seen <= ttl;
}
// ── HTTP ─────────────────────────────────────────────────────────────────────
const MAX_RESPONSE = 8 * 1024 * 1024; // agent ~587KB, sealed+base64 ~0.8MB; cap well above
async function readResponse(connection) {
    const blocks = [];
    let total = 0;
    while (true) {
        const block = new Uint8Array(await connection.input.read(64 * 1024));
        if (block.length === 0)
            break;
        total += block.length;
        if (total > MAX_RESPONSE)
            throw new Error("response too large"); // (#9)
        blocks.push(block);
    }
    const all = new Uint8Array(total);
    let offset = 0;
    for (const block of blocks) {
        all.set(block, offset);
        offset += block.length;
    }
    const response = utf8Decode(all);
    const separator = response.indexOf("\r\n\r\n");
    if (separator < 0)
        throw new Error("invalid HTTP response");
    const header = response.slice(0, separator);
    const body = response.slice(separator + 4);
    if (!/^HTTP\/1\.[01] 200\b/.test(header)) {
        let reason = body;
        try {
            const parsed = JSON.parse(body);
            reason = parsed.error ?? body;
        }
        catch { /* keep raw body */ }
        throw new Error(`script server rejected request: ${reason || header.split("\r\n")[0]}`);
    }
    return body;
}
// Open the sealed response. box.open returns null on a Poly1305 mismatch and
// THROWS on a malformed nonce/box length — both are routed to the same "auth
// failed" so callers fall back to the offline cache, never to a naked resume. (F3)
function openSealed(raw, ephPriv, cnonce) {
    const nonce = fromBase64(raw.seal_nonce);
    const boxed = fromBase64(raw.seal_box);
    if (nonce.length !== 24 || boxed.length < 16)
        throw new Error("sealed channel: bad framing");
    let opened;
    try {
        opened = nacl.box.open(boxed, nonce, fromHex(RemoteConfig.channelPubKeyHex), ephPriv);
    }
    catch {
        throw new Error("sealed channel: open error");
    }
    if (opened === null)
        throw new Error("sealed channel: authentication failed");
    const inner = JSON.parse(utf8Decode(opened));
    if (inner.protocol !== 3)
        throw new Error(`sealed inner protocol ${inner.protocol}`);
    if (inner.cnonce !== cnonce)
        throw new Error("sealed inner cnonce mismatch");
    return inner;
}
async function download(host, cnonce, haveVersion, haveEpoch) {
    const eph = newEphemeral(); // per-host ephemeral (F4); throws if no secure RNG (F2)
    const connection = await withTimeout(Socket.connect({ family: "ipv4", host, port: RemoteConfig.port, tls: RemoteConfig.tls }), RemoteConfig.connectTimeoutMs, `connect ${host}`);
    try {
        const body = JSON.stringify({
            protocol: RemoteConfig.protocol,
            client: "btb-v59-gadget",
            platform: Process.platform,
            arch: Process.arch,
            cnonce,
            eph_pub: toHex(eph.pub),
            have: haveVersion,
            have_epoch: haveEpoch
        });
        const request = `POST ${RemoteConfig.path} HTTP/1.0\r\n` +
            `Host: ${host}:${RemoteConfig.port}\r\n` +
            "Content-Type: application/json\r\n" +
            `Content-Length: ${utf8Encode(body).length}\r\n` +
            "Connection: close\r\n\r\n" + body;
        await connection.output.writeAll(Array.from(utf8Encode(request)));
        const raw = JSON.parse(await readResponse(connection));
        // Downgrade guard: the client speaks ONLY v3 — refuse anything a MITM
        // tries to answer as a lower (forgeable) protocol, before opening. (F7)
        if (typeof raw.protocol !== "number" || raw.protocol < 3) {
            throw new Error(`downgrade refused (protocol ${raw.protocol})`);
        }
        return openSealed(raw, eph.priv, cnonce);
    }
    finally {
        await connection.close();
        eph.priv.fill(0);
    }
}
async function fetchEnvelope(cnonce, haveVersion, haveEpoch) {
    let lastError = new Error("no hosts configured");
    for (const host of RemoteConfig.hosts) {
        try {
            console.log(`[bootstrap] fetching agent from ${host}:${RemoteConfig.port}`);
            return await download(host, cnonce, haveVersion, haveEpoch);
        }
        catch (error) {
            lastError = error;
            console.log(`[bootstrap] ${host} failed: ${describe(error)}`);
        }
    }
    throw new Error(`all hosts failed: ${describe(lastError)}`);
}
// ── verification (inner is already authenticated by Poly1305 + cnonce bound) ──
function verifyInner(env, minEpoch) {
    if (!(env.epoch >= minEpoch))
        throw new Error(`epoch rollback rejected (${env.epoch} < ${minEpoch})`);
    if (!relSigOk(env.version, env.epoch, env.content_hash, env.rel_sig)) {
        throw new Error("release signature invalid");
    }
    // Freshness is defense-in-depth only: replay is already blocked by the fresh
    // per-request ephemeral (a stale box won't open under a new eph key) and the
    // authenticated cnonce echo. So a skewed device clock must NOT brick the
    // launch (#8) — log and proceed rather than hard-fail.
    if (Math.abs(nowSec() - env.issued_at) > 300) {
        note(`clock skew (issued_at ${env.issued_at}, now ${nowSec()}) — accepting`);
    }
}
function fullSource(env) {
    if (typeof env.source !== "string" || env.source.length === 0)
        throw new Error("full response missing source");
    if (toHex(sha256(utf8Encode(env.source))) !== env.content_hash)
        throw new Error("agent does not match content hash");
    if (env.version !== env.content_hash.slice(0, 16))
        throw new Error("version/content_hash mismatch");
    return env.source;
}
// ── run ──────────────────────────────────────────────────────────────────────
let resumed = false;
function runAgent(source, label) {
    if (resumed) {
        note(`load-wait already over — not starting agent ${label}`);
        return;
    }
    const execute = new Function("ObjC", "Java", source);
    execute(ObjCBridge, JavaBridge);
    const init = rpc.exports.init;
    if (typeof init !== "function")
        throw new Error("remote agent has no init export");
    init("remote");
    note(`agent ${label} loaded`);
}
// Runs after the app has already resumed with the cached agent active. Confirms
// with the server and, if a newer agent exists, caches it for the NEXT launch —
// it never re-runs the agent this session, so it cannot disturb the running game.
async function backgroundRefresh(dirs, cache, minEpoch, cnonce) {
    let env;
    try {
        env = await withTimeout(fetchEnvelope(cnonce, cache.version, cache.epoch), RemoteConfig.networkBudgetMs, "network budget");
    }
    catch (error) {
        note(`offline — kept cache ${cache.version} (${describe(error)})`);
        return;
    }
    verifyInner(env, minEpoch);
    if (env.not_modified === true) {
        // Bind not_modified to the cache we actually hold (F1): a MITM setting
        // have=<current> cannot make us "confirm" a version we do not have.
        if (env.content_hash !== cache.content_hash || env.version !== cache.version) {
            note(`not_modified mismatch — ignoring`);
            return;
        }
        refreshCacheMeta(dirs, env, cache);
        writeHighWater(dirs, env.epoch);
        note(`up to date (${env.version})`);
        return;
    }
    writeCacheEncrypted(dirs, env, fullSource(env));
    writeHighWater(dirs, env.epoch);
    note(`update ${env.version} (epoch ${env.epoch}) cached — active next launch`);
}
async function start() {
    const dirs = resolveDirs();
    const cache = dirs !== null ? readCache(dirs) : null;
    const highWater = dirs !== null ? readHighWater(dirs) : 0;
    const floor = Math.max(RemoteConfig.minEpoch, highWater);
    const minEpoch = Math.max(floor, cache?.epoch ?? 0);
    const cnonce = toHex(randomBytes(16));
    // Fast path (instant relaunch): a cached agent is one we already downloaded
    // and verified. If it is within its offline window and at/above the rollback
    // floor, run it right away — hooks install before the game's first connect
    // and the launch never waits on the network — then confirm in the background.
    if (dirs !== null && cache !== null && cache.epoch >= floor && cacheStillFresh(cache)) {
        const d = dirs, c = cache;
        note(`cache hit ${c.version} (epoch ${c.epoch}) — running now, checking server in background`);
        runAgent(c.source, `${c.version} (cache)`);
        setTimeout(() => {
            backgroundRefresh(d, c, minEpoch, cnonce).catch(error => note(`bg refresh failed: ${describe(error)}`));
        }, 0);
        return;
    }
    // No usable cache (first launch / purged / expired / rolled-back): block on
    // the download. A failure ANYWHERE in fetch/open/verify falls back to a valid
    // cache if we have one, else resumes without an agent. (F5 — guard + open +
    // verify all sit inside this catch, unlike the old dead branch.)
    let env;
    try {
        env = await withTimeout(fetchEnvelope(cnonce, cache?.version ?? null, cache?.epoch ?? 0), RemoteConfig.networkBudgetMs, "network budget");
        verifyInner(env, minEpoch);
    }
    catch (error) {
        if (cache !== null && cache.epoch >= floor && cacheStillFresh(cache)) {
            note(`sealed fetch failed (${describe(error)}) — running cached agent ${cache.version}`);
            runAgent(cache.source, `${cache.version} (cache, offline)`);
            return;
        }
        throw error;
    }
    if (env.not_modified === true) {
        if (cache === null || env.content_hash !== cache.content_hash || env.version !== cache.version) {
            throw new Error("not_modified but no matching cache");
        }
        const cached = cache;
        note(`server unchanged (${env.version}) — running cache`);
        runAgent(cached.source, `${env.version} (cache)`);
        if (dirs !== null) {
            setTimeout(() => { refreshCacheMeta(dirs, env, cached); writeHighWater(dirs, env.epoch); }, 0);
        }
        return;
    }
    const source = fullSource(env);
    note(`downloaded agent ${env.version} (epoch ${env.epoch})`);
    runAgent(source, `${env.version} (fresh)`);
    if (dirs !== null) {
        setTimeout(() => { writeCacheEncrypted(dirs, env, source); writeHighWater(dirs, env.epoch); }, 0);
    }
}
// Block the app at load until the agent is downloaded (or restored from cache)
// AND its hooks are installed. The gadget keeps the app suspended
// (can_block_at_load_time) until this module's top-level await settles, then
// calls resume(). Without this the game's first connect races ahead of the
// server-redirect hook and reaches the original server. The outer cap makes an
// unreachable server (with no usable cache) resume the launch instead of
// bricking it; `resumed` then stops a late agent from initialising post-resume.
await Promise.race([
    start().catch(error => note(`failed: ${describe(error)}`)),
    delay(10000).then(() => { resumed = true; console.error("[bootstrap] load-wait timed out; resuming without agent"); })
]);
