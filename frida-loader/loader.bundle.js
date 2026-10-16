📦
6507 /src/loader.js
3818 /node_modules/@frida/base64-js/index.js
↻ base64-js
55789 /node_modules/@frida/buffer/index.js
↻ buffer
2221 /node_modules/@frida/ieee754/index.js
↻ ieee754
15603 /node_modules/frida-java-bridge/index.js
↻ frida-java-bridge
1957 /node_modules/frida-java-bridge/lib/alloc.js
163089 /node_modules/frida-java-bridge/lib/android.js
241 /node_modules/frida-java-bridge/lib/api.js
60957 /node_modules/frida-java-bridge/lib/class-factory.js
38237 /node_modules/frida-java-bridge/lib/class-model.js
33908 /node_modules/frida-java-bridge/lib/env.js
33765 /node_modules/frida-java-bridge/lib/jvm.js
2038 /node_modules/frida-java-bridge/lib/jvmti.js
963 /node_modules/frida-java-bridge/lib/lru.js
364 /node_modules/frida-java-bridge/lib/machine-code.js
227 /node_modules/frida-java-bridge/lib/memoize.js
26623 /node_modules/frida-java-bridge/lib/mkdex.js
157 /node_modules/frida-java-bridge/lib/result.js
18114 /node_modules/frida-java-bridge/lib/types.js
4360 /node_modules/frida-java-bridge/lib/vm.js
95068 /node_modules/frida-objc-bridge/index.js
↻ frida-objc-bridge
6949 /node_modules/frida-objc-bridge/lib/api.js
7556 /node_modules/frida-objc-bridge/lib/fastpaths.js
1736 /src/remote/Ed25519.js
4329 /src/remote/RemoteConfig.js
7668 /src/remote/RemoteCrypto.js
26 /src/remote/env.js
73661 /src/vendor/tweetnacl.mjs
✄
// Basic protocol-v3 loader. Build with: python3 frida-loader/build.py
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

✄
const lookup = []
const revLookup = []

const code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (let i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  const len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  let validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  const placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
export function byteLength (b64) {
  const lens = getLens(b64)
  const validLen = lens[0]
  const placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

export function toByteArray (b64) {
  const lens = getLens(b64)
  const validLen = lens[0]
  const placeHoldersLen = lens[1]

  const arr = new Uint8Array(_byteLength(b64, validLen, placeHoldersLen))

  let curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  const len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  let i
  for (i = 0; i < len; i += 4) {
    const tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    const tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    const tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  const output = []
  for (let i = start; i < end; i += 3) {
    const tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

export function fromByteArray (uint8) {
  const len = uint8.length
  const extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  const parts = []
  const maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (let i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    const tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    const tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}

✄
/*!
 * The buffer module from node.js, for Frida.
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */

import * as base64 from 'base64-js'
import * as ieee754 from 'ieee754'

export const config = {
  INSPECT_MAX_BYTES: 50
}

const K_MAX_LENGTH = 0x7fffffff
export { K_MAX_LENGTH as kMaxLength }

Buffer.TYPED_ARRAY_SUPPORT = true

Object.defineProperty(Buffer.prototype, 'parent', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.buffer
  }
})

Object.defineProperty(Buffer.prototype, 'offset', {
  enumerable: true,
  get: function () {
    if (!Buffer.isBuffer(this)) return undefined
    return this.byteOffset
  }
})

function createBuffer (length) {
  if (length > K_MAX_LENGTH) {
    throw new RangeError('The value "' + length + '" is invalid for option "size"')
  }
  // Return an augmented `Uint8Array` instance
  const buf = new Uint8Array(length)
  Object.setPrototypeOf(buf, Buffer.prototype)
  return buf
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

export function Buffer (arg, encodingOrOffset, length) {
  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new TypeError(
        'The "string" argument must be of type string. Received type number'
      )
    }
    return allocUnsafe(arg)
  }
  return from(arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

function from (value, encodingOrOffset, length) {
  if (typeof value === 'string') {
    return fromString(value, encodingOrOffset)
  }

  if (ArrayBuffer.isView(value)) {
    return fromArrayView(value)
  }

  if (value == null) {
    throw new TypeError(
      'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
      'or Array-like Object. Received type ' + (typeof value)
    )
  }

  if (value instanceof ArrayBuffer ||
      (value && value.buffer instanceof ArrayBuffer)) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (value instanceof SharedArrayBuffer ||
      (value && value.buffer instanceof SharedArrayBuffer)) {
    return fromArrayBuffer(value, encodingOrOffset, length)
  }

  if (typeof value === 'number') {
    throw new TypeError(
      'The "value" argument must not be of type number. Received type number'
    )
  }

  const valueOf = value.valueOf && value.valueOf()
  if (valueOf != null && valueOf !== value) {
    return Buffer.from(valueOf, encodingOrOffset, length)
  }

  const b = fromObject(value)
  if (b) return b

  if (typeof Symbol !== 'undefined' && Symbol.toPrimitive != null &&
      typeof value[Symbol.toPrimitive] === 'function') {
    return Buffer.from(value[Symbol.toPrimitive]('string'), encodingOrOffset, length)
  }

  throw new TypeError(
    'The first argument must be one of type string, Buffer, ArrayBuffer, Array, ' +
    'or Array-like Object. Received type ' + (typeof value)
  )
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(value, encodingOrOffset, length)
}

// Note: Change prototype *after* Buffer.from is defined to workaround Chrome bug:
// https://github.com/feross/buffer/pull/148
Object.setPrototypeOf(Buffer.prototype, Uint8Array.prototype)
Object.setPrototypeOf(Buffer, Uint8Array)

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be of type number')
  } else if (size < 0) {
    throw new RangeError('The value "' + size + '" is invalid for option "size"')
  }
}

function alloc (size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpreted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(size).fill(fill, encoding)
      : createBuffer(size).fill(fill)
  }
  return createBuffer(size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(size, fill, encoding)
}

function allocUnsafe (size) {
  assertSize(size)
  return createBuffer(size < 0 ? 0 : checked(size) | 0)
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(size)
}

function fromString (string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('Unknown encoding: ' + encoding)
  }

  const length = byteLength(string, encoding) | 0
  let buf = createBuffer(length)

  const actual = buf.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    buf = buf.slice(0, actual)
  }

  return buf
}

function fromArrayLike (array) {
  const length = array.length < 0 ? 0 : checked(array.length) | 0
  const buf = createBuffer(length)
  for (let i = 0; i < length; i += 1) {
    buf[i] = array[i] & 255
  }
  return buf
}

function fromArrayView (arrayView) {
  if (arrayView instanceof Uint8Array) {
    const copy = new Uint8Array(arrayView)
    return fromArrayBuffer(copy.buffer, copy.byteOffset, copy.byteLength)
  }
  return fromArrayLike(arrayView)
}

function fromArrayBuffer (array, byteOffset, length) {
  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('"offset" is outside of buffer bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('"length" is outside of buffer bounds')
  }

  let buf
  if (byteOffset === undefined && length === undefined) {
    buf = new Uint8Array(array)
  } else if (length === undefined) {
    buf = new Uint8Array(array, byteOffset)
  } else {
    buf = new Uint8Array(array, byteOffset, length)
  }

  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(buf, Buffer.prototype)

  return buf
}

function fromObject (obj) {
  if (Buffer.isBuffer(obj)) {
    const len = checked(obj.length) | 0
    const buf = createBuffer(len)

    if (buf.length === 0) {
      return buf
    }

    obj.copy(buf, 0, 0, len)
    return buf
  }

  if (obj.length !== undefined) {
    if (typeof obj.length !== 'number' || Number.isNaN(obj.length)) {
      return createBuffer(0)
    }
    return fromArrayLike(obj)
  }

  if (obj.type === 'Buffer' && Array.isArray(obj.data)) {
    return fromArrayLike(obj.data)
  }
}

function checked (length) {
  // Note: cannot use `length < K_MAX_LENGTH` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= K_MAX_LENGTH) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + K_MAX_LENGTH.toString(16) + ' bytes')
  }
  return length | 0
}

export function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return b != null && b._isBuffer === true &&
    b !== Buffer.prototype // so Buffer.isBuffer(Buffer.prototype) will be false
}

Buffer.compare = function compare (a, b) {
  if (a instanceof Uint8Array) a = Buffer.from(a, a.offset, a.byteLength)
  if (b instanceof Uint8Array) b = Buffer.from(b, b.offset, b.byteLength)
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError(
      'The "buf1", "buf2" arguments must be one of type Buffer or Uint8Array'
    )
  }

  if (a === b) return 0

  let x = a.length
  let y = b.length

  for (let i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!Array.isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  let i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  const buffer = Buffer.allocUnsafe(length)
  let pos = 0
  for (i = 0; i < list.length; ++i) {
    let buf = list[i]
    if (buf instanceof Uint8Array) {
      if (pos + buf.length > buffer.length) {
        if (!Buffer.isBuffer(buf)) {
          buf = Buffer.from(buf.buffer, buf.byteOffset, buf.byteLength)
        }
        buf.copy(buffer, pos)
      } else {
        Uint8Array.prototype.set.call(
          buffer,
          buf,
          pos
        )
      }
    } else if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    } else {
      buf.copy(buffer, pos)
    }
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (ArrayBuffer.isView(string) || string instanceof ArrayBuffer) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    throw new TypeError(
      'The "string" argument must be one of type string, Buffer, or ArrayBuffer. ' +
      'Received type ' + typeof string
    )
  }

  const len = string.length
  const mustMatch = (arguments.length > 2 && arguments[2] === true)
  if (!mustMatch && len === 0) return 0

  // Use a for loop to avoid recursion
  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) {
          return mustMatch ? -1 : utf8ToBytes(string).length // assume utf8
        }
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  let loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coercion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// This property is used by `Buffer.isBuffer` (and the `is-buffer` npm package)
// to detect a Buffer instance. It's not possible to use `instanceof Buffer`
// reliably in a frida-compile context because there could be multiple different
// copies of the 'buffer' package in use. This method works even for Buffer
// instances that were created from another copy of the `buffer` package.
// See: https://github.com/feross/buffer/issues/154
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  const i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  const len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (let i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  const len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (let i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  const len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (let i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  const length = this.length
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.toLocaleString = Buffer.prototype.toString

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  let str = ''
  const max = config.INSPECT_MAX_BYTES
  str = this.toString('hex', 0, max).replace(/(.{2})/g, '$1 ').trim()
  if (this.length > max) str += ' ... '
  return '<Buffer ' + str + '>'
}
Buffer.prototype[Symbol.for('nodejs.util.inspect.custom')] = Buffer.prototype.inspect

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (target instanceof Uint8Array) {
    target = Buffer.from(target, target.offset, target.byteLength)
  }
  if (!Buffer.isBuffer(target)) {
    throw new TypeError(
      'The "target" argument must be one of type Buffer or Uint8Array. ' +
      'Received type ' + (typeof target)
    )
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  let x = thisEnd - thisStart
  let y = end - start
  const len = Math.min(x, y)

  const thisCopy = this.slice(thisStart, thisEnd)
  const targetCopy = target.slice(start, end)

  for (let i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset // Coerce to Number.
  if (Number.isNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [val], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  let indexSize = 1
  let arrLength = arr.length
  let valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  let i
  if (dir) {
    let foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      let found = true
      for (let j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  const remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  const strLen = string.length

  if (length > strLen / 2) {
    length = strLen / 2
  }
  let i
  for (i = 0; i < length; ++i) {
    const parsed = parseInt(string.substr(i * 2, 2), 16)
    if (Number.isNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset >>> 0
    if (isFinite(length)) {
      length = length >>> 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  const remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  let loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
      case 'latin1':
      case 'binary':
        return asciiWrite(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  const res = []

  let i = start
  while (i < end) {
    const firstByte = buf[i]
    let codePoint = null
    let bytesPerSequence = (firstByte > 0xEF)
      ? 4
      : (firstByte > 0xDF)
          ? 3
          : (firstByte > 0xBF)
              ? 2
              : 1

    if (i + bytesPerSequence <= end) {
      let secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
const MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  const len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  let res = ''
  let i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  let ret = ''
  end = Math.min(buf.length, end)

  for (let i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  const len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  let out = ''
  for (let i = start; i < end; ++i) {
    out += hexSliceLookupTable[buf[i]]
  }
  return out
}

function utf16leSlice (buf, start, end) {
  const bytes = buf.slice(start, end)
  let res = ''
  // If bytes.length is odd, the last 8 bits must be ignored (same as node.js)
  for (let i = 0; i < bytes.length - 1; i += 2) {
    res += String.fromCharCode(bytes[i] + (bytes[i + 1] * 256))
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  const len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  const newBuf = this.subarray(start, end)
  // Return an augmented `Uint8Array` instance
  Object.setPrototypeOf(newBuf, Buffer.prototype)

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUintLE =
Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUintBE =
Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  let val = this[offset + --byteLength]
  let mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUint8 =
Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUint16LE =
Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUint16BE =
Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUint32LE =
Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUint32BE =
Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readBigUInt64LE = function readBigUInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const lo = first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24

  const hi = this[++offset] +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    last * 2 ** 24

  return BigInt(lo) + (BigInt(hi) << BigInt(32))
}

Buffer.prototype.readBigUInt64BE = function readBigUInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const hi = first * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  const lo = this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last

  return (BigInt(hi) << BigInt(32)) + BigInt(lo)
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let val = this[offset]
  let mul = 1
  let i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  let i = byteLength
  let mul = 1
  let val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 2, this.length)
  const val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readBigInt64LE = function readBigInt64LE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = this[offset + 4] +
    this[offset + 5] * 2 ** 8 +
    this[offset + 6] * 2 ** 16 +
    (last << 24) // Overflow

  return (BigInt(val) << BigInt(32)) +
    BigInt(first +
    this[++offset] * 2 ** 8 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 24)
}

Buffer.prototype.readBigInt64BE = function readBigInt64BE (offset) {
  offset = offset >>> 0
  validateNumber(offset, 'offset')
  const first = this[offset]
  const last = this[offset + 7]
  if (first === undefined || last === undefined) {
    boundsError(offset, this.length - 8)
  }

  const val = (first << 24) + // Overflow
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    this[++offset]

  return (BigInt(val) << BigInt(32)) +
    BigInt(this[++offset] * 2 ** 24 +
    this[++offset] * 2 ** 16 +
    this[++offset] * 2 ** 8 +
    last)
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  offset = offset >>> 0
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUintLE =
Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let mul = 1
  let i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUintBE =
Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  byteLength = byteLength >>> 0
  if (!noAssert) {
    const maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  let i = byteLength - 1
  let mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUint8 =
Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeUint16LE =
Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeUint16BE =
Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeUint32LE =
Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset + 3] = (value >>> 24)
  this[offset + 2] = (value >>> 16)
  this[offset + 1] = (value >>> 8)
  this[offset] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeUint32BE =
Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

function wrtBigUInt64LE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  lo = lo >> 8
  buf[offset++] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  hi = hi >> 8
  buf[offset++] = hi
  return offset
}

function wrtBigUInt64BE (buf, value, offset, min, max) {
  checkIntBI(value, min, max, buf, offset, 7)

  let lo = Number(value & BigInt(0xffffffff))
  buf[offset + 7] = lo
  lo = lo >> 8
  buf[offset + 6] = lo
  lo = lo >> 8
  buf[offset + 5] = lo
  lo = lo >> 8
  buf[offset + 4] = lo
  let hi = Number(value >> BigInt(32) & BigInt(0xffffffff))
  buf[offset + 3] = hi
  hi = hi >> 8
  buf[offset + 2] = hi
  hi = hi >> 8
  buf[offset + 1] = hi
  hi = hi >> 8
  buf[offset] = hi
  return offset + 8
}

Buffer.prototype.writeBigUInt64LE = function writeBigUInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
}

Buffer.prototype.writeBigUInt64BE = function writeBigUInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, BigInt(0), BigInt('0xffffffffffffffff'))
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = 0
  let mul = 1
  let sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    const limit = Math.pow(2, (8 * byteLength) - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  let i = byteLength - 1
  let mul = 1
  let sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  this[offset] = (value >>> 8)
  this[offset + 1] = (value & 0xff)
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  this[offset] = (value & 0xff)
  this[offset + 1] = (value >>> 8)
  this[offset + 2] = (value >>> 16)
  this[offset + 3] = (value >>> 24)
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  this[offset] = (value >>> 24)
  this[offset + 1] = (value >>> 16)
  this[offset + 2] = (value >>> 8)
  this[offset + 3] = (value & 0xff)
  return offset + 4
}

Buffer.prototype.writeBigInt64LE = function writeBigInt64LE (value, offset = 0) {
  return wrtBigUInt64LE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
}

Buffer.prototype.writeBigInt64BE = function writeBigInt64BE (value, offset = 0) {
  return wrtBigUInt64BE(this, value, offset, -BigInt('0x8000000000000000'), BigInt('0x7fffffffffffffff'))
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  value = +value
  offset = offset >>> 0
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!Buffer.isBuffer(target)) throw new TypeError('argument should be a Buffer')
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('Index out of range')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  const len = end - start

  if (this === target) {
    this.copyWithin(targetStart, start, end)
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, end),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
    if (val.length === 1) {
      const code = val.charCodeAt(0)
      if ((encoding === 'utf8' && code < 128) ||
          encoding === 'latin1') {
        // Fast path: If `val` fits into a single byte, use that numeric value.
        val = code
      }
    }
  } else if (typeof val === 'number') {
    val = val & 255
  } else if (typeof val === 'boolean') {
    val = Number(val)
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  let i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    const bytes = Buffer.isBuffer(val)
      ? val
      : Buffer.from(val, encoding)
    const len = bytes.length
    if (len === 0) {
      throw new TypeError('The value "' + val +
        '" is invalid for argument "value"')
    }
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// CUSTOM ERRORS
// =============

// Simplified versions from Node, changed for Buffer-only usage
const errors = {}
function E (sym, getMessage, Base) {
  errors[sym] = class NodeError extends Base {
    constructor () {
      super()

      Object.defineProperty(this, 'message', {
        value: getMessage.apply(this, arguments),
        writable: true,
        configurable: true
      })

      // Add the error code to the name to include it in the stack trace.
      this.name = `${this.name} [${sym}]`
      // Access the stack to generate the error message including the error code
      // from the name.
      this.stack // eslint-disable-line no-unused-expressions
      // Reset the name to the actual name.
      delete this.name
    }

    get code () {
      return sym
    }

    set code (value) {
      Object.defineProperty(this, 'code', {
        configurable: true,
        enumerable: true,
        value,
        writable: true
      })
    }

    toString () {
      return `${this.name} [${sym}]: ${this.message}`
    }
  }
}

E('ERR_BUFFER_OUT_OF_BOUNDS',
  function (name) {
    if (name) {
      return `${name} is outside of buffer bounds`
    }

    return 'Attempt to access memory outside buffer bounds'
  }, RangeError)
E('ERR_INVALID_ARG_TYPE',
  function (name, actual) {
    return `The "${name}" argument must be of type number. Received type ${typeof actual}`
  }, TypeError)
E('ERR_OUT_OF_RANGE',
  function (str, range, input) {
    let msg = `The value of "${str}" is out of range.`
    let received = input
    if (Number.isInteger(input) && Math.abs(input) > 2 ** 32) {
      received = addNumericalSeparator(String(input))
    } else if (typeof input === 'bigint') {
      received = String(input)
      if (input > BigInt(2) ** BigInt(32) || input < -(BigInt(2) ** BigInt(32))) {
        received = addNumericalSeparator(received)
      }
      received += 'n'
    }
    msg += ` It must be ${range}. Received ${received}`
    return msg
  }, RangeError)

function addNumericalSeparator (val) {
  let res = ''
  let i = val.length
  const start = val[0] === '-' ? 1 : 0
  for (; i >= start + 4; i -= 3) {
    res = `_${val.slice(i - 3, i)}${res}`
  }
  return `${val.slice(0, i)}${res}`
}

// CHECK FUNCTIONS
// ===============

function checkBounds (buf, offset, byteLength) {
  validateNumber(offset, 'offset')
  if (buf[offset] === undefined || buf[offset + byteLength] === undefined) {
    boundsError(offset, buf.length - (byteLength + 1))
  }
}

function checkIntBI (value, min, max, buf, offset, byteLength) {
  if (value > max || value < min) {
    const n = typeof min === 'bigint' ? 'n' : ''
    let range
    if (byteLength > 3) {
      if (min === 0 || min === BigInt(0)) {
        range = `>= 0${n} and < 2${n} ** ${(byteLength + 1) * 8}${n}`
      } else {
        range = `>= -(2${n} ** ${(byteLength + 1) * 8 - 1}${n}) and < 2 ** ` +
                `${(byteLength + 1) * 8 - 1}${n}`
      }
    } else {
      range = `>= ${min}${n} and <= ${max}${n}`
    }
    throw new errors.ERR_OUT_OF_RANGE('value', range, value)
  }
  checkBounds(buf, offset, byteLength)
}

function validateNumber (value, name) {
  if (typeof value !== 'number') {
    throw new errors.ERR_INVALID_ARG_TYPE(name, 'number', value)
  }
}

function boundsError (value, length, type) {
  if (Math.floor(value) !== value) {
    validateNumber(value, type)
    throw new errors.ERR_OUT_OF_RANGE(type || 'offset', 'an integer', value)
  }

  if (length < 0) {
    throw new errors.ERR_BUFFER_OUT_OF_BOUNDS()
  }

  throw new errors.ERR_OUT_OF_RANGE(type || 'offset',
                                    `>= ${type ? 1 : 0} and <= ${length}`,
                                    value)
}

// HELPER FUNCTIONS
// ================

const INVALID_BASE64_RE = /[^+/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node takes equal signs as end of the Base64 encoding
  str = str.split('=')[0]
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = str.trim().replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  let codePoint
  const length = string.length
  let leadSurrogate = null
  const bytes = []

  for (let i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  let c, hi, lo
  const byteArray = []
  for (let i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  let i
  for (i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

// Create lookup table for `toString('hex')`
// See: https://github.com/feross/buffer/issues/219
const hexSliceLookupTable = (function () {
  const alphabet = '0123456789abcdef'
  const table = new Array(256)
  for (let i = 0; i < 16; ++i) {
    const i16 = i * 16
    for (let j = 0; j < 16; ++j) {
      table[i16 + j] = alphabet[i] + alphabet[j]
    }
  }
  return table
})()

export default {
  config,
  kMaxLength: K_MAX_LENGTH,
  Buffer,
  SlowBuffer
}

✄
/*! ieee754. BSD-3-Clause License. Feross Aboukhadijeh <https://feross.org/opensource> */

export function read (buffer, offset, isLE, mLen, nBytes) {
  let e, m
  const eLen = (nBytes * 8) - mLen - 1
  const eMax = (1 << eLen) - 1
  const eBias = eMax >> 1
  let nBits = -7
  let i = isLE ? (nBytes - 1) : 0
  const d = isLE ? -1 : 1
  let s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  while (nBits > 0) {
    e = (e * 256) + buffer[offset + i]
    i += d
    nBits -= 8
  }

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  while (nBits > 0) {
    m = (m * 256) + buffer[offset + i]
    i += d
    nBits -= 8
  }

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

export function write (buffer, value, offset, isLE, mLen, nBytes) {
  let e, m, c
  let eLen = (nBytes * 8) - mLen - 1
  const eMax = (1 << eLen) - 1
  const eBias = eMax >> 1
  const rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  let i = isLE ? 0 : (nBytes - 1)
  const d = isLE ? 1 : -1
  const s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  while (mLen >= 8) {
    buffer[offset + i] = m & 0xff
    i += d
    m /= 256
    mLen -= 8
  }

  e = (e << mLen) | m
  eLen += mLen
  while (eLen > 0) {
    buffer[offset + i] = e & 0xff
    i += d
    e /= 256
    eLen -= 8
  }

  buffer[offset + i - d] |= s * 128
}

✄
import getApi from './lib/api.js';
import {
  getAndroidVersion,
  withAllArtThreadsSuspended,
  withRunnableArtThread,
  makeArtClassVisitor,
  makeArtClassLoaderVisitor,
  backtrace,
  deoptimizeEverything,
  deoptimizeBootImage,
  deoptimizeMethod
} from './lib/android.js';
import ClassFactory from './lib/class-factory.js';
import ClassModel from './lib/class-model.js';
import Env from './lib/env.js';
import { initialize } from './lib/types.js';
import VM from './lib/vm.js';
import { checkJniResult } from './lib/result.js';

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

class Runtime {
  ACC_PUBLIC       = 0x0001;
  ACC_PRIVATE      = 0x0002;
  ACC_PROTECTED    = 0x0004;
  ACC_STATIC       = 0x0008;
  ACC_FINAL        = 0x0010;
  ACC_SYNCHRONIZED = 0x0020;
  ACC_BRIDGE       = 0x0040;
  ACC_VARARGS      = 0x0080;
  ACC_NATIVE       = 0x0100;
  ACC_ABSTRACT     = 0x0400;
  ACC_STRICT       = 0x0800;
  ACC_SYNTHETIC    = 0x1000;

  constructor () {
    this.classFactory = null;
    this.ClassFactory = ClassFactory;
    this.vm = null;
    this.api = null;

    this._initialized = false;
    this._apiError = null;
    this._wakeupHandler = null;
    this._pollListener = null;
    this._pendingMainOps = [];
    this._pendingVmOps = [];
    this._cachedIsAppProcess = null;

    try {
      this._tryInitialize();
    } catch (e) {
    }
  }

  _tryInitialize () {
    if (this._initialized) {
      return true;
    }

    if (this._apiError !== null) {
      throw this._apiError;
    }

    let api;
    try {
      api = getApi();
      this.api = api;
    } catch (e) {
      this._apiError = e;
      throw e;
    }
    if (api === null) {
      return false;
    }

    const vm = new VM(api);
    this.vm = vm;

    initialize(vm);
    ClassFactory._initialize(vm, api);
    this.classFactory = new ClassFactory();

    this._initialized = true;

    return true;
  }

  _dispose () {
    if (this.api === null) {
      return;
    }

    const { vm } = this;
    vm.perform(env => {
      ClassFactory._disposeAll(env);
      Env.dispose(env);
    });
    Script.nextTick(() => {
      VM.dispose(vm);
    });
  }

  get available () {
    return this._tryInitialize();
  }

  get androidVersion () {
    return getAndroidVersion();
  }

  synchronized (obj, fn) {
    const { $h: objHandle = obj } = obj;
    if (!(objHandle instanceof NativePointer)) {
      throw new Error('Java.synchronized: the first argument `obj` must be either a pointer or a Java instance');
    }

    const env = this.vm.getEnv();
    checkJniResult('VM::MonitorEnter', env.monitorEnter(objHandle));
    try {
      fn();
    } finally {
      env.monitorExit(objHandle);
    }
  }

  enumerateLoadedClasses (callbacks) {
    this._checkAvailable();

    const { flavor } = this.api;
    if (flavor === 'jvm') {
      this._enumerateLoadedClassesJvm(callbacks);
    } else if (flavor === 'art') {
      this._enumerateLoadedClassesArt(callbacks);
    } else {
      this._enumerateLoadedClassesDalvik(callbacks);
    }
  }

  enumerateLoadedClassesSync () {
    const classes = [];
    this.enumerateLoadedClasses({
      onMatch (c) {
        classes.push(c);
      },
      onComplete () {
      }
    });
    return classes;
  }

  enumerateClassLoaders (callbacks) {
    this._checkAvailable();

    const { flavor } = this.api;
    if (flavor === 'jvm') {
      this._enumerateClassLoadersJvm(callbacks);
    } else if (flavor === 'art') {
      this._enumerateClassLoadersArt(callbacks);
    } else {
      throw new Error('Enumerating class loaders is not supported on Dalvik');
    }
  }

  enumerateClassLoadersSync () {
    const loaders = [];
    this.enumerateClassLoaders({
      onMatch (c) {
        loaders.push(c);
      },
      onComplete () {
      }
    });
    return loaders;
  }

  _enumerateLoadedClassesJvm (callbacks) {
    const { api, vm } = this;
    const { jvmti } = api;
    const env = vm.getEnv();

    const countPtr = Memory.alloc(jsizeSize);
    const classesPtr = Memory.alloc(pointerSize);
    jvmti.getLoadedClasses(countPtr, classesPtr);

    const count = countPtr.readS32();
    const classes = classesPtr.readPointer();
    const handles = [];
    for (let i = 0; i !== count; i++) {
      handles.push(classes.add(i * pointerSize).readPointer());
    }
    jvmti.deallocate(classes);

    try {
      for (const handle of handles) {
        const className = env.getClassName(handle);
        callbacks.onMatch(className, handle);
      }

      callbacks.onComplete();
    } finally {
      handles.forEach(handle => {
        env.deleteLocalRef(handle);
      });
    }
  }

  _enumerateClassLoadersJvm (callbacks) {
    this.choose('java.lang.ClassLoader', callbacks);
  }

  _enumerateLoadedClassesArt (callbacks) {
    const { vm, api } = this;
    const env = vm.getEnv();

    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const { vm: vmHandle } = api;
    withRunnableArtThread(vm, env, thread => {
      const collectClassHandles = makeArtClassVisitor(klass => {
        const handle = addGlobalReference(vmHandle, thread, klass);
        try {
          const className = env.getClassName(handle);
          callbacks.onMatch(className, handle);
        } finally {
          env.deleteGlobalRef(handle);
        }
        return true;
      });

      api['art::ClassLinker::VisitClasses'](api.artClassLinker.address, collectClassHandles);
    });

    callbacks.onComplete();
  }

  _enumerateClassLoadersArt (callbacks) {
    const { classFactory: factory, vm, api } = this;
    const env = vm.getEnv();

    const visitClassLoaders = api['art::ClassLinker::VisitClassLoaders'];
    if (visitClassLoaders === undefined) {
      throw new Error('This API is only available on Android >= 7.0');
    }

    const ClassLoader = factory.use('java.lang.ClassLoader');

    const loaderHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const { vm: vmHandle } = api;
    withRunnableArtThread(vm, env, thread => {
      const collectLoaderHandles = makeArtClassLoaderVisitor(loader => {
        loaderHandles.push(addGlobalReference(vmHandle, thread, loader));
        return true;
      });
      withAllArtThreadsSuspended(() => {
        visitClassLoaders(api.artClassLinker.address, collectLoaderHandles);
      });
    });

    try {
      loaderHandles.forEach(handle => {
        const loader = factory.cast(handle, ClassLoader);
        callbacks.onMatch(loader);
      });
    } finally {
      loaderHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  _enumerateLoadedClassesDalvik (callbacks) {
    const { api } = this;

    const HASH_TOMBSTONE = ptr('0xcbcacccd');
    const loadedClassesOffset = 172;
    const hashEntrySize = 8;

    const ptrLoadedClassesHashtable = api.gDvm.add(loadedClassesOffset);
    const hashTable = ptrLoadedClassesHashtable.readPointer();

    const tableSize = hashTable.readS32();
    const ptrpEntries = hashTable.add(12);
    const pEntries = ptrpEntries.readPointer();
    const end = tableSize * hashEntrySize;

    for (let offset = 0; offset < end; offset += hashEntrySize) {
      const pEntryPtr = pEntries.add(offset);
      const dataPtr = pEntryPtr.add(4).readPointer();

      if (dataPtr.isNull() || dataPtr.equals(HASH_TOMBSTONE)) {
        continue;
      }

      const descriptionPtr = dataPtr.add(24).readPointer();
      const description = descriptionPtr.readUtf8String();
      if (description.startsWith('L')) {
        const name = description.substring(1, description.length - 1).replace(/\//g, '.');
        callbacks.onMatch(name);
      }
    }

    callbacks.onComplete();
  }

  enumerateMethods (query) {
    const { classFactory: factory } = this;
    const env = this.vm.getEnv();
    const ClassLoader = factory.use('java.lang.ClassLoader');

    return ClassModel.enumerateMethods(query, this.api, env)
      .map(group => {
        const handle = group.loader;
        group.loader = (handle !== null) ? factory.wrap(handle, ClassLoader, env) : null;
        return group;
      });
  }

  scheduleOnMainThread (fn) {
    this.performNow(() => {
      this._pendingMainOps.push(fn);

      let { _wakeupHandler: wakeupHandler } = this;
      if (wakeupHandler === null) {
        const { classFactory: factory } = this;
        const Handler = factory.use('android.os.Handler');
        const Looper = factory.use('android.os.Looper');

        wakeupHandler = Handler.$new(Looper.getMainLooper());
        this._wakeupHandler = wakeupHandler;
      }

      if (this._pollListener === null) {
        this._pollListener = Interceptor.attach(Process.getModuleByName('libc.so').getExportByName('epoll_wait'), this._makePollHook());
        Interceptor.flush();
      }

      wakeupHandler.sendEmptyMessage(1);
    });
  }

  _makePollHook () {
    const mainThreadId = Process.id;
    const { _pendingMainOps: pending } = this;

    return function () {
      if (this.threadId !== mainThreadId) {
        return;
      }

      let fn;
      while ((fn = pending.shift()) !== undefined) {
        try {
          fn();
        } catch (e) {
          Script.nextTick(() => { throw e; });
        }
      }
    };
  }

  perform (fn) {
    this._checkAvailable();

    if (!this._isAppProcess() || this.classFactory.loader !== null) {
      try {
        this.vm.perform(fn);
      } catch (e) {
        Script.nextTick(() => { throw e; });
      }
    } else {
      this._pendingVmOps.push(fn);
      if (this._pendingVmOps.length === 1) {
        this._performPendingVmOpsWhenReady();
      }
    }
  }

  performNow (fn) {
    this._checkAvailable();

    return this.vm.perform(() => {
      const { classFactory: factory } = this;

      if (this._isAppProcess() && factory.loader === null) {
        const ActivityThread = factory.use('android.app.ActivityThread');
        const app = ActivityThread.currentApplication();
        if (app !== null) {
          initFactoryFromApplication(factory, app);
        }
      }

      return fn();
    });
  }

  _performPendingVmOpsWhenReady () {
    this.vm.perform(() => {
      const { classFactory: factory } = this;

      const ActivityThread = factory.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      if (app !== null) {
        initFactoryFromApplication(factory, app);
        this._performPendingVmOps();
        return;
      }

      const runtime = this;
      let initialized = false;
      let hookpoint = 'early';

      const handleBindApplication = ActivityThread.handleBindApplication;
      handleBindApplication.implementation = function (data) {
        if (data.instrumentationName.value !== null) {
          hookpoint = 'late';

          const LoadedApk = factory.use('android.app.LoadedApk');
          const makeApplication = LoadedApk.makeApplication;
          makeApplication.implementation = function (forceDefaultAppClass, instrumentation) {
            if (!initialized) {
              initialized = true;
              initFactoryFromLoadedApk(factory, this);
              runtime._performPendingVmOps();
            }

            return makeApplication.apply(this, arguments);
          };
        }

        handleBindApplication.apply(this, arguments);
      };

      const getPackageInfoCandidates = ActivityThread.getPackageInfo.overloads
        .map(m => [m.argumentTypes.length, m])
        .sort(([arityA,], [arityB,]) => arityB - arityA)
        .map(([_, method]) => method);
      const getPackageInfo = getPackageInfoCandidates[0];
      getPackageInfo.implementation = function (...args) {
        const apk = getPackageInfo.call(this, ...args);

        if (!initialized && hookpoint === 'early') {
          initialized = true;
          initFactoryFromLoadedApk(factory, apk);
          runtime._performPendingVmOps();
        }

        return apk;
      };
    });
  }

  _performPendingVmOps () {
    const { vm, _pendingVmOps: pending } = this;

    let fn;
    while ((fn = pending.shift()) !== undefined) {
      try {
        vm.perform(fn);
      } catch (e) {
        Script.nextTick(() => { throw e; });
      }
    }
  }

  use (className, options) {
    return this.classFactory.use(className, options);
  }

  openClassFile (filePath) {
    return this.classFactory.openClassFile(filePath);
  }

  choose (specifier, callbacks) {
    this.classFactory.choose(specifier, callbacks);
  }

  retain (obj) {
    return this.classFactory.retain(obj);
  }

  cast (obj, C) {
    return this.classFactory.cast(obj, C);
  }

  array (type, elements) {
    return this.classFactory.array(type, elements);
  }

  backtrace (options) {
    return backtrace(this.vm, options);
  }

  // Reference: http://stackoverflow.com/questions/2848575/how-to-detect-ui-thread-on-android
  isMainThread () {
    const Looper = this.classFactory.use('android.os.Looper');
    const mainLooper = Looper.getMainLooper();
    const myLooper = Looper.myLooper();
    if (myLooper === null) {
      return false;
    }
    return mainLooper.$isSameObject(myLooper);
  }

  registerClass (spec) {
    return this.classFactory.registerClass(spec);
  }

  deoptimizeEverything () {
    const { vm } = this;
    return deoptimizeEverything(vm, vm.getEnv());
  }

  deoptimizeBootImage () {
    const { vm } = this;
    return deoptimizeBootImage(vm, vm.getEnv());
  }

  deoptimizeMethod (method) {
    const { vm } = this;
    return deoptimizeMethod(vm, vm.getEnv(), method);
  }

  _checkAvailable () {
    if (!this.available) {
      throw new Error('Java API not available');
    }
  }

  _isAppProcess () {
    let result = this._cachedIsAppProcess;
    if (result === null) {
      if (this.api.flavor === 'jvm') {
        result = false;
        this._cachedIsAppProcess = result;
        return result;
      }

      const readlink = new NativeFunction(Module.getGlobalExportByName('readlink'), 'pointer', ['pointer', 'pointer', 'pointer'], {
        exceptions: 'propagate'
      });

      const pathname = Memory.allocUtf8String('/proc/self/exe');
      const bufferSize = 1024;
      const buffer = Memory.alloc(bufferSize);

      const size = readlink(pathname, buffer, ptr(bufferSize)).toInt32();
      if (size !== -1) {
        const exe = buffer.readUtf8String(size);
        result = /^\/system\/bin\/app_process/.test(exe);
      } else {
        result = true;
      }

      this._cachedIsAppProcess = result;
    }

    return result;
  }
}

function initFactoryFromApplication (factory, app) {
  const Process = factory.use('android.os.Process');

  factory.loader = app.getClassLoader();

  if (Process.myUid() === Process.SYSTEM_UID.value) {
    factory.cacheDir = '/data/system';
    factory.codeCacheDir = '/data/dalvik-cache';
  } else {
    if ('getCodeCacheDir' in app) {
      factory.cacheDir = app.getCacheDir().getCanonicalPath();
      factory.codeCacheDir = app.getCodeCacheDir().getCanonicalPath();
    } else {
      factory.cacheDir = app.getFilesDir().getCanonicalPath();
      factory.codeCacheDir = app.getCacheDir().getCanonicalPath();
    }
  }
}

function initFactoryFromLoadedApk (factory, apk) {
  const JFile = factory.use('java.io.File');

  factory.loader = apk.getClassLoader();

  const dataDir = JFile.$new(apk.getDataDir()).getCanonicalPath();
  factory.cacheDir = dataDir;
  factory.codeCacheDir = dataDir + '/cache';
}

const runtime = new Runtime();
Script.bindWeak(runtime, () => { runtime._dispose(); });

export default runtime;

✄
const {
  pageSize,
  pointerSize
} = Process;

class CodeAllocator {
  constructor (sliceSize) {
    this.sliceSize = sliceSize;
    this.slicesPerPage = pageSize / sliceSize;

    this.pages = [];
    this.free = [];
  }

  allocateSlice (spec, alignment) {
    const anyLocation = spec.near === undefined;
    const anyAlignment = alignment === 1;
    if (anyLocation && anyAlignment) {
      const slice = this.free.pop();
      if (slice !== undefined) {
        return slice;
      }
    } else if (alignment < pageSize) {
      const { free } = this;
      const n = free.length;
      const alignMask = anyAlignment ? null : ptr(alignment - 1);
      for (let i = 0; i !== n; i++) {
        const slice = free[i];

        const satisfiesLocation = anyLocation || this._isSliceNear(slice, spec);
        const satisfiesAlignment = anyAlignment || slice.and(alignMask).isNull();

        if (satisfiesLocation && satisfiesAlignment) {
          return free.splice(i, 1)[0];
        }
      }
    }

    return this._allocatePage(spec);
  }

  _allocatePage (spec) {
    const page = Memory.alloc(pageSize, spec);

    const { sliceSize, slicesPerPage } = this;

    for (let i = 1; i !== slicesPerPage; i++) {
      const slice = page.add(i * sliceSize);
      this.free.push(slice);
    }

    this.pages.push(page);

    return page;
  }

  _isSliceNear (slice, spec) {
    const sliceEnd = slice.add(this.sliceSize);

    const { near, maxDistance } = spec;

    const startDistance = abs(near.sub(slice));
    const endDistance = abs(near.sub(sliceEnd));

    return startDistance.compare(maxDistance) <= 0 &&
        endDistance.compare(maxDistance) <= 0;
  }

  freeSlice (slice) {
    this.free.push(slice);
  }
}

function abs (nptr) {
  const shmt = (pointerSize === 4) ? 31 : 63;
  const mask = ptr(1).shl(shmt).not();
  return nptr.and(mask);
}

export default function makeAllocator (sliceSize) {
  return new CodeAllocator(sliceSize);
}

✄
import makeCodeAllocator from './alloc.js';
import {
  jvmtiVersion,
  jvmtiCapabilities,
  EnvJvmti
} from './jvmti.js';
import { parseInstructionsAt } from './machine-code.js';
import memoize from './memoize.js';
import { checkJniResult, JNI_OK } from './result.js';
import VM from './vm.js';

const jsizeSize = 4;
const pointerSize = Process.pointerSize;

const {
  readU32,
  readPointer,
  writeU32,
  writePointer
} = NativePointer.prototype;

const kAccPublic = 0x0001;
const kAccStatic = 0x0008;
const kAccFinal = 0x0010;
const kAccNative = 0x0100;
const kAccFastNative = 0x00080000;
const kAccCriticalNative = 0x00200000;
const kAccFastInterpreterToInterpreterInvoke = 0x40000000;
const kAccSkipAccessChecks = 0x00080000;
const kAccSingleImplementation = 0x08000000;
const kAccNterpEntryPointFastPathFlag = 0x00100000;
const kAccNterpInvokeFastPathFlag = 0x00200000;
const kAccPublicApi = 0x10000000;
const kAccXposedHookedMethod = 0x10000000;

const kPointer = 0x0;

const kFullDeoptimization = 3;
const kSelectiveDeoptimization = 5;

const THUMB_BIT_REMOVAL_MASK = ptr(1).not();

const X86_JMP_MAX_DISTANCE = 0x7fffbfff;
const ARM64_ADRP_MAX_DISTANCE = 0xfffff000;

const ENV_VTABLE_OFFSET_EXCEPTION_CLEAR = 17 * pointerSize;
const ENV_VTABLE_OFFSET_FATAL_ERROR = 18 * pointerSize;

export const DVM_JNI_ENV_OFFSET_SELF = 12;

const DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT = 112;
const DVM_CLASS_OBJECT_OFFSET_VTABLE = 116;

const DVM_OBJECT_OFFSET_CLAZZ = 0;

const DVM_METHOD_SIZE = 56;
const DVM_METHOD_OFFSET_ACCESS_FLAGS = 4;
const DVM_METHOD_OFFSET_METHOD_INDEX = 8;
const DVM_METHOD_OFFSET_REGISTERS_SIZE = 10;
const DVM_METHOD_OFFSET_OUTS_SIZE = 12;
const DVM_METHOD_OFFSET_INS_SIZE = 14;
const DVM_METHOD_OFFSET_SHORTY = 28;
const DVM_METHOD_OFFSET_JNI_ARG_INFO = 36;

const DALVIK_JNI_RETURN_VOID = 0;
const DALVIK_JNI_RETURN_FLOAT = 1;
const DALVIK_JNI_RETURN_DOUBLE = 2;
const DALVIK_JNI_RETURN_S8 = 3;
const DALVIK_JNI_RETURN_S4 = 4;
const DALVIK_JNI_RETURN_S2 = 5;
const DALVIK_JNI_RETURN_U2 = 6;
const DALVIK_JNI_RETURN_S1 = 7;
const DALVIK_JNI_NO_ARG_INFO = 0x80000000;
const DALVIK_JNI_RETURN_SHIFT = 28;

const STD_STRING_SIZE = 3 * pointerSize;
const STD_VECTOR_SIZE = 3 * pointerSize;

const AF_UNIX = 1;
const SOCK_STREAM = 1;

const getArtRuntimeSpec = memoize(_getArtRuntimeSpec);
const getArtInstrumentationSpec = memoize(_getArtInstrumentationSpec);
export const getArtMethodSpec = memoize(_getArtMethodSpec);
export const getArtThreadSpec = memoize(_getArtThreadSpec);
const getArtManagedStackSpec = memoize(_getArtManagedStackSpec);
const getArtThreadStateTransitionImpl = memoize(_getArtThreadStateTransitionImpl);
export const getAndroidVersion = memoize(_getAndroidVersion);
const getAndroidCodename = memoize(_getAndroidCodename);
export const getAndroidApiLevel = memoize(_getAndroidApiLevel);
export const getArtApexVersion = memoize(_getArtApexVersion);
const getArtQuickFrameInfoGetterThunk = memoize(_getArtQuickFrameInfoGetterThunk);

const makeCxxMethodWrapperReturningPointerByValue =
    (Process.arch === 'ia32')
      ? makeCxxMethodWrapperReturningPointerByValueInFirstArg
      : makeCxxMethodWrapperReturningPointerByValueGeneric;

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const artThreadStateTransitions = {};

let cachedApi = null;
let cachedArtClassLinkerSpec = null;
let MethodMangler = null;
let artController = null;
const inlineHooks = [];
const patchedClasses = new Map();
const artQuickInterceptors = [];
let thunkPage = null;
let thunkOffset = 0;
let taughtArtAboutReplacementMethods = false;
let taughtArtAboutMethodInstrumentation = false;
let backtraceModule = null;
const jdwpSessions = [];
let socketpair = null;

let trampolineAllocator = null;

export function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /^lib(art|dvm).so$/.test(m.name))
    .filter(m => !/\/system\/fake-libs/.test(m.path));
  if (vmModules.length === 0) {
    return null;
  }
  const vmModule = vmModules[0];

  const flavor = (vmModule.name.indexOf('art') !== -1) ? 'art' : 'dalvik';
  const isArt = flavor === 'art';

  const temporaryApi = {
    module: vmModule,
    find (name) {
      const { module } = this;
      let address = module.findExportByName(name);
      if (address === null) {
        address = module.findSymbolByName(name);
      }
      return address;
    },
    flavor,
    addLocalReference: null
  };

  temporaryApi.isApiLevel34OrApexEquivalent = isArt && (
    temporaryApi.find('_ZN3art7AppInfo29GetPrimaryApkReferenceProfileEv') !== null ||
    temporaryApi.find('_ZN3art6Thread15RunFlipFunctionEPS0_') !== null
  );

  const pending = isArt
    ? {
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

          // Android < 7
          artInterpreterToCompiledCodeBridge: function (address) {
            this.artInterpreterToCompiledCodeBridge = address;
          },

          // Android >= 8
          _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE: ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
          // Android >= 6
          _ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE: ['art::JavaVMExt::AddGlobalRef', 'pointer', ['pointer', 'pointer', 'pointer']],
          // Android < 6: makeAddGlobalRefFallbackForAndroid5() needs these:
          _ZN3art17ReaderWriterMutex13ExclusiveLockEPNS_6ThreadE: ['art::ReaderWriterMutex::ExclusiveLock', 'void', ['pointer', 'pointer']],
          _ZN3art17ReaderWriterMutex15ExclusiveUnlockEPNS_6ThreadE: ['art::ReaderWriterMutex::ExclusiveUnlock', 'void', ['pointer', 'pointer']],

          // Android <= 7
          _ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE: function (address) {
            this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
          },
          // Android > 7
          _ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE: function (address) {
            this['art::IndirectReferenceTable::Add'] = new NativeFunction(address, 'pointer', ['pointer', 'uint', 'pointer'], nativeFunctionOptions);
          },

          // Android >= 7
          _ZN3art9JavaVMExt12DecodeGlobalEPv: function (address) {
            let decodeGlobal;
            if (getAndroidApiLevel() >= 26) {
              // Returns ObjPtr<mirror::Object>
              decodeGlobal = makeCxxMethodWrapperReturningPointerByValue(address, ['pointer', 'pointer']);
            } else {
              // Returns mirror::Object *
              decodeGlobal = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
            }
            this['art::JavaVMExt::DecodeGlobal'] = function (vm, thread, ref) {
              return decodeGlobal(vm, ref);
            };
          },
          // Android >= 6
          _ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv: ['art::JavaVMExt::DecodeGlobal', 'pointer', ['pointer', 'pointer', 'pointer']],

          // makeDecodeGlobalFallback() uses:
          // Android >= 15
          _ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject: ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],
          // Android < 6
          _ZNK3art6Thread13DecodeJObjectEP8_jobject: ['art::Thread::DecodeJObject', 'pointer', ['pointer', 'pointer']],

          // Android >= 6
          _ZN3art10ThreadList10SuspendAllEPKcb: ['art::ThreadList::SuspendAll', 'void', ['pointer', 'pointer', 'bool']],
          // or fallback:
          _ZN3art10ThreadList10SuspendAllEv: function (address) {
            const suspendAll = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['art::ThreadList::SuspendAll'] = function (threadList, cause, longSuspend) {
              return suspendAll(threadList);
            };
          },

          _ZN3art10ThreadList9ResumeAllEv: ['art::ThreadList::ResumeAll', 'void', ['pointer']],

          // Android >= 7
          _ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE: ['art::ClassLinker::VisitClasses', 'void', ['pointer', 'pointer']],
          // Android < 7
          _ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_: function (address) {
            const visitClasses = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['art::ClassLinker::VisitClasses'] = function (classLinker, visitor) {
              visitClasses(classLinker, visitor, NULL);
            };
          },

          _ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE: ['art::ClassLinker::VisitClassLoaders', 'void', ['pointer', 'pointer']],

          _ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_: ['art::gc::Heap::VisitObjects', 'void', ['pointer', 'pointer', 'pointer']],
          _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: ['art::gc::Heap::GetInstances', 'void', ['pointer', 'pointer', 'pointer', 'int', 'pointer']],

          // Android >= 9
          _ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE: function (address) {
            const getInstances = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer', 'bool', 'int', 'pointer'], nativeFunctionOptions);
            this['art::gc::Heap::GetInstances'] = function (instance, scope, hClass, maxCount, instances) {
              const useIsAssignableFrom = 0;
              getInstances(instance, scope, hClass, useIsAssignableFrom, maxCount, instances);
            };
          },

          _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb: ['art::StackVisitor::StackVisitor', 'void', ['pointer', 'pointer', 'pointer', 'uint', 'uint', 'bool']],
          _ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb: ['art::StackVisitor::StackVisitor', 'void', ['pointer', 'pointer', 'pointer', 'uint', 'size_t', 'bool']],
          _ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb: ['art::StackVisitor::WalkStack', 'void', ['pointer', 'bool']],
          _ZNK3art12StackVisitor9GetMethodEv: ['art::StackVisitor::GetMethod', 'pointer', ['pointer']],
          _ZNK3art12StackVisitor16DescribeLocationEv: function (address) {
            this['art::StackVisitor::DescribeLocation'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer']);
          },
          _ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv: function (address) {
            this['art::StackVisitor::GetCurrentQuickFrameInfo'] = makeArtQuickFrameInfoGetter(address);
          },

          _ZN3art7Context6CreateEv: ['art::Context::Create', 'pointer', []],
          _ZN3art6Thread18GetLongJumpContextEv: ['art::Thread::GetLongJumpContext', 'pointer', ['pointer']],

          _ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE: function (address) {
            this['art::mirror::Class::GetDescriptor'] = address;
          },
          _ZN3art6mirror5Class11GetLocationEv: function (address) {
            this['art::mirror::Class::GetLocation'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer']);
          },

          _ZN3art9ArtMethod12PrettyMethodEb: function (address) {
            this['art::ArtMethod::PrettyMethod'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer', 'bool']);
          },
          _ZN3art12PrettyMethodEPNS_9ArtMethodEb: function (address) {
            this['art::ArtMethod::PrettyMethodNullSafe'] = makeCxxMethodWrapperReturningStdStringByValue(address, ['pointer', 'bool']);
          },

          // Android < 6 for cloneArtMethod()
          _ZN3art6Thread14CurrentFromGdbEv: ['art::Thread::CurrentFromGdb', 'pointer', []],
          _ZN3art6mirror6Object5CloneEPNS_6ThreadE: function (address) {
            this['art::mirror::Object::Clone'] = new NativeFunction(address, 'pointer', ['pointer', 'pointer'], nativeFunctionOptions);
          },
          _ZN3art6mirror6Object5CloneEPNS_6ThreadEm: function (address) {
            const clone = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
              const numTargetBytes = NULL;
              return clone(thisPtr, threadPtr, numTargetBytes);
            };
          },
          _ZN3art6mirror6Object5CloneEPNS_6ThreadEj: function (address) {
            const clone = new NativeFunction(address, 'pointer', ['pointer', 'pointer', 'uint'], nativeFunctionOptions);
            this['art::mirror::Object::Clone'] = function (thisPtr, threadPtr) {
              const numTargetBytes = 0;
              return clone(thisPtr, threadPtr, numTargetBytes);
            };
          },

          _ZN3art3Dbg14SetJdwpAllowedEb: ['art::Dbg::SetJdwpAllowed', 'void', ['bool']],
          _ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE: ['art::Dbg::ConfigureJdwp', 'void', ['pointer']],
          _ZN3art31InternalDebuggerControlCallback13StartDebuggerEv: ['art::InternalDebuggerControlCallback::StartDebugger', 'void', ['pointer']],
          _ZN3art3Dbg9StartJdwpEv: ['art::Dbg::StartJdwp', 'void', []],
          _ZN3art3Dbg8GoActiveEv: ['art::Dbg::GoActive', 'void', []],
          _ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE: ['art::Dbg::RequestDeoptimization', 'void', ['pointer']],
          _ZN3art3Dbg20ManageDeoptimizationEv: ['art::Dbg::ManageDeoptimization', 'void', []],

          _ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv: ['art::Instrumentation::EnableDeoptimization', 'void', ['pointer']],
          // Android >= 6
          _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc: ['art::Instrumentation::DeoptimizeEverything', 'void', ['pointer', 'pointer']],
          // Android < 6
          _ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv: function (address) {
            const deoptimize = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['art::Instrumentation::DeoptimizeEverything'] = function (instrumentation, key) {
              deoptimize(instrumentation);
            };
          },
          _ZN3art7Runtime19DeoptimizeBootImageEv: ['art::Runtime::DeoptimizeBootImage', 'void', ['pointer']],
          _ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE: ['art::Instrumentation::Deoptimize', 'void', ['pointer', 'pointer']],

          // Android >= 11
          _ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID: ['art::jni::JniIdManager::DecodeMethodId', 'pointer', ['pointer', 'pointer']],
          _ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID: ['art::jni::JniIdManager::DecodeFieldId', 'pointer', ['pointer', 'pointer']],
          _ZN3art11interpreter18GetNterpEntryPointEv: ['art::interpreter::GetNterpEntryPoint', 'pointer', []],

          _ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi: ['art::Monitor::TranslateLocation', 'void', ['pointer', 'uint32', 'pointer', 'pointer']]
        },
        variables: {
          _ZN3art3Dbg9gRegistryE: function (address) {
            this.isJdwpStarted = () => !address.readPointer().isNull();
          },
          _ZN3art3Dbg15gDebuggerActiveE: function (address) {
            this.isDebuggerActive = () => !!address.readU8();
          }
        },
        optionals: new Set([
          'artInterpreterToCompiledCodeBridge',
          '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadENS_6ObjPtrINS_6mirror6ObjectEEE',
          '_ZN3art9JavaVMExt12AddGlobalRefEPNS_6ThreadEPNS_6mirror6ObjectE',
          '_ZN3art9JavaVMExt12DecodeGlobalEPv',
          '_ZN3art9JavaVMExt12DecodeGlobalEPNS_6ThreadEPv',
          '_ZNK3art6Thread19DecodeGlobalJObjectEP8_jobject',
          '_ZNK3art6Thread13DecodeJObjectEP8_jobject',
          '_ZN3art10ThreadList10SuspendAllEPKcb',
          '_ZN3art10ThreadList10SuspendAllEv',
          '_ZN3art11ClassLinker12VisitClassesEPNS_12ClassVisitorE',
          '_ZN3art11ClassLinker12VisitClassesEPFbPNS_6mirror5ClassEPvES4_',
          '_ZNK3art11ClassLinker17VisitClassLoadersEPNS_18ClassLoaderVisitorE',
          '_ZN3art6mirror6Object5CloneEPNS_6ThreadE',
          '_ZN3art6mirror6Object5CloneEPNS_6ThreadEm',
          '_ZN3art6mirror6Object5CloneEPNS_6ThreadEj',
          '_ZN3art22IndirectReferenceTable3AddEjPNS_6mirror6ObjectE',
          '_ZN3art22IndirectReferenceTable3AddENS_15IRTSegmentStateENS_6ObjPtrINS_6mirror6ObjectEEE',
          '_ZN3art2gc4Heap12VisitObjectsEPFvPNS_6mirror6ObjectEPvES5_',
          '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE',
          '_ZN3art2gc4Heap12GetInstancesERNS_24VariableSizedHandleScopeENS_6HandleINS_6mirror5ClassEEEbiRNSt3__16vectorINS4_INS5_6ObjectEEENS8_9allocatorISB_EEEE',
          '_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEjb',
          '_ZN3art12StackVisitorC2EPNS_6ThreadEPNS_7ContextENS0_13StackWalkKindEmb',
          '_ZN3art12StackVisitor9WalkStackILNS0_16CountTransitionsE0EEEvb',
          '_ZNK3art12StackVisitor9GetMethodEv',
          '_ZNK3art12StackVisitor16DescribeLocationEv',
          '_ZNK3art12StackVisitor24GetCurrentQuickFrameInfoEv',
          '_ZN3art7Context6CreateEv',
          '_ZN3art6Thread18GetLongJumpContextEv',
          '_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE',
          '_ZN3art6mirror5Class11GetLocationEv',
          '_ZN3art9ArtMethod12PrettyMethodEb',
          '_ZN3art12PrettyMethodEPNS_9ArtMethodEb',
          '_ZN3art3Dbg13ConfigureJdwpERKNS_4JDWP11JdwpOptionsE',
          '_ZN3art31InternalDebuggerControlCallback13StartDebuggerEv',
          '_ZN3art3Dbg15gDebuggerActiveE',
          '_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv',
          '_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc',
          '_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEv',
          '_ZN3art7Runtime19DeoptimizeBootImageEv',
          '_ZN3art15instrumentation15Instrumentation10DeoptimizeEPNS_9ArtMethodE',
          '_ZN3art3Dbg9StartJdwpEv',
          '_ZN3art3Dbg8GoActiveEv',
          '_ZN3art3Dbg21RequestDeoptimizationERKNS_21DeoptimizationRequestE',
          '_ZN3art3Dbg20ManageDeoptimizationEv',
          '_ZN3art3Dbg9gRegistryE',
          '_ZN3art3jni12JniIdManager14DecodeMethodIdEP10_jmethodID',
          '_ZN3art3jni12JniIdManager13DecodeFieldIdEP9_jfieldID',
          '_ZN3art11interpreter18GetNterpEntryPointEv',
          '_ZN3art7Monitor17TranslateLocationEPNS_9ArtMethodEjPPKcPi'
        ])
      }
    : {
        functions: {
          _Z20dvmDecodeIndirectRefP6ThreadP8_jobject: ['dvmDecodeIndirectRef', 'pointer', ['pointer', 'pointer']],
          _Z15dvmUseJNIBridgeP6MethodPv: ['dvmUseJNIBridge', 'void', ['pointer', 'pointer']],
          _Z20dvmHeapSourceGetBasev: ['dvmHeapSourceGetBase', 'pointer', []],
          _Z21dvmHeapSourceGetLimitv: ['dvmHeapSourceGetLimit', 'pointer', []],
          _Z16dvmIsValidObjectPK6Object: ['dvmIsValidObject', 'uint8', ['pointer']],
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']]
        },
        variables: {
          gDvmJni: function (address) {
            this.gDvmJni = address;
          },
          gDvm: function (address) {
            this.gDvm = address;
          }
        }
      };

  const {
    functions = {},
    variables = {},
    optionals = new Set()
  } = pending;

  const missing = [];

  for (const [name, signature] of Object.entries(functions)) {
    const address = temporaryApi.find(name);
    if (address !== null) {
      if (typeof signature === 'function') {
        signature.call(temporaryApi, address);
      } else {
        temporaryApi[signature[0]] = new NativeFunction(address, signature[1], signature[2], nativeFunctionOptions);
      }
    } else {
      if (!optionals.has(name)) {
        missing.push(name);
      }
    }
  }

  for (const [name, handler] of Object.entries(variables)) {
    const address = temporaryApi.find(name);
    if (address !== null) {
      handler.call(temporaryApi, address);
    } else {
      if (!optionals.has(name)) {
        missing.push(name);
      }
    }
  }

  if (missing.length > 0) {
    throw new Error('Java API only partially available; please file a bug. Missing: ' + missing.join(', '));
  }

  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();

  if (isArt) {
    const apiLevel = getAndroidApiLevel();

    let kAccCompileDontBother;
    if (apiLevel >= 27) {
      kAccCompileDontBother = 0x02000000;
    } else if (apiLevel >= 24) {
      kAccCompileDontBother = 0x01000000;
    } else {
      kAccCompileDontBother = 0;
    }
    temporaryApi.kAccCompileDontBother = kAccCompileDontBother;

    const artRuntime = temporaryApi.vm.add(pointerSize).readPointer();
    temporaryApi.artRuntime = artRuntime;
    const runtimeSpec = getArtRuntimeSpec(temporaryApi);
    const runtimeOffset = runtimeSpec.offset;
    const instrumentationOffset = runtimeOffset.instrumentation;
    temporaryApi.artInstrumentation = (instrumentationOffset !== null) ? artRuntime.add(instrumentationOffset) : null;

    const instrumentationIsPointer = getArtApexVersion() >= 360_000_000;
    if (instrumentationIsPointer && temporaryApi.artInstrumentation != null) {
      temporaryApi.artInstrumentation = temporaryApi.artInstrumentation.readPointer();
    }

    temporaryApi.artHeap = artRuntime.add(runtimeOffset.heap).readPointer();
    temporaryApi.artThreadList = artRuntime.add(runtimeOffset.threadList).readPointer();

    /*
     * We must use the *correct* copy (or address) of art_quick_generic_jni_trampoline
     * in order for the stack trace to recognize the JNI stub quick frame.
     *
     * For ARTs for Android 6.x we can just use the JNI trampoline built into ART.
     */
    const classLinker = artRuntime.add(runtimeOffset.classLinker).readPointer();

    const classLinkerOffsets = getArtClassLinkerSpec(artRuntime, runtimeSpec).offset;
    const quickResolutionTrampoline = classLinker.add(classLinkerOffsets.quickResolutionTrampoline).readPointer();
    const quickImtConflictTrampoline = classLinker.add(classLinkerOffsets.quickImtConflictTrampoline).readPointer();
    const quickGenericJniTrampoline = classLinker.add(classLinkerOffsets.quickGenericJniTrampoline).readPointer();
    const quickToInterpreterBridgeTrampoline = classLinker.add(classLinkerOffsets.quickToInterpreterBridgeTrampoline).readPointer();

    temporaryApi.artClassLinker = {
      address: classLinker,
      quickResolutionTrampoline,
      quickImtConflictTrampoline,
      quickGenericJniTrampoline,
      quickToInterpreterBridgeTrampoline
    };

    const vm = new VM(temporaryApi);

    temporaryApi.artQuickGenericJniTrampoline = getArtQuickEntrypointFromTrampoline(quickGenericJniTrampoline, vm);
    temporaryApi.artQuickToInterpreterBridge = getArtQuickEntrypointFromTrampoline(quickToInterpreterBridgeTrampoline, vm);
    temporaryApi.artQuickResolutionTrampoline = getArtQuickEntrypointFromTrampoline(quickResolutionTrampoline, vm);

    if (temporaryApi['art::JavaVMExt::AddGlobalRef'] === undefined) {
      temporaryApi['art::JavaVMExt::AddGlobalRef'] = makeAddGlobalRefFallbackForAndroid5(temporaryApi);
    }
    if (temporaryApi['art::JavaVMExt::DecodeGlobal'] === undefined) {
      temporaryApi['art::JavaVMExt::DecodeGlobal'] = makeDecodeGlobalFallback(temporaryApi);
    }
    if (temporaryApi['art::ArtMethod::PrettyMethod'] === undefined) {
      temporaryApi['art::ArtMethod::PrettyMethod'] = temporaryApi['art::ArtMethod::PrettyMethodNullSafe'];
    }
    if (temporaryApi['art::interpreter::GetNterpEntryPoint'] !== undefined) {
      temporaryApi.artNterpEntryPoint = temporaryApi['art::interpreter::GetNterpEntryPoint']();
    } else {
      temporaryApi.artNterpEntryPoint = temporaryApi.find('ExecuteNterpImpl');
    }

    artController = makeArtController(temporaryApi, vm);

    fixupArtQuickDeliverExceptionBug(temporaryApi);

    let cachedJvmti = null;
    Object.defineProperty(temporaryApi, 'jvmti', {
      get () {
        if (cachedJvmti === null) {
          cachedJvmti = [tryGetEnvJvmti(vm, this.artRuntime)];
        }
        return cachedJvmti[0];
      }
    });
  }

  const cxxImports = vmModule.enumerateImports()
    .filter(imp => imp.name.indexOf('_Z') === 0)
    .reduce((result, imp) => {
      result[imp.name] = imp.address;
      return result;
    }, {});
  temporaryApi.$new = new NativeFunction(cxxImports._Znwm || cxxImports._Znwj, 'pointer', ['ulong'], nativeFunctionOptions);
  temporaryApi.$delete = new NativeFunction(cxxImports._ZdlPv, 'void', ['pointer'], nativeFunctionOptions);

  MethodMangler = isArt ? ArtMethodMangler : DalvikMethodMangler;

  return temporaryApi;
}

function tryGetEnvJvmti (vm, runtime) {
  let env = null;

  vm.perform(() => {
    const ensurePluginLoadedAddr = getApi().find('_ZN3art7Runtime18EnsurePluginLoadedEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE');
    if (ensurePluginLoadedAddr === null) {
      return;
    }
    const ensurePluginLoaded = new NativeFunction(ensurePluginLoadedAddr,
      'bool',
      ['pointer', 'pointer', 'pointer']);
    const errorPtr = Memory.alloc(pointerSize);
    const success = ensurePluginLoaded(runtime, Memory.allocUtf8String('libopenjdkjvmti.so'), errorPtr);
    if (!success) {
      // FIXME: Avoid leaking error
      return;
    }

    const kArtTiVersion = jvmtiVersion.v1_2 | 0x40000000;
    const handle = vm.tryGetEnvHandle(kArtTiVersion);
    if (handle === null) {
      return;
    }
    env = new EnvJvmti(handle, vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    if (result !== JNI_OK) {
      env = null;
    }
  });

  return env;
}

export function ensureClassInitialized (env, classRef) {
  const api = getApi();
  if (api.flavor !== 'art') {
    return;
  }

  env.getClassName(classRef);
}

function getArtVMSpec (api) {
  return {
    offset: (pointerSize === 4)
      ? {
          globalsLock: 32,
          globals: 72
        }
      : {
          globalsLock: 64,
          globals: 112
        }
  };
}

function _getArtRuntimeSpec (api) {
  /*
   * class Runtime {
   * ...
   * gc::Heap* heap_;                <-- we need to find this
   * std::unique_ptr<ArenaPool> jit_arena_pool_;     <----- API level >= 24
   * std::unique_ptr<ArenaPool> arena_pool_;             __
   * std::unique_ptr<ArenaPool> low_4gb_arena_pool_/linear_alloc_arena_pool_; <--|__ API level >= 23
   * std::unique_ptr<LinearAlloc> linear_alloc_;         \_
   * std::atomic<LinearAlloc*> startup_linear_alloc_;<----- API level >= 34
   * size_t max_spins_before_thin_lock_inflation_;
   * MonitorList* monitor_list_;
   * MonitorPool* monitor_pool_;
   * ThreadList* thread_list_;        <--- and these
   * InternTable* intern_table_;      <--/
   * ClassLinker* class_linker_;      <-/
   * SignalCatcher* signal_catcher_;
   * SmallIrtAllocator* small_irt_allocator_; <------------ API level >= 33 or Android Tiramisu Developer Preview
   * std::unique_ptr<jni::JniIdManager> jni_id_manager_; <- API level >= 30 or Android R Developer Preview
   * bool use_tombstoned_traces_;     <-------------------- API level 27/28
   * std::string stack_trace_file_;   <-------------------- API level <= 28
   * JavaVMExt* java_vm_;             <-- so we find this then calculate our way backwards
   * ...
   * }
   */

  const vm = api.vm;
  const runtime = api.artRuntime;

  const startOffset = (pointerSize === 4) ? 200 : 384;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();
  const codename = getAndroidCodename();
  const { isApiLevel34OrApexEquivalent } = api;

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = runtime.add(offset).readPointer();
    if (value.equals(vm)) {
      let classLinkerOffsets;
      let jniIdManagerOffset = null;
      if (apiLevel >= 33 || codename === 'Tiramisu' || isApiLevel34OrApexEquivalent) {
        classLinkerOffsets = [offset - (4 * pointerSize)];
        jniIdManagerOffset = offset - pointerSize;
      } else if (apiLevel >= 30 || codename === 'R') {
        classLinkerOffsets = [offset - (3 * pointerSize), offset - (4 * pointerSize)];
        jniIdManagerOffset = offset - pointerSize;
      } else if (apiLevel >= 29) {
        classLinkerOffsets = [offset - (2 * pointerSize)];
      } else if (apiLevel >= 27) {
        classLinkerOffsets = [offset - STD_STRING_SIZE - (3 * pointerSize)];
      } else {
        classLinkerOffsets = [offset - STD_STRING_SIZE - (2 * pointerSize)];
      }

      for (const classLinkerOffset of classLinkerOffsets) {
        const internTableOffset = classLinkerOffset - pointerSize;
        const threadListOffset = internTableOffset - pointerSize;

        let heapOffset;
        if (isApiLevel34OrApexEquivalent) {
          heapOffset = threadListOffset - (9 * pointerSize);
        } else if (apiLevel >= 24) {
          heapOffset = threadListOffset - (8 * pointerSize);
        } else if (apiLevel >= 23) {
          heapOffset = threadListOffset - (7 * pointerSize);
        } else {
          heapOffset = threadListOffset - (4 * pointerSize);
        }

        const candidate = {
          offset: {
            heap: heapOffset,
            threadList: threadListOffset,
            internTable: internTableOffset,
            classLinker: classLinkerOffset,
            jniIdManager: jniIdManagerOffset
          }
        };
        if (tryGetArtClassLinkerSpec(runtime, candidate) !== null) {
          spec = candidate;
          break;
        }
      }

      break;
    }
  }

  if (spec === null) {
    throw new Error('Unable to determine Runtime field offsets');
  }

  const instrumentationIsPointer = getArtApexVersion() >= 360_000_000;
  spec.offset.instrumentation = instrumentationIsPointer
    ? tryDetectInstrumentationPointer(api)
    : tryDetectInstrumentationOffset(api);

  spec.offset.jniIdsIndirection = tryDetectJniIdsIndirectionOffset(api);

  return spec;
}

const instrumentationOffsetParsers = {
  ia32: parsex86InstrumentationOffset,
  x64: parsex86InstrumentationOffset,
  arm: parseArmInstrumentationOffset,
  arm64: parseArm64InstrumentationOffset
};

function tryDetectInstrumentationOffset (api) {
  const impl = api['art::Runtime::DeoptimizeBootImage'];
  if (impl === undefined) {
    return null;
  }

  return parseInstructionsAt(impl, instrumentationOffsetParsers[Process.arch], { limit: 30 });
}

function parsex86InstrumentationOffset (insn) {
  if (insn.mnemonic !== 'lea') {
    return null;
  }

  const offset = insn.operands[1].value.disp;
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }

  return offset;
}

function parseArmInstrumentationOffset (insn) {
  if (insn.mnemonic !== 'add.w') {
    return null;
  }

  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }

  const op2 = ops[2];
  if (op2.type !== 'imm') {
    return null;
  }

  return op2.value;
}

function parseArm64InstrumentationOffset (insn) {
  if (insn.mnemonic !== 'add') {
    return null;
  }

  const ops = insn.operands;
  if (ops.length !== 3) {
    return null;
  }

  if (ops[0].value === 'sp' || ops[1].value === 'sp') {
    return null;
  }

  const op2 = ops[2];
  if (op2.type !== 'imm') {
    return null;
  }

  const offset = op2.value.valueOf();
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }

  return offset;
}

const instrumentationPointerParser = {
  ia32: parsex86InstrumentationPointer,
  x64: parsex86InstrumentationPointer,
  arm: parseArmInstrumentationPointer,
  arm64: parseArm64InstrumentationPointer
};

function tryDetectInstrumentationPointer (api) {
  const impl = api['art::Runtime::DeoptimizeBootImage'];
  if (impl === undefined) {
    return null;
  }

  return parseInstructionsAt(impl, instrumentationPointerParser[Process.arch], { limit: 30 });
}

function parsex86InstrumentationPointer (insn) {
  if (insn.mnemonic !== 'mov') {
    return null;
  }

  const ops = insn.operands;

  const dst = ops[0];
  if (dst.value !== 'rax') {
    return null;
  }

  const src = ops[1];
  if (src.type !== 'mem') {
    return null;
  }

  const mem = src.value;
  if (mem.base !== 'rdi') {
    return null;
  }

  const offset = mem.disp;
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }
  return offset;
}

function parseArmInstrumentationPointer (insn) {
  return null;
}

function parseArm64InstrumentationPointer (insn) {
  if (insn.mnemonic !== 'ldr') {
    return null;
  }

  const ops = insn.operands;

  if (ops[0].value === 'x0') {
    return null;
  }

  const mem = ops[1].value;
  if (mem.base !== 'x0') {
    return null;
  }

  const offset = mem.disp;
  if (offset < 0x100 || offset > 0x400) {
    return null;
  }
  return offset;
}

const jniIdsIndirectionOffsetParsers = {
  ia32: parsex86JniIdsIndirectionOffset,
  x64: parsex86JniIdsIndirectionOffset,
  arm: parseArmJniIdsIndirectionOffset,
  arm64: parseArm64JniIdsIndirectionOffset
};

function tryDetectJniIdsIndirectionOffset (api) {
  const impl = api.find('_ZN3art7Runtime12SetJniIdTypeENS_9JniIdTypeE');
  if (impl === null) {
    return null;
  }

  const offset = parseInstructionsAt(impl, jniIdsIndirectionOffsetParsers[Process.arch], { limit: 20 });
  if (offset === null) {
    throw new Error('Unable to determine Runtime.jni_ids_indirection_ offset');
  }

  return offset;
}

function parsex86JniIdsIndirectionOffset (insn) {
  if (insn.mnemonic === 'cmp') {
    return insn.operands[0].value.disp;
  }

  return null;
}

function parseArmJniIdsIndirectionOffset (insn) {
  if (insn.mnemonic === 'ldr.w') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function parseArm64JniIdsIndirectionOffset (insn, prevInsn) {
  if (prevInsn === null) {
    return null;
  }

  const { mnemonic } = insn;
  const { mnemonic: prevMnemonic } = prevInsn;

  if ((mnemonic === 'cmp' && prevMnemonic === 'ldr') || (mnemonic === 'bl' && prevMnemonic === 'str')) {
    return prevInsn.operands[1].value.disp;
  }

  return null;
}

function _getArtInstrumentationSpec () {
  const deoptimizationEnabledOffsets = {
    '4-21': 136,
    '4-22': 136,
    '4-23': 172,
    '4-24': 196,
    '4-25': 196,
    '4-26': 196,
    '4-27': 196,
    '4-28': 212,
    '4-29': 172,
    '4-30': 180,
    '4-31': 180,
    '8-21': 224,
    '8-22': 224,
    '8-23': 296,
    '8-24': 344,
    '8-25': 344,
    '8-26': 352,
    '8-27': 352,
    '8-28': 392,
    '8-29': 328,
    '8-30': 336,
    '8-31': 336
  };

  const deoptEnabledOffset = deoptimizationEnabledOffsets[`${pointerSize}-${getAndroidApiLevel()}`];
  if (deoptEnabledOffset === undefined) {
    throw new Error('Unable to determine Instrumentation field offsets');
  }

  return {
    offset: {
      forcedInterpretOnly: 4,
      deoptimizationEnabled: deoptEnabledOffset
    }
  };
}

function getArtClassLinkerSpec (runtime, runtimeSpec) {
  const spec = tryGetArtClassLinkerSpec(runtime, runtimeSpec);
  if (spec === null) {
    throw new Error('Unable to determine ClassLinker field offsets');
  }
  return spec;
}

function tryGetArtClassLinkerSpec (runtime, runtimeSpec) {
  if (cachedArtClassLinkerSpec !== null) {
    return cachedArtClassLinkerSpec;
  }

  /*
   * On Android 5.x:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* portable_resolution_trampoline_;
   * const void* quick_resolution_trampoline_;
   * const void* portable_imt_conflict_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   *
   * On Android 6.x and above:
   *
   * class ClassLinker {
   * ...
   * InternTable* intern_table_;                          <-- We find this then calculate our way forwards
   * const void* quick_resolution_trampoline_;
   * const void* quick_imt_conflict_trampoline_;
   * const void* quick_generic_jni_trampoline_;           <-- ...to this
   * const void* quick_to_interpreter_bridge_trampoline_;
   * ...
   * }
   */

  const { classLinker: classLinkerOffset, internTable: internTableOffset } = runtimeSpec.offset;
  const classLinker = runtime.add(classLinkerOffset).readPointer();
  const internTable = runtime.add(internTableOffset).readPointer();

  const startOffset = (pointerSize === 4) ? 100 : 200;
  const endOffset = startOffset + (100 * pointerSize);

  const apiLevel = getAndroidApiLevel();

  let spec = null;

  for (let offset = startOffset; offset !== endOffset; offset += pointerSize) {
    const value = classLinker.add(offset).readPointer();
    if (value.equals(internTable)) {
      let delta;
      if (apiLevel >= 30 || getAndroidCodename() === 'R') {
        delta = 6;
      } else if (apiLevel >= 29) {
        delta = 4;
      } else if (apiLevel >= 23) {
        delta = 3;
      } else {
        delta = 5;
      }

      const quickGenericJniTrampolineOffset = offset + (delta * pointerSize);

      let quickResolutionTrampolineOffset;
      if (apiLevel >= 23) {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (2 * pointerSize);
      } else {
        quickResolutionTrampolineOffset = quickGenericJniTrampolineOffset - (3 * pointerSize);
      }

      spec = {
        offset: {
          quickResolutionTrampoline: quickResolutionTrampolineOffset,
          quickImtConflictTrampoline: quickGenericJniTrampolineOffset - pointerSize,
          quickGenericJniTrampoline: quickGenericJniTrampolineOffset,
          quickToInterpreterBridgeTrampoline: quickGenericJniTrampolineOffset + pointerSize
        }
      };

      break;
    }
  }

  if (spec !== null) {
    cachedArtClassLinkerSpec = spec;
  }

  return spec;
}

export function getArtClassSpec (vm) {
  const MAX_OFFSET = 0x100;

  let spec = null;

  vm.perform(env => {
    const fieldSpec = getArtFieldSpec(vm);
    const methodSpec = getArtMethodSpec(vm);

    const fInfo = {
      artArrayLengthSize: 4,
      artArrayEntrySize: fieldSpec.size,
      // java/lang/Thread has 36 fields on Android 16.
      artArrayMax: 50
    };

    const mInfo = {
      artArrayLengthSize: pointerSize,
      artArrayEntrySize: methodSpec.size,
      // java/lang/Thread has 79 methods on Android 16.
      artArrayMax: 100
    };

    const readArtArray = (objectBase, fieldOffset, lengthSize) => {
      const header = objectBase.add(fieldOffset).readPointer();
      if (header.isNull()) {
        return null;
      }

      const length = (lengthSize === 4) ? header.readU32() : header.readU64().valueOf();
      if (length <= 0) {
        return null;
      }

      return {
        length,
        data: header.add(lengthSize)
      };
    };

    const hasEntry = (objectBase, offset, needle, info) => {
      try {
        const artArray = readArtArray(objectBase, offset, info.artArrayLengthSize);
        if (artArray === null) {
          return false;
        }

        const artArrayEnd = Math.min(artArray.length, info.artArrayMax);
        for (let i = 0; i !== artArrayEnd; i++) {
          const fieldPtr = artArray.data.add(i * info.artArrayEntrySize);
          if (fieldPtr.equals(needle)) {
            return true;
          }
        }
      } catch {
      }

      return false;
    };

    const clazz = env.findClass('java/lang/Thread');
    const clazzRef = env.newGlobalRef(clazz);

    try {
      let object;
      withRunnableArtThread(vm, env, thread => {
        object = getApi()['art::JavaVMExt::DecodeGlobal'](vm, thread, clazzRef);
      });

      const fieldInstance = unwrapFieldId(env.getFieldId(clazzRef, 'name', 'Ljava/lang/String;'));
      const fieldStatic = unwrapFieldId(env.getStaticFieldId(clazzRef, 'MAX_PRIORITY', 'I'));

      let offsetStatic = -1;
      let offsetInstance = -1;
      for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
        if (offsetStatic === -1 && hasEntry(object, offset, fieldStatic, fInfo)) {
          offsetStatic = offset;
        }
        if (offsetInstance === -1 && hasEntry(object, offset, fieldInstance, fInfo)) {
          offsetInstance = offset;
        }
      }
      if (offsetInstance === -1 || offsetStatic === -1) {
        throw new Error('Unable to find fields in java/lang/Thread; please file a bug');
      }
      const sfieldOffset = (offsetInstance !== offsetStatic) ? offsetStatic : 0;
      const ifieldOffset = offsetInstance;

      let offsetMethods = -1;
      const methodInstance = unwrapMethodId(env.getMethodId(clazzRef, 'getName', '()Ljava/lang/String;'));
      for (let offset = 0; offset !== MAX_OFFSET; offset += 4) {
        if (offsetMethods === -1 && hasEntry(object, offset, methodInstance, mInfo)) {
          offsetMethods = offset;
        }
      }
      if (offsetMethods === -1) {
        throw new Error('Unable to find methods in java/lang/Thread; please file a bug');
      }

      let offsetCopiedMethods = -1;
      const methodsArray = readArtArray(object, offsetMethods, mInfo.artArrayLengthSize);
      const methodsArraySize = methodsArray.length;
      for (let offset = offsetMethods; offset !== MAX_OFFSET; offset += 4) {
        if (object.add(offset).readU16() === methodsArraySize) {
          offsetCopiedMethods = offset;
          break;
        }
      }
      if (offsetCopiedMethods === -1) {
        throw new Error('Unable to find copied methods in java/lang/Thread; please file a bug');
      }

      spec = {
        offset: {
          ifields: ifieldOffset,
          methods: offsetMethods,
          sfields: sfieldOffset,
          copiedMethodsOffset: offsetCopiedMethods,
        }
      };
    } finally {
      env.deleteLocalRef(clazz);
      env.deleteGlobalRef(clazzRef);
    }
  });

  return spec;
}

function _getArtMethodSpec (vm) {
  const api = getApi();
  let spec;

  vm.perform(env => {
    const process = env.findClass('android/os/Process');
    const getElapsedCpuTime = unwrapMethodId(env.getStaticMethodId(process, 'getElapsedCpuTime', '()J'));
    env.deleteLocalRef(process);

    const runtimeModule = Process.getModuleByName('libandroid_runtime.so');
    const runtimeStart = runtimeModule.base;
    const runtimeEnd = runtimeStart.add(runtimeModule.size);

    const apiLevel = getAndroidApiLevel();

    const entrypointFieldSize = (apiLevel <= 21) ? 8 : pointerSize;

    const expectedAccessFlags = kAccPublic | kAccStatic | kAccFinal | kAccNative;
    const relevantAccessFlagsMask = ~(kAccFastInterpreterToInterpreterInvoke | kAccPublicApi | kAccNterpInvokeFastPathFlag) >>> 0;

    let jniCodeOffset = null;
    let accessFlagsOffset = null;
    let remaining = 2;
    for (let offset = 0; offset !== 64 && remaining !== 0; offset += 4) {
      const field = getElapsedCpuTime.add(offset);

      if (jniCodeOffset === null) {
        const address = field.readPointer();
        if (address.compare(runtimeStart) >= 0 && address.compare(runtimeEnd) < 0) {
          jniCodeOffset = offset;
          remaining--;
        }
      }

      if (accessFlagsOffset === null) {
        const flags = field.readU32();
        if ((flags & relevantAccessFlagsMask) === expectedAccessFlags) {
          accessFlagsOffset = offset;
          remaining--;
        }
      }
    }

    if (remaining !== 0) {
      throw new Error('Unable to determine ArtMethod field offsets');
    }

    const quickCodeOffset = jniCodeOffset + entrypointFieldSize;

    const size = (apiLevel <= 21) ? (quickCodeOffset + 32) : (quickCodeOffset + pointerSize);

    spec = {
      size,
      offset: {
        jniCode: jniCodeOffset,
        quickCode: quickCodeOffset,
        accessFlags: accessFlagsOffset
      }
    };

    if ('artInterpreterToCompiledCodeBridge' in api) {
      spec.offset.interpreterCode = jniCodeOffset - entrypointFieldSize;
    }
  });

  return spec;
}

export function getArtFieldSpec (vm) {
  const apiLevel = getAndroidApiLevel();

  if (apiLevel >= 23) {
    return {
      size: 16,
      offset: {
        accessFlags: 4
      }
    };
  }

  if (apiLevel >= 21) {
    return {
      size: 24,
      offset: {
        accessFlags: 12
      }
    };
  }

  return null;
}

function _getArtThreadSpec (vm) {
  /*
   * bool32_t is_exception_reported_to_instrumentation_; <-- We need this on API level <= 22
   * ...
   * mirror::Throwable* exception;                       <-- ...and this on all versions
   * uint8_t* stack_end;
   * ManagedStack managed_stack;
   * uintptr_t* suspend_trigger;
   * JNIEnvExt* jni_env;                                 <-- We find this then calculate our way backwards/forwards
   * JNIEnvExt* tmp_jni_env;                             <-- API level >= 23
   * Thread* self;
   * mirror::Object* opeer;
   * jobject jpeer;
   * uint8_t* stack_begin;
   * size_t stack_size;
   * ThrowLocation throw_location;                       <-- ...and this on API level <= 22
   * union DepsOrStackTraceSample {
   *   DepsOrStackTraceSample() {
   *     verifier_deps = nullptr;
   *     stack_trace_sample = nullptr;
   *   }
   *   std::vector<ArtMethod*>* stack_trace_sample;
   *   verifier::VerifierDeps* verifier_deps;
   * } deps_or_stack_trace_sample;
   * Thread* wait_next;
   * mirror::Object* monitor_enter_object;
   * BaseHandleScope* top_handle_scope;                  <-- ...and to this on all versions
   */

  const apiLevel = getAndroidApiLevel();

  let spec;

  vm.perform(env => {
    const threadHandle = getArtThreadFromEnv(env);
    const envHandle = env.handle;

    let isExceptionReportedOffset = null;
    let exceptionOffset = null;
    let throwLocationOffset = null;
    let topHandleScopeOffset = null;
    let managedStackOffset = null;
    let selfOffset = null;

    for (let offset = 144; offset !== 256; offset += pointerSize) {
      const field = threadHandle.add(offset);

      const value = field.readPointer();
      if (value.equals(envHandle)) {
        exceptionOffset = offset - (6 * pointerSize);
        managedStackOffset = offset - (4 * pointerSize);
        selfOffset = offset + (2 * pointerSize);
        if (apiLevel <= 22) {
          exceptionOffset -= pointerSize;

          isExceptionReportedOffset = exceptionOffset - pointerSize - (9 * 8) - (3 * 4);

          throwLocationOffset = offset + (6 * pointerSize);

          managedStackOffset -= pointerSize;

          selfOffset -= pointerSize;
        }

        topHandleScopeOffset = offset + (9 * pointerSize);
        if (apiLevel <= 22) {
          topHandleScopeOffset += (2 * pointerSize) + 4;
          if (pointerSize === 8) {
            topHandleScopeOffset += 4;
          }
        }
        if (apiLevel >= 23) {
          topHandleScopeOffset += pointerSize;
        }

        break;
      }
    }

    if (topHandleScopeOffset === null) {
      throw new Error('Unable to determine ArtThread field offsets');
    }

    spec = {
      offset: {
        isExceptionReportedToInstrumentation: isExceptionReportedOffset,
        exception: exceptionOffset,
        throwLocation: throwLocationOffset,
        topHandleScope: topHandleScopeOffset,
        managedStack: managedStackOffset,
        self: selfOffset
      }
    };
  });

  return spec;
}

function _getArtManagedStackSpec () {
  const apiLevel = getAndroidApiLevel();

  if (apiLevel >= 23) {
    return {
      offset: {
        topQuickFrame: 0,
        link: pointerSize
      }
    };
  } else {
    return {
      offset: {
        topQuickFrame: 2 * pointerSize,
        link: 0
      }
    };
  }
}

const artQuickTrampolineParsers = {
  ia32: parseArtQuickTrampolineX86,
  x64: parseArtQuickTrampolineX86,
  arm: parseArtQuickTrampolineArm,
  arm64: parseArtQuickTrampolineArm64
};

function getArtQuickEntrypointFromTrampoline (trampoline, vm) {
  let address;

  vm.perform(env => {
    const thread = getArtThreadFromEnv(env);

    const tryParse = artQuickTrampolineParsers[Process.arch];

    const insn = Instruction.parse(trampoline);

    const offset = tryParse(insn);
    if (offset !== null) {
      address = thread.add(offset).readPointer();
    } else {
      address = trampoline;
    }
  });

  return address;
}

function parseArtQuickTrampolineX86 (insn) {
  if (insn.mnemonic === 'jmp') {
    return insn.operands[0].value.disp;
  }

  return null;
}

function parseArtQuickTrampolineArm (insn) {
  if (insn.mnemonic === 'ldr.w') {
    return insn.operands[1].value.disp;
  }

  return null;
}

function parseArtQuickTrampolineArm64 (insn) {
  if (insn.mnemonic === 'ldr') {
    return insn.operands[1].value.disp;
  }

  return null;
}

export function getArtThreadFromEnv (env) {
  return env.handle.add(pointerSize).readPointer();
}

function _getAndroidVersion () {
  return getAndroidSystemProperty('ro.build.version.release');
}

function _getAndroidCodename () {
  return getAndroidSystemProperty('ro.build.version.codename');
}

function _getAndroidApiLevel () {
  return parseInt(getAndroidSystemProperty('ro.build.version.sdk'), 10);
}

function _getArtApexVersion () {
  try {
    const mountInfo = File.readAllText('/proc/self/mountinfo');

    let artSource = null;
    const sourceVersions = new Map();
    for (const line of mountInfo.trimEnd().split('\n')) {
      const elements = line.split(' ');

      const mountRoot = elements[4];
      if (!mountRoot.startsWith('/apex/com.android.art')) {
        continue;
      }

      const mountSource = elements[10];
      if (mountRoot.includes('@')) {
        sourceVersions.set(mountSource, mountRoot.split('@')[1]);
      } else {
        artSource = mountSource;
      }
    }

    const strVersion = sourceVersions.get(artSource);
    return (strVersion !== undefined) ? parseInt(strVersion) : computeArtApexVersionFromApiLevel();
  } catch {
    return computeArtApexVersionFromApiLevel();
  }
}

function computeArtApexVersionFromApiLevel () {
  return getAndroidApiLevel() * 10_000_000;
}

let systemPropertyGet = null;
const PROP_VALUE_MAX = 92;

function getAndroidSystemProperty (name) {
  if (systemPropertyGet === null) {
    systemPropertyGet = new NativeFunction(
      Process.getModuleByName('libc.so').getExportByName('__system_property_get'),
      'int',
      ['pointer', 'pointer'],
      nativeFunctionOptions);
  }
  const buf = Memory.alloc(PROP_VALUE_MAX);
  systemPropertyGet(Memory.allocUtf8String(name), buf);
  return buf.readUtf8String();
}

export function withRunnableArtThread (vm, env, fn) {
  const perform = getArtThreadStateTransitionImpl(vm, env);

  const id = getArtThreadFromEnv(env).toString();
  artThreadStateTransitions[id] = fn;

  perform(env.handle);

  if (artThreadStateTransitions[id] !== undefined) {
    delete artThreadStateTransitions[id];
    throw new Error('Unable to perform state transition; please file a bug');
  }
}

function _getArtThreadStateTransitionImpl (vm, env) {
  const callback = new NativeCallback(onThreadStateTransitionComplete, 'void', ['pointer']);
  return makeArtThreadStateTransitionImpl(vm, env, callback);
}

function onThreadStateTransitionComplete (thread) {
  const id = thread.toString();

  const fn = artThreadStateTransitions[id];
  delete artThreadStateTransitions[id];
  fn(thread);
}

export function withAllArtThreadsSuspended (fn) {
  const api = getApi();

  const threadList = api.artThreadList;
  const longSuspend = false;
  api['art::ThreadList::SuspendAll'](threadList, Memory.allocUtf8String('frida'), longSuspend ? 1 : 0);
  try {
    fn();
  } finally {
    api['art::ThreadList::ResumeAll'](threadList);
  }
}

class ArtClassVisitor {
  constructor (visit) {
    const visitor = Memory.alloc(4 * pointerSize);

    const vtable = visitor.add(pointerSize);
    visitor.writePointer(vtable);

    const onVisit = new NativeCallback((self, klass) => {
      return visit(klass) === true ? 1 : 0;
    }, 'bool', ['pointer', 'pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

export function makeArtClassVisitor (visit) {
  const api = getApi();

  if (api['art::ClassLinker::VisitClasses'] instanceof NativeFunction) {
    return new ArtClassVisitor(visit);
  }

  return new NativeCallback(klass => {
    return visit(klass) === true ? 1 : 0;
  }, 'bool', ['pointer', 'pointer']);
}

class ArtClassLoaderVisitor {
  constructor (visit) {
    const visitor = Memory.alloc(4 * pointerSize);

    const vtable = visitor.add(pointerSize);
    visitor.writePointer(vtable);

    const onVisit = new NativeCallback((self, klass) => {
      visit(klass);
    }, 'void', ['pointer', 'pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisit);

    this.handle = visitor;
    this._onVisit = onVisit;
  }
}

export function makeArtClassLoaderVisitor (visit) {
  return new ArtClassLoaderVisitor(visit);
}

const WalkKind = {
  'include-inlined-frames': 0,
  'skip-inlined-frames': 1
};

export class ArtStackVisitor {
  constructor (thread, context, walkKind, numFrames = 0, checkSuspended = true) {
    const api = getApi();

    const baseSize = 512; /* Up to 488 bytes on 64-bit Android Q. */
    const vtableSize = 3 * pointerSize;

    const visitor = Memory.alloc(baseSize + vtableSize);

    api['art::StackVisitor::StackVisitor'](visitor, thread, context, WalkKind[walkKind], numFrames,
      checkSuspended ? 1 : 0);

    const vtable = visitor.add(baseSize);
    visitor.writePointer(vtable);

    const onVisitFrame = new NativeCallback(this._visitFrame.bind(this), 'bool', ['pointer']);
    vtable.add(2 * pointerSize).writePointer(onVisitFrame);

    this.handle = visitor;
    this._onVisitFrame = onVisitFrame;

    const curShadowFrame = visitor.add((pointerSize === 4) ? 12 : 24);
    this._curShadowFrame = curShadowFrame;
    this._curQuickFrame = curShadowFrame.add(pointerSize);
    this._curQuickFramePc = curShadowFrame.add(2 * pointerSize);
    this._curOatQuickMethodHeader = curShadowFrame.add(3 * pointerSize);

    this._getMethodImpl = api['art::StackVisitor::GetMethod'];
    this._descLocImpl = api['art::StackVisitor::DescribeLocation'];
    this._getCQFIImpl = api['art::StackVisitor::GetCurrentQuickFrameInfo'];
  }

  walkStack (includeTransitions = false) {
    getApi()['art::StackVisitor::WalkStack'](this.handle, includeTransitions ? 1 : 0);
  }

  _visitFrame () {
    return this.visitFrame() ? 1 : 0;
  }

  visitFrame () {
    throw new Error('Subclass must implement visitFrame');
  }

  getMethod () {
    const methodHandle = this._getMethodImpl(this.handle);
    if (methodHandle.isNull()) {
      return null;
    }
    return new ArtMethod(methodHandle);
  }

  getCurrentQuickFramePc () {
    return this._curQuickFramePc.readPointer();
  }

  getCurrentQuickFrame () {
    return this._curQuickFrame.readPointer();
  }

  getCurrentShadowFrame () {
    return this._curShadowFrame.readPointer();
  }

  describeLocation () {
    const result = new StdString();
    this._descLocImpl(result, this.handle);
    return result.disposeToString();
  }

  getCurrentOatQuickMethodHeader () {
    return this._curOatQuickMethodHeader.readPointer();
  }

  getCurrentQuickFrameInfo () {
    return this._getCQFIImpl(this.handle);
  }
}

export class ArtMethod {
  constructor (handle) {
    this.handle = handle;
  }

  prettyMethod (withSignature = true) {
    const result = new StdString();
    getApi()['art::ArtMethod::PrettyMethod'](result, this.handle, withSignature ? 1 : 0);
    return result.disposeToString();
  }

  toString () {
    return `ArtMethod(handle=${this.handle})`;
  }
}

function makeArtQuickFrameInfoGetter (impl) {
  return function (self) {
    const result = Memory.alloc(12);

    getArtQuickFrameInfoGetterThunk(impl)(result, self);

    return {
      frameSizeInBytes: result.readU32(),
      coreSpillMask: result.add(4).readU32(),
      fpSpillMask: result.add(8).readU32()
    };
  };
}

function _getArtQuickFrameInfoGetterThunk (impl) {
  let thunk = NULL;
  switch (Process.arch) {
    case 'ia32':
      thunk = makeThunk(32, writer => {
        writer.putMovRegRegOffsetPtr('ecx', 'esp', 4); // result
        writer.putMovRegRegOffsetPtr('edx', 'esp', 8); // self
        writer.putCallAddressWithArguments(impl, ['ecx', 'edx']);

        // Restore callee's stack frame
        writer.putMovRegReg('esp', 'ebp');
        writer.putPopReg('ebp');

        writer.putRet();
      });
      break;
    case 'x64':
      thunk = makeThunk(32, writer => {
        writer.putPushReg('rdi'); // preserve result buffer pointer
        writer.putCallAddressWithArguments(impl, ['rsi']); // self
        writer.putPopReg('rdi');

        // Struct is stored by value in the rax and edx registers
        // Write struct to result buffer
        writer.putMovRegPtrReg('rdi', 'rax');
        writer.putMovRegOffsetPtrReg('rdi', 8, 'edx');

        writer.putRet();
      });
      break;
    case 'arm':
      thunk = makeThunk(16, writer => {
        // By calling convention, we pass a pointer for the result struct
        writer.putCallAddressWithArguments(impl, ['r0', 'r1']);
        writer.putPopRegs(['r0', 'lr']);
        writer.putMovRegReg('pc', 'lr');
      });
      break;
    case 'arm64':
      thunk = makeThunk(64, writer => {
        writer.putPushRegReg('x0', 'lr');
        writer.putCallAddressWithArguments(impl, ['x1']);
        writer.putPopRegReg('x2', 'lr');
        writer.putStrRegRegOffset('x0', 'x2', 0);
        writer.putStrRegRegOffset('w1', 'x2', 8);
        writer.putRet();
      });
      break;
  }
  return new NativeFunction(thunk, 'void', ['pointer', 'pointer'], nativeFunctionOptions);
}

const thunkRelocators = {
  ia32: globalThis.X86Relocator,
  x64: globalThis.X86Relocator,
  arm: globalThis.ThumbRelocator,
  arm64: globalThis.Arm64Relocator
};

const thunkWriters = {
  ia32: globalThis.X86Writer,
  x64: globalThis.X86Writer,
  arm: globalThis.ThumbWriter,
  arm64: globalThis.Arm64Writer
};

function makeThunk (size, write) {
  if (thunkPage === null) {
    thunkPage = Memory.alloc(Process.pageSize);
  }

  const thunk = thunkPage.add(thunkOffset);

  const arch = Process.arch;

  const Writer = thunkWriters[arch];
  Memory.patchCode(thunk, size, code => {
    const writer = new Writer(code, { pc: thunk });
    write(writer);
    writer.flush();
    if (writer.offset > size) {
      throw new Error(`Wrote ${writer.offset}, exceeding maximum of ${size}`);
    }
  });

  thunkOffset += size;

  return (arch === 'arm') ? thunk.or(1) : thunk;
}

function notifyArtMethodHooked (method, vm) {
  ensureArtKnowsHowToHandleMethodInstrumentation(vm);
  ensureArtKnowsHowToHandleReplacementMethods(vm);
}

function makeArtController (api, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const managedStackOffsets = getArtManagedStackSpec().offset;

  const code = `
#include <gum/guminterceptor.h>

extern GMutex lock;
extern GHashTable * methods;
extern GHashTable * replacements;
extern gpointer last_seen_art_method;

extern gpointer get_oat_quick_method_header_impl (gpointer method, gpointer pc);

void
init (void)
{
  g_mutex_init (&lock);
  methods = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  replacements = g_hash_table_new_full (NULL, NULL, NULL, NULL);
}

void
finalize (void)
{
  g_hash_table_unref (replacements);
  g_hash_table_unref (methods);
  g_mutex_clear (&lock);
}

gboolean
is_replacement_method (gpointer method)
{
  gboolean is_replacement;

  g_mutex_lock (&lock);

  is_replacement = g_hash_table_contains (replacements, method);

  g_mutex_unlock (&lock);

  return is_replacement;
}

gpointer
get_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);

  g_mutex_unlock (&lock);

  return replacement_method;
}

void
set_replacement_method (gpointer original_method,
                        gpointer replacement_method)
{
  g_mutex_lock (&lock);

  g_hash_table_insert (methods, original_method, replacement_method);
  g_hash_table_insert (replacements, replacement_method, original_method);

  g_mutex_unlock (&lock);
}

void
synchronize_replacement_methods (guint quick_code_offset,
                                 void * nterp_entrypoint,
                                 void * quick_to_interpreter_bridge)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
  {
    void ** quick_code;

    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

    quick_code = hooked_method + quick_code_offset;
    if (*quick_code == nterp_entrypoint)
      *quick_code = quick_to_interpreter_bridge;
  }

  g_mutex_unlock (&lock);
}

void
delete_replacement_method (gpointer original_method)
{
  gpointer replacement_method;

  g_mutex_lock (&lock);

  replacement_method = g_hash_table_lookup (methods, original_method);
  if (replacement_method != NULL)
  {
    g_hash_table_remove (methods, original_method);
    g_hash_table_remove (replacements, replacement_method);
  }

  g_mutex_unlock (&lock);
}

gpointer
translate_method (gpointer method)
{
  gpointer translated_method;

  g_mutex_lock (&lock);

  translated_method = g_hash_table_lookup (replacements, method);

  g_mutex_unlock (&lock);

  return (translated_method != NULL) ? translated_method : method;
}

gpointer
find_replacement_method_from_quick_code (gpointer method,
                                         gpointer thread)
{
  gpointer replacement_method;
  gpointer managed_stack;
  gpointer top_quick_frame;
  gpointer link_managed_stack;
  gpointer * link_top_quick_frame;

  replacement_method = get_replacement_method (method);
  if (replacement_method == NULL)
    return NULL;

  /*
   * Stack check.
   *
   * Return NULL to indicate that the original method should be invoked, otherwise
   * return a pointer to the replacement ArtMethod.
   *
   * If the caller is our own JNI replacement stub, then a stack transition must
   * have been pushed onto the current thread's linked list.
   *
   * Therefore, we invoke the original method if the following conditions are met:
   *   1- The current managed stack is empty.
   *   2- The ArtMethod * inside the linked managed stack's top quick frame is the
   *      same as our replacement.
   */
  managed_stack = thread + ${threadOffsets.managedStack};
  top_quick_frame = *((gpointer *) (managed_stack + ${managedStackOffsets.topQuickFrame}));
  if (top_quick_frame != NULL)
    return replacement_method;

  link_managed_stack = *((gpointer *) (managed_stack + ${managedStackOffsets.link}));
  if (link_managed_stack == NULL)
    return replacement_method;

  link_top_quick_frame = GSIZE_TO_POINTER (*((gsize *) (link_managed_stack + ${managedStackOffsets.topQuickFrame})) & ~((gsize) 1));
  if (link_top_quick_frame == NULL || *link_top_quick_frame != replacement_method)
    return replacement_method;

  return NULL;
}

void
on_interpreter_do_call (GumInvocationContext * ic)
{
  gpointer method, replacement_method;

  method = gum_invocation_context_get_nth_argument (ic, 0);

  replacement_method = get_replacement_method (method);
  if (replacement_method != NULL)
    gum_invocation_context_replace_nth_argument (ic, 0, replacement_method);
}

gpointer
on_art_method_get_oat_quick_method_header (gpointer method,
                                           gpointer pc)
{
  if (is_replacement_method (method))
    return NULL;

  return get_oat_quick_method_header_impl (method, pc);
}

void
on_art_method_pretty_method (GumInvocationContext * ic)
{
  const guint this_arg_index = ${(Process.arch === 'arm64') ? 0 : 1};
  gpointer method;

  method = gum_invocation_context_get_nth_argument (ic, this_arg_index);
  if (method == NULL)
    gum_invocation_context_replace_nth_argument (ic, this_arg_index, last_seen_art_method);
  else
    last_seen_art_method = method;
}

void
on_leave_gc_concurrent_copying_copying_phase (GumInvocationContext * ic)
{
  GHashTableIter iter;
  gpointer hooked_method, replacement_method;

  g_mutex_lock (&lock);

  g_hash_table_iter_init (&iter, methods);
  while (g_hash_table_iter_next (&iter, &hooked_method, &replacement_method))
    *((uint32_t *) replacement_method) = *((uint32_t *) hooked_method);

  g_mutex_unlock (&lock);
}
`;

  const lockSize = 8;
  const methodsSize = pointerSize;
  const replacementsSize = pointerSize;
  const lastSeenArtMethodSize = pointerSize;

  const data = Memory.alloc(lockSize + methodsSize + replacementsSize + lastSeenArtMethodSize);

  const lock = data;
  const methods = lock.add(lockSize);
  const replacements = methods.add(methodsSize);
  const lastSeenArtMethod = replacements.add(replacementsSize);

  const getOatQuickMethodHeaderImpl = api.find((pointerSize === 4)
    ? '_ZN3art9ArtMethod23GetOatQuickMethodHeaderEj'
    : '_ZN3art9ArtMethod23GetOatQuickMethodHeaderEm');

  const cm = new CModule(code, {
    lock,
    methods,
    replacements,
    last_seen_art_method: lastSeenArtMethod,
    get_oat_quick_method_header_impl: getOatQuickMethodHeaderImpl ?? ptr('0xdeadbeef')
  });

  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };

  return {
    handle: cm,
    replacedMethods: {
      isReplacement: new NativeFunction(cm.is_replacement_method, 'bool', ['pointer'], fastOptions),
      get: new NativeFunction(cm.get_replacement_method, 'pointer', ['pointer'], fastOptions),
      set: new NativeFunction(cm.set_replacement_method, 'void', ['pointer', 'pointer'], fastOptions),
      synchronize: new NativeFunction(cm.synchronize_replacement_methods, 'void', ['uint', 'pointer', 'pointer'], fastOptions),
      delete: new NativeFunction(cm.delete_replacement_method, 'void', ['pointer'], fastOptions),
      translate: new NativeFunction(cm.translate_method, 'pointer', ['pointer'], fastOptions),
      findReplacementFromQuickCode: cm.find_replacement_method_from_quick_code
    },
    getOatQuickMethodHeaderImpl,
    hooks: {
      Interpreter: {
        doCall: cm.on_interpreter_do_call
      },
      ArtMethod: {
        getOatQuickMethodHeader: cm.on_art_method_get_oat_quick_method_header,
        prettyMethod: cm.on_art_method_pretty_method
      },
      Gc: {
        copyingPhase: {
          onLeave: cm.on_leave_gc_concurrent_copying_copying_phase
        },
        runFlip: {
          onEnter: cm.on_leave_gc_concurrent_copying_copying_phase
        }
      }
    }
  };
}

function ensureArtKnowsHowToHandleMethodInstrumentation (vm) {
  if (taughtArtAboutMethodInstrumentation) {
    return;
  }
  taughtArtAboutMethodInstrumentation = true;

  instrumentArtQuickEntrypoints(vm);
  instrumentArtMethodInvocationFromInterpreter();
  instrumentArtGarbageCollection();
  instrumentArtFixupStaticTrampolines();
}

function instrumentArtQuickEntrypoints (vm) {
  const api = getApi();

  // Entrypoints that dispatch method invocation from the quick ABI.
  const quickEntrypoints = [
    api.artQuickGenericJniTrampoline,
    api.artQuickToInterpreterBridge,
    api.artQuickResolutionTrampoline
  ];

  quickEntrypoints.forEach(entrypoint => {
    Memory.protect(entrypoint, 32, 'rwx');

    const interceptor = new ArtQuickCodeInterceptor(entrypoint);
    interceptor.activate(vm);

    artQuickInterceptors.push(interceptor);
  });
}

function instrumentArtMethodInvocationFromInterpreter () {
  const api = getApi();

  const apiLevel = getAndroidApiLevel();
  const { isApiLevel34OrApexEquivalent } = api;

  let artInterpreterDoCallExportRegex;
  if (apiLevel <= 22) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_6mirror9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (apiLevel <= 33 && !isApiLevel34OrApexEquivalent) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]ELb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtPNS_6JValueE$/;
  } else if (isApiLevel34OrApexEquivalent) {
    artInterpreterDoCallExportRegex = /^_ZN3art11interpreter6DoCallILb[0-1]EEEbPNS_9ArtMethodEPNS_6ThreadERNS_11ShadowFrameEPKNS_11InstructionEtbPNS_6JValueE$/;
  } else {
    throw new Error('Unable to find method invocation in ART; please file a bug');
  }

  const art = api.module;
  const entries = [...art.enumerateExports(), ...art.enumerateSymbols()].filter(entry => artInterpreterDoCallExportRegex.test(entry.name));

  if (entries.length === 0) {
    throw new Error('Unable to find method invocation in ART; please file a bug');
  }

  for (const entry of entries) {
    Interceptor.attach(entry.address, artController.hooks.Interpreter.doCall);
  }
}

function instrumentArtGarbageCollection () {
  const api = getApi();
  const art = api.module;

  const gc = art.findSymbolByName('_ZN3art2gc4Heap22CollectGarbageInternalENS0_9collector6GcTypeENS0_7GcCauseEbj');
  if (gc === null) {
    return;
  }

  const { artNterpEntryPoint, artQuickToInterpreterBridge } = api;
  const quickCodeOffset = getArtMethodSpec(api.vm).offset.quickCode;
  Interceptor.attach(gc, {
    onLeave () {
      artController.replacedMethods.synchronize(quickCodeOffset, artNterpEntryPoint, artQuickToInterpreterBridge);
    }
  });
}

function instrumentArtFixupStaticTrampolines () {
  const patterns = [
    ['_ZN3art11ClassLinker26VisiblyInitializedCallback22MarkVisiblyInitializedEPNS_6ThreadE', 'e90340f8 : ff0ff0ff'],
    ['_ZN3art11ClassLinker26VisiblyInitializedCallback29AdjustThreadVisibilityCounterEPNS_6ThreadEl', '7f0f00f9 : 1ffcffff'],
  ];
  const api = getApi();
  const art = api.module;
  for (const [name, pattern] of patterns) {
    const base = art.findSymbolByName(name);
    if (base === null) {
      continue;
    }

    const matches = Memory.scanSync(base, 8192, pattern);
    if (matches.length === 0) {
      return;
    }

    const { artNterpEntryPoint, artQuickToInterpreterBridge } = api;
    const quickCodeOffset = getArtMethodSpec(api.vm).offset.quickCode;
    Interceptor.attach(matches[0].address, function () {
      artController.replacedMethods.synchronize(quickCodeOffset, artNterpEntryPoint, artQuickToInterpreterBridge);
    });

    return;
  }
}

function ensureArtKnowsHowToHandleReplacementMethods (vm) {
  if (taughtArtAboutReplacementMethods) {
    return;
  }
  taughtArtAboutReplacementMethods = true;

  if (!maybeInstrumentGetOatQuickMethodHeaderInlineCopies()) {
    const { getOatQuickMethodHeaderImpl } = artController;
    if (getOatQuickMethodHeaderImpl === null) {
      return;
    }

    try {
      Interceptor.replace(getOatQuickMethodHeaderImpl, artController.hooks.ArtMethod.getOatQuickMethodHeader);
    } catch (e) {
      /*
       * Already replaced by another script. For now we don't support replacing methods from multiple scripts,
       * but we'll allow users to try it if they're feeling adventurous.
       */
    }
  }

  const apiLevel = getAndroidApiLevel();

  let copyingPhase = null;
  const api = getApi();
  if (apiLevel > 28) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12CopyingPhaseEv');
  } else if (apiLevel > 22) {
    copyingPhase = api.find('_ZN3art2gc9collector17ConcurrentCopying12MarkingPhaseEv');
  }
  if (copyingPhase !== null) {
    Interceptor.attach(copyingPhase, artController.hooks.Gc.copyingPhase);
  }

  let runFlip = null;
  runFlip = api.find('_ZN3art6Thread15RunFlipFunctionEPS0_');
  if (runFlip === null) {
    runFlip = api.find('_ZN3art6Thread15RunFlipFunctionEPS0_b');
  }
  if (runFlip !== null) {
    Interceptor.attach(runFlip, artController.hooks.Gc.runFlip);
  }
}

const artGetOatQuickMethodHeaderInlinedCopyHandler = {
  arm: {
    signatures: [
      {
        pattern: [
          'b0 68', // ldr r0, [r6, #8]
          '01 30', // adds r0, #1
          '0c d0', // beq #0x16fcd4
          '1b 98', // ldr r0, [sp, #0x6c]
          ':',
          'c0 ff',
          'c0 ff',
          '00 ff',
          '00 2f'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          'd8 f8 08 00', // ldr r0, [r8, #8]
          '01 30', // adds r0, #1
          '0c d0', // beq #0x16fcd4
          '1b 98', // ldr r0, [sp, #0x6c]
          ':',
          'f0 ff ff 0f',
          'ff ff',
          '00 ff',
          '00 2f'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      },
      {
        pattern: [
          'b0 68', // ldr r0, [r6, #8]
          '01 30', // adds r0, #1
          '40 f0 c3 80', // bne #0x203bf0
          '00 25', // movs r5, #0
          ':',
          'c0 ff',
          'c0 ff',
          'c0 fb 00 d0',
          'ff f8'
        ],
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm
  },
  arm64: {
    signatures: [
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x23, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '40 01 00 54', // b.eq 0x2e4204
          '88 39 00 f0', // adrp x8, 0xa17000
          ':',
          /* 00 */ 'fc ff ff',
          '1f fc ff ff',
          '1f 00 00 ff',
          '00 00 00 9f'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      },
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x?, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '40 01 00 54', // b.eq <target>
          '00 0e 40 f9', // ldr x?, [x?, #0x18]
          ':',
          /* 00 */ 'fc ff ff',
          '1f fc ff ff',
          '1f 00 00 ff',
          '00 fc ff ff'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      },
      {
        pattern: [
          /* e8 */ '0a 40 b9', // ldr w8, [x23, #0x8]
          '1f 05 00 31', // cmn w8, #0x1
          '01 34 00 54', // b.ne 0x3d8e50
          'e0 03 1f aa', // mov x0, xzr
          ':',
          /* 00 */ 'fc ff ff',
          '1f fc ff ff',
          '1f 00 00 ff',
          'e0 ff ff ff'
        ],
        offset: 1,
        validateMatch: validateGetOatQuickMethodHeaderInlinedMatchArm64
      }
    ],
    instrument: instrumentGetOatQuickMethodHeaderInlinedCopyArm64
  }
};

function validateGetOatQuickMethodHeaderInlinedMatchArm ({ address, size }) {
  const ldr = Instruction.parse(address.or(1));
  const [ldrDst, ldrSrc] = ldr.operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = ldrDst.value;

  const branch = Instruction.parse(ldr.next.add(2));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = branch.address.add(branch.size);

  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === 'beq') {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }

  return parseInstructionsAt(targetWhenRegularMethod.or(1), tryParse, { limit: 3 });

  function tryParse (insn) {
    const { mnemonic } = insn;
    if (!(mnemonic === 'ldr' || mnemonic === 'ldr.w')) {
      return null;
    }

    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 0x14)) {
      return null;
    }

    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}

function validateGetOatQuickMethodHeaderInlinedMatchArm64 ({ address, size }) {
  const [ldrDst, ldrSrc] = Instruction.parse(address).operands;
  const methodReg = ldrSrc.value.base;
  const scratchReg = 'x' + ldrDst.value.substring(1);

  const branch = Instruction.parse(address.add(8));
  const targetWhenTrue = ptr(branch.operands[0].value);
  const targetWhenFalse = address.add(12);

  let targetWhenRegularMethod, targetWhenRuntimeMethod;
  if (branch.mnemonic === 'b.eq') {
    targetWhenRegularMethod = targetWhenFalse;
    targetWhenRuntimeMethod = targetWhenTrue;
  } else {
    targetWhenRegularMethod = targetWhenTrue;
    targetWhenRuntimeMethod = targetWhenFalse;
  }

  return parseInstructionsAt(targetWhenRegularMethod, tryParse, { limit: 3 });

  function tryParse (insn) {
    if (insn.mnemonic !== 'ldr') {
      return null;
    }

    const { base, disp } = insn.operands[1].value;
    if (!(base === methodReg && disp === 0x18)) {
      return null;
    }

    return {
      methodReg,
      scratchReg,
      target: {
        whenTrue: targetWhenTrue,
        whenRegularMethod: targetWhenRegularMethod,
        whenRuntimeMethod: targetWhenRuntimeMethod
      }
    };
  }
}

function maybeInstrumentGetOatQuickMethodHeaderInlineCopies () {
  if (getAndroidApiLevel() < 31) {
    return false;
  }

  const handler = artGetOatQuickMethodHeaderInlinedCopyHandler[Process.arch];
  if (handler === undefined) {
    // Not needed on x86 and x64, at least not for now...
    return false;
  }

  const signatures = handler.signatures.map(({ pattern, offset = 0, validateMatch = returnEmptyObject }) => {
    return {
      pattern: new MatchPattern(pattern.join('')),
      offset,
      validateMatch
    };
  });

  const impls = [];
  for (const { base, size } of getApi().module.enumerateRanges('--x')) {
    for (const { pattern, offset, validateMatch } of signatures) {
      const matches = Memory.scanSync(base, size, pattern)
        .map(({ address, size }) => {
          return { address: address.sub(offset), size: size + offset };
        })
        .filter(match => {
          const validationResult = validateMatch(match);
          if (validationResult === null) {
            return false;
          }
          match.validationResult = validationResult;
          return true;
        });
      impls.push(...matches);
    }
  }

  if (impls.length === 0) {
    return false;
  }

  impls.forEach(handler.instrument);

  return true;
}

function returnEmptyObject () {
  return {};
}

class InlineHook {
  constructor (address, size, trampoline) {
    this.address = address;
    this.size = size;
    this.originalCode = address.readByteArray(size);
    this.trampoline = trampoline;
  }

  revert () {
    Memory.patchCode(this.address, this.size, code => {
      code.writeByteArray(this.originalCode);
    });
  }
}

function instrumentGetOatQuickMethodHeaderInlinedCopyArm ({ address, size, validationResult }) {
  const { methodReg, target } = validationResult;

  const trampoline = Memory.alloc(Process.pageSize);
  let redirectCapacity = size;

  Memory.patchCode(trampoline, 256, code => {
    const writer = new ThumbWriter(code, { pc: trampoline });

    const relocator = new ThumbRelocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const vpushFpRegs = [0x2d, 0xed, 0x10, 0x0a]; /* vpush {s0-s15} */
    writer.putBytes(vpushFpRegs);

    const savedRegs = ['r0', 'r1', 'r2', 'r3'];
    writer.putPushRegs(savedRegs);

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegImm('r0', 0);

    writer.putPopRegs(savedRegs);

    const vpopFpRegs = [0xbd, 0xec, 0x10, 0x0a]; /* vpop {s0-s15} */
    writer.putBytes(vpopFpRegs);

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();

    const tailIsRegular = relocator.input.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    while (redirectCapacity < 10) {
      const offset = relocator.readOne();
      if (offset === 0) {
        redirectCapacity = 10;
        break;
      }
      redirectCapacity = offset;
    }
    relocator.writeAll();
    writer.putBranchAddress(address.add(redirectCapacity + 1));

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
  });

  inlineHooks.push(new InlineHook(address, redirectCapacity, trampoline));

  Memory.patchCode(address, redirectCapacity, code => {
    const writer = new ThumbWriter(code, { pc: address });
    writer.putLdrRegAddress('pc', trampoline.or(1));
    writer.flush();
  });
}

function instrumentGetOatQuickMethodHeaderInlinedCopyArm64 ({ address, size, validationResult }) {
  const { methodReg, scratchReg, target } = validationResult;

  const trampoline = Memory.alloc(Process.pageSize);

  Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });

    const relocator = new Arm64Relocator(address, writer);
    for (let i = 0; i !== 2; i++) {
      relocator.readOne();
    }
    relocator.writeAll();

    relocator.readOne();
    relocator.skipOne();
    writer.putBCondLabel('eq', 'runtime_or_replacement_method');

    const savedRegs = [
      'd0', 'd1',
      'd2', 'd3',
      'd4', 'd5',
      'd6', 'd7',
      'x0', 'x1',
      'x2', 'x3',
      'x4', 'x5',
      'x6', 'x7',
      'x8', 'x9',
      'x10', 'x11',
      'x12', 'x13',
      'x14', 'x15',
      'x16', 'x17'
    ];
    const numSavedRegs = savedRegs.length;

    for (let i = 0; i !== numSavedRegs; i += 2) {
      writer.putPushRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putCallAddressWithArguments(artController.replacedMethods.isReplacement, [methodReg]);
    writer.putCmpRegReg('x0', 'xzr');

    for (let i = numSavedRegs - 2; i >= 0; i -= 2) {
      writer.putPopRegReg(savedRegs[i], savedRegs[i + 1]);
    }

    writer.putBCondLabel('ne', 'runtime_or_replacement_method');
    writer.putBLabel('regular_method');

    relocator.readOne();
    const tailInstruction = relocator.input;

    const tailIsRegular = tailInstruction.address.equals(target.whenRegularMethod);

    writer.putLabel(tailIsRegular ? 'regular_method' : 'runtime_or_replacement_method');
    relocator.writeOne();
    writer.putBranchAddress(tailInstruction.next);

    writer.putLabel(tailIsRegular ? 'runtime_or_replacement_method' : 'regular_method');
    writer.putBranchAddress(target.whenTrue);

    writer.flush();
  });

  inlineHooks.push(new InlineHook(address, size, trampoline));

  Memory.patchCode(address, size, code => {
    const writer = new Arm64Writer(code, { pc: address });
    writer.putLdrRegAddress(scratchReg, trampoline);
    writer.putBrReg(scratchReg);
    writer.flush();
  });
}

export function makeMethodMangler (methodId) {
  return new MethodMangler(methodId);
}

export function translateMethod (methodId) {
  return artController.replacedMethods.translate(methodId);
}

export function backtrace (vm, options = {}) {
  const { limit = 16 } = options;

  const env = vm.getEnv();

  if (backtraceModule === null) {
    backtraceModule = makeBacktraceModule(vm, env);
  }

  return backtraceModule.backtrace(env, limit);
}

function makeBacktraceModule (vm, env) {
  const api = getApi();

  const performImpl = Memory.alloc(Process.pointerSize);

  const cm = new CModule(`
#include <glib.h>
#include <stdbool.h>
#include <string.h>
#include <gum/gumtls.h>
#include <json-glib/json-glib.h>

typedef struct _ArtBacktrace ArtBacktrace;
typedef struct _ArtStackFrame ArtStackFrame;

typedef struct _ArtStackVisitor ArtStackVisitor;
typedef struct _ArtStackVisitorVTable ArtStackVisitorVTable;

typedef struct _ArtClass ArtClass;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtThread ArtThread;
typedef struct _ArtContext ArtContext;

typedef struct _JNIEnv JNIEnv;

typedef struct _StdString StdString;
typedef struct _StdTinyString StdTinyString;
typedef struct _StdLargeString StdLargeString;

typedef enum {
  STACK_WALK_INCLUDE_INLINED_FRAMES,
  STACK_WALK_SKIP_INLINED_FRAMES,
} StackWalkKind;

struct _StdTinyString
{
  guint8 unused;
  gchar data[(3 * sizeof (gpointer)) - 1];
};

struct _StdLargeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

struct _StdString
{
  union
  {
    guint8 flags;
    StdTinyString tiny;
    StdLargeString large;
  };
};

struct _ArtBacktrace
{
  GChecksum * id;
  GArray * frames;
  gchar * frames_json;
};

struct _ArtStackFrame
{
  ArtMethod * method;
  gsize dexpc;
  StdString description;
};

struct _ArtStackVisitorVTable
{
  void (* unused1) (void);
  void (* unused2) (void);
  bool (* visit) (ArtStackVisitor * visitor);
};

struct _ArtStackVisitor
{
  ArtStackVisitorVTable * vtable;

  guint8 padding[512];

  ArtStackVisitorVTable vtable_storage;

  ArtBacktrace * backtrace;
};

struct _ArtMethod
{
  guint32 declaring_class;
  guint32 access_flags;
};

extern GumTlsKey current_backtrace;

extern void (* perform_art_thread_state_transition) (JNIEnv * env);

extern ArtContext * art_make_context (ArtThread * thread);

extern void art_stack_visitor_init (ArtStackVisitor * visitor, ArtThread * thread, void * context, StackWalkKind walk_kind,
    size_t num_frames, bool check_suspended);
extern void art_stack_visitor_walk_stack (ArtStackVisitor * visitor, bool include_transitions);
extern ArtMethod * art_stack_visitor_get_method (ArtStackVisitor * visitor);
extern void art_stack_visitor_describe_location (StdString * description, ArtStackVisitor * visitor);
extern ArtMethod * translate_method (ArtMethod * method);
extern void translate_location (ArtMethod * method, guint32 pc, const gchar ** source_file, gint32 * line_number);
extern void get_class_location (StdString * result, ArtClass * klass);
extern void cxx_delete (void * mem);
extern unsigned long strtoul (const char * str, char ** endptr, int base);

static bool visit_frame (ArtStackVisitor * visitor);
static void art_stack_frame_destroy (ArtStackFrame * frame);

static void append_jni_type_name (GString * s, const gchar * name, gsize length);

static void std_string_destroy (StdString * str);
static gchar * std_string_get_data (StdString * str);

void
init (void)
{
  current_backtrace = gum_tls_key_new ();
}

void
finalize (void)
{
  gum_tls_key_free (current_backtrace);
}

ArtBacktrace *
_create (JNIEnv * env,
         guint limit)
{
  ArtBacktrace * bt;

  bt = g_new (ArtBacktrace, 1);
  bt->id = g_checksum_new (G_CHECKSUM_SHA1);
  bt->frames = (limit != 0)
      ? g_array_sized_new (FALSE, FALSE, sizeof (ArtStackFrame), limit)
      : g_array_new (FALSE, FALSE, sizeof (ArtStackFrame));
  g_array_set_clear_func (bt->frames, (GDestroyNotify) art_stack_frame_destroy);
  bt->frames_json = NULL;

  gum_tls_key_set_value (current_backtrace, bt);

  perform_art_thread_state_transition (env);

  gum_tls_key_set_value (current_backtrace, NULL);

  return bt;
}

void
_on_thread_state_transition_complete (ArtThread * thread)
{
  ArtContext * context;
  ArtStackVisitor visitor = {
    .vtable_storage = {
      .visit = visit_frame,
    },
  };

  context = art_make_context (thread);

  art_stack_visitor_init (&visitor, thread, context, STACK_WALK_SKIP_INLINED_FRAMES, 0, true);
  visitor.vtable = &visitor.vtable_storage;
  visitor.backtrace = gum_tls_key_get_value (current_backtrace);

  art_stack_visitor_walk_stack (&visitor, false);

  cxx_delete (context);
}

static bool
visit_frame (ArtStackVisitor * visitor)
{
  ArtBacktrace * bt = visitor->backtrace;
  ArtStackFrame frame;
  const gchar * description, * dexpc_part;

  frame.method = art_stack_visitor_get_method (visitor);

  art_stack_visitor_describe_location (&frame.description, visitor);

  description = std_string_get_data (&frame.description);
  if (strstr (description, " '<") != NULL)
    goto skip;

  dexpc_part = strstr (description, " at dex PC 0x");
  if (dexpc_part == NULL)
    goto skip;
  frame.dexpc = strtoul (dexpc_part + 13, NULL, 16);

  g_array_append_val (bt->frames, frame);

  g_checksum_update (bt->id, (guchar *) &frame.method, sizeof (frame.method));
  g_checksum_update (bt->id, (guchar *) &frame.dexpc, sizeof (frame.dexpc));

  return true;

skip:
  std_string_destroy (&frame.description);
  return true;
}

static void
art_stack_frame_destroy (ArtStackFrame * frame)
{
  std_string_destroy (&frame->description);
}

void
_destroy (ArtBacktrace * backtrace)
{
  g_free (backtrace->frames_json);
  g_array_free (backtrace->frames, TRUE);
  g_checksum_free (backtrace->id);
  g_free (backtrace);
}

const gchar *
_get_id (ArtBacktrace * backtrace)
{
  return g_checksum_get_string (backtrace->id);
}

const gchar *
_get_frames (ArtBacktrace * backtrace)
{
  GArray * frames = backtrace->frames;
  JsonBuilder * b;
  guint i;
  JsonNode * root;

  if (backtrace->frames_json != NULL)
    return backtrace->frames_json;

  b = json_builder_new_immutable ();

  json_builder_begin_array (b);

  for (i = 0; i != frames->len; i++)
  {
    ArtStackFrame * frame = &g_array_index (frames, ArtStackFrame, i);
    gchar * description, * ret_type, * paren_open, * paren_close, * arg_types, * token, * method_name, * class_name;
    GString * signature;
    gchar * cursor;
    ArtMethod * translated_method;
    StdString location;
    gsize dexpc;
    const gchar * source_file;
    gint32 line_number;

    description = std_string_get_data (&frame->description);

    ret_type = strchr (description, '\\'') + 1;

    paren_open = strchr (ret_type, '(');
    paren_close = strchr (paren_open, ')');
    *paren_open = '\\0';
    *paren_close = '\\0';

    arg_types = paren_open + 1;

    token = strrchr (ret_type, '.');
    *token = '\\0';

    method_name = token + 1;

    token = strrchr (ret_type, ' ');
    *token = '\\0';

    class_name = token + 1;

    signature = g_string_sized_new (128);

    append_jni_type_name (signature, class_name, method_name - class_name - 1);
    g_string_append_c (signature, ',');
    g_string_append (signature, method_name);
    g_string_append (signature, ",(");

    if (arg_types != paren_close)
    {
      for (cursor = arg_types; cursor != NULL;)
      {
        gsize length;
        gchar * next;

        token = strstr (cursor, ", ");
        if (token != NULL)
        {
          length = token - cursor;
          next = token + 2;
        }
        else
        {
          length = paren_close - cursor;
          next = NULL;
        }

        append_jni_type_name (signature, cursor, length);

        cursor = next;
      }
    }

    g_string_append_c (signature, ')');

    append_jni_type_name (signature, ret_type, class_name - ret_type - 1);

    translated_method = translate_method (frame->method);
    dexpc = (translated_method == frame->method) ? frame->dexpc : 0;

    get_class_location (&location, GSIZE_TO_POINTER (translated_method->declaring_class));

    translate_location (translated_method, dexpc, &source_file, &line_number);

    json_builder_begin_object (b);

    json_builder_set_member_name (b, "signature");
    json_builder_add_string_value (b, signature->str);

    json_builder_set_member_name (b, "origin");
    json_builder_add_string_value (b, std_string_get_data (&location));

    json_builder_set_member_name (b, "className");
    json_builder_add_string_value (b, class_name);

    json_builder_set_member_name (b, "methodName");
    json_builder_add_string_value (b, method_name);

    json_builder_set_member_name (b, "methodFlags");
    json_builder_add_int_value (b, translated_method->access_flags);

    json_builder_set_member_name (b, "fileName");
    json_builder_add_string_value (b, source_file);

    json_builder_set_member_name (b, "lineNumber");
    json_builder_add_int_value (b, line_number);

    json_builder_end_object (b);

    std_string_destroy (&location);
    g_string_free (signature, TRUE);
  }

  json_builder_end_array (b);

  root = json_builder_get_root (b);
  backtrace->frames_json = json_to_string (root, FALSE);
  json_node_unref (root);

  return backtrace->frames_json;
}

static void
append_jni_type_name (GString * s,
                      const gchar * name,
                      gsize length)
{
  gchar shorty = '\\0';
  gsize i;

  switch (name[0])
  {
    case 'b':
      if (strncmp (name, "boolean", length) == 0)
        shorty = 'Z';
      else if (strncmp (name, "byte", length) == 0)
        shorty = 'B';
      break;
    case 'c':
      if (strncmp (name, "char", length) == 0)
        shorty = 'C';
      break;
    case 'd':
      if (strncmp (name, "double", length) == 0)
        shorty = 'D';
      break;
    case 'f':
      if (strncmp (name, "float", length) == 0)
        shorty = 'F';
      break;
    case 'i':
      if (strncmp (name, "int", length) == 0)
        shorty = 'I';
      break;
    case 'l':
      if (strncmp (name, "long", length) == 0)
        shorty = 'J';
      break;
    case 's':
      if (strncmp (name, "short", length) == 0)
        shorty = 'S';
      break;
    case 'v':
      if (strncmp (name, "void", length) == 0)
        shorty = 'V';
      break;
  }

  if (shorty != '\\0')
  {
    g_string_append_c (s, shorty);

    return;
  }

  if (length > 2 && name[length - 2] == '[' && name[length - 1] == ']')
  {
    g_string_append_c (s, '[');
    append_jni_type_name (s, name, length - 2);

    return;
  }

  g_string_append_c (s, 'L');

  for (i = 0; i != length; i++)
  {
    gchar ch = name[i];
    if (ch != '.')
      g_string_append_c (s, ch);
    else
      g_string_append_c (s, '/');
  }

  g_string_append_c (s, ';');
}

static void
std_string_destroy (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  if (is_large)
    cxx_delete (str->large.data);
}

static gchar *
std_string_get_data (StdString * str)
{
  bool is_large = (str->flags & 1) != 0;
  return is_large ? str->large.data : str->tiny.data;
}
`, {
    current_backtrace: Memory.alloc(Process.pointerSize),
    perform_art_thread_state_transition: performImpl,
    art_make_context: api['art::Thread::GetLongJumpContext'] ?? api['art::Context::Create'],
    art_stack_visitor_init: api['art::StackVisitor::StackVisitor'],
    art_stack_visitor_walk_stack: api['art::StackVisitor::WalkStack'],
    art_stack_visitor_get_method: api['art::StackVisitor::GetMethod'],
    art_stack_visitor_describe_location: api['art::StackVisitor::DescribeLocation'],
    translate_method: artController.replacedMethods.translate,
    translate_location: api['art::Monitor::TranslateLocation'],
    get_class_location: api['art::mirror::Class::GetLocation'],
    cxx_delete: api.$delete,
    strtoul: Process.getModuleByName('libc.so').getExportByName('strtoul')
  });

  const _create = new NativeFunction(cm._create, 'pointer', ['pointer', 'uint'], nativeFunctionOptions);
  const _destroy = new NativeFunction(cm._destroy, 'void', ['pointer'], nativeFunctionOptions);

  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };
  const _getId = new NativeFunction(cm._get_id, 'pointer', ['pointer'], fastOptions);
  const _getFrames = new NativeFunction(cm._get_frames, 'pointer', ['pointer'], fastOptions);

  const performThreadStateTransition = makeArtThreadStateTransitionImpl(vm, env, cm._on_thread_state_transition_complete);
  cm._performData = performThreadStateTransition;
  performImpl.writePointer(performThreadStateTransition);

  cm.backtrace = (env, limit) => {
    const handle = _create(env, limit);
    const bt = new Backtrace(handle);
    Script.bindWeak(bt, destroy.bind(null, handle));
    return bt;
  };

  function destroy (handle) {
    _destroy(handle);
  }

  cm.getId = handle => {
    return _getId(handle).readUtf8String();
  };

  cm.getFrames = handle => {
    return JSON.parse(_getFrames(handle).readUtf8String());
  };

  return cm;
}

class Backtrace {
  constructor (handle) {
    this.handle = handle;
  }

  get id () {
    return backtraceModule.getId(this.handle);
  }

  get frames () {
    return backtraceModule.getFrames(this.handle);
  }
}

export function revertGlobalPatches () {
  patchedClasses.forEach(entry => {
    entry.vtablePtr.writePointer(entry.vtable);
    entry.vtableCountPtr.writeS32(entry.vtableCount);
  });
  patchedClasses.clear();

  for (const interceptor of artQuickInterceptors.splice(0)) {
    interceptor.deactivate();
  }

  for (const hook of inlineHooks.splice(0)) {
    hook.revert();
  }
}

function unwrapMethodId (methodId) {
  return unwrapGenericId(methodId, 'art::jni::JniIdManager::DecodeMethodId');
}

function unwrapFieldId (fieldId) {
  return unwrapGenericId(fieldId, 'art::jni::JniIdManager::DecodeFieldId');
}

function unwrapGenericId (genericId, apiMethod) {
  const api = getApi();

  const runtimeOffset = getArtRuntimeSpec(api).offset;
  const jniIdManagerOffset = runtimeOffset.jniIdManager;
  const jniIdsIndirectionOffset = runtimeOffset.jniIdsIndirection;

  if (jniIdManagerOffset !== null && jniIdsIndirectionOffset !== null) {
    const runtime = api.artRuntime;

    const jniIdsIndirection = runtime.add(jniIdsIndirectionOffset).readInt();

    if (jniIdsIndirection !== kPointer) {
      const jniIdManager = runtime.add(jniIdManagerOffset).readPointer();
      return api[apiMethod](jniIdManager, genericId);
    }
  }

  return genericId;
}

const artQuickCodeReplacementTrampolineWriters = {
  ia32: writeArtQuickCodeReplacementTrampolineIA32,
  x64: writeArtQuickCodeReplacementTrampolineX64,
  arm: writeArtQuickCodeReplacementTrampolineArm,
  arm64: writeArtQuickCodeReplacementTrampolineArm64
};

function writeArtQuickCodeReplacementTrampolineIA32 (trampoline, target, redirectSize, constraints, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 128, code => {
    const writer = new X86Writer(code, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);

    const fxsave = [0x0f, 0xae, 0x04, 0x24]; /* fxsave [esp] */
    const fxrstor = [0x0f, 0xae, 0x0c, 0x24]; /* fxrstor [esp] */

    // Save core args & callee-saves.
    writer.putPushax();

    writer.putMovRegReg('ebp', 'esp');

    // Save FPRs + alignment padding.
    writer.putAndRegU32('esp', 0xfffffff0);
    writer.putSubRegImm('esp', 512);
    writer.putBytes(fxsave);

    writer.putMovRegFsU32Ptr('ebx', threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ['eax', 'ebx']);

    writer.putTestRegReg('eax', 'eax');
    writer.putJccShortLabel('je', 'restore_registers', 'no-hint');

    // Set value of eax in the current frame.
    writer.putMovRegOffsetPtrReg('ebp', 7 * 4, 'eax');

    writer.putLabel('restore_registers');

    // Restore FPRs.
    writer.putBytes(fxrstor);

    writer.putMovRegReg('esp', 'ebp');

    // Restore core args & callee-saves.
    writer.putPopax();

    writer.putJccShortLabel('jne', 'invoke_replacement', 'no-hint');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putJmpRegOffsetPtr('eax', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineX64 (trampoline, target, redirectSize, constraints, vm) {
  const threadOffsets = getArtThreadSpec(vm).offset;
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 256, code => {
    const writer = new X86Writer(code, { pc: trampoline });
    const relocator = new X86Relocator(target, writer);

    const fxsave = [0x0f, 0xae, 0x04, 0x24]; /* fxsave [rsp] */
    const fxrstor = [0x0f, 0xae, 0x0c, 0x24]; /* fxrstor [rsp] */

    // Save core args & callee-saves.
    writer.putPushax();

    writer.putMovRegReg('rbp', 'rsp');

    // Save FPRs + alignment padding.
    writer.putAndRegU32('rsp', 0xfffffff0);
    writer.putSubRegImm('rsp', 512);
    writer.putBytes(fxsave);

    writer.putMovRegGsU32Ptr('rbx', threadOffsets.self);
    writer.putCallAddressWithAlignedArguments(artController.replacedMethods.findReplacementFromQuickCode, ['rdi', 'rbx']);

    writer.putTestRegReg('rax', 'rax');
    writer.putJccShortLabel('je', 'restore_registers', 'no-hint');

    // Set value of rdi in the current frame.
    writer.putMovRegOffsetPtrReg('rbp', 8 * 8, 'rax');

    writer.putLabel('restore_registers');

    // Restore FPRs.
    writer.putBytes(fxrstor);

    writer.putMovRegReg('rsp', 'rbp');

    // Restore core args & callee-saves.
    writer.putPopax();

    writer.putJccShortLabel('jne', 'invoke_replacement', 'no-hint');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putJmpAddress(target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putJmpRegOffsetPtr('rdi', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineArm (trampoline, target, redirectSize, constraints, vm) {
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

  let offset;
  Memory.patchCode(trampoline, 128, code => {
    const writer = new ThumbWriter(code, { pc: trampoline });
    const relocator = new ThumbRelocator(targetAddress, writer);

    const vpushFpRegs = [0x2d, 0xed, 0x10, 0x0a]; /* vpush {s0-s15} */
    const vpopFpRegs = [0xbd, 0xec, 0x10, 0x0a]; /* vpop {s0-s15} */

    // Save core args, callee-saves, LR.
    writer.putPushRegs([
      'r1',
      'r2',
      'r3',
      'r5',
      'r6',
      'r7',
      'r8',
      'r10',
      'r11',
      'lr'
    ]);

    // Save FPRs.
    writer.putBytes(vpushFpRegs);

    // Save ArtMethod* + alignment padding.
    writer.putSubRegRegImm('sp', 'sp', 8);
    writer.putStrRegRegOffset('r0', 'sp', 0);

    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ['r0', 'r9']);

    writer.putCmpRegImm('r0', 0);
    writer.putBCondLabel('eq', 'restore_registers');

    // Set value of r0 in the current frame.
    writer.putStrRegRegOffset('r0', 'sp', 0);

    writer.putLabel('restore_registers');

    // Restore ArtMethod*
    writer.putLdrRegRegOffset('r0', 'sp', 0);
    writer.putAddRegRegImm('sp', 'sp', 8);

    // Restore FPRs.
    writer.putBytes(vpopFpRegs);

    // Restore LR, callee-saves & core args.
    writer.putPopRegs([
      'lr',
      'r11',
      'r10',
      'r8',
      'r7',
      'r6',
      'r5',
      'r3',
      'r2',
      'r1'
    ]);

    writer.putBCondLabel('ne', 'invoke_replacement');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      writer.putLdrRegAddress('pc', target.add(offset));
    }

    writer.putLabel('invoke_replacement');

    writer.putLdrRegRegOffset('pc', 'r0', artMethodOffsets.quickCode);

    writer.flush();
  });

  return offset;
}

function writeArtQuickCodeReplacementTrampolineArm64 (trampoline, target, redirectSize, { availableScratchRegs }, vm) {
  const artMethodOffsets = getArtMethodSpec(vm).offset;

  let offset;
  Memory.patchCode(trampoline, 256, code => {
    const writer = new Arm64Writer(code, { pc: trampoline });
    const relocator = new Arm64Relocator(target, writer);

    // Save FPRs.
    writer.putPushRegReg('d0', 'd1');
    writer.putPushRegReg('d2', 'd3');
    writer.putPushRegReg('d4', 'd5');
    writer.putPushRegReg('d6', 'd7');

    // Save core args, callee-saves & LR.
    writer.putPushRegReg('x1', 'x2');
    writer.putPushRegReg('x3', 'x4');
    writer.putPushRegReg('x5', 'x6');
    writer.putPushRegReg('x7', 'x20');
    writer.putPushRegReg('x21', 'x22');
    writer.putPushRegReg('x23', 'x24');
    writer.putPushRegReg('x25', 'x26');
    writer.putPushRegReg('x27', 'x28');
    writer.putPushRegReg('x29', 'lr');

    // Save ArtMethod* + alignment padding.
    writer.putSubRegRegImm('sp', 'sp', 16);
    writer.putStrRegRegOffset('x0', 'sp', 0);

    writer.putCallAddressWithArguments(artController.replacedMethods.findReplacementFromQuickCode, ['x0', 'x19']);

    writer.putCmpRegReg('x0', 'xzr');
    writer.putBCondLabel('eq', 'restore_registers');

    // Set value of x0 in the current frame.
    writer.putStrRegRegOffset('x0', 'sp', 0);

    writer.putLabel('restore_registers');

    // Restore ArtMethod*
    writer.putLdrRegRegOffset('x0', 'sp', 0);
    writer.putAddRegRegImm('sp', 'sp', 16);

    // Restore core args, callee-saves & LR.
    writer.putPopRegReg('x29', 'lr');
    writer.putPopRegReg('x27', 'x28');
    writer.putPopRegReg('x25', 'x26');
    writer.putPopRegReg('x23', 'x24');
    writer.putPopRegReg('x21', 'x22');
    writer.putPopRegReg('x7', 'x20');
    writer.putPopRegReg('x5', 'x6');
    writer.putPopRegReg('x3', 'x4');
    writer.putPopRegReg('x1', 'x2');

    // Restore FPRs.
    writer.putPopRegReg('d6', 'd7');
    writer.putPopRegReg('d4', 'd5');
    writer.putPopRegReg('d2', 'd3');
    writer.putPopRegReg('d0', 'd1');

    writer.putBCondLabel('ne', 'invoke_replacement');

    do {
      offset = relocator.readOne();
    } while (offset < redirectSize && !relocator.eoi);

    relocator.writeAll();

    if (!relocator.eoi) {
      const scratchReg = Array.from(availableScratchRegs)[0];
      writer.putLdrRegAddress(scratchReg, target.add(offset));
      writer.putBrReg(scratchReg);
    }

    writer.putLabel('invoke_replacement');

    writer.putLdrRegRegOffset('x16', 'x0', artMethodOffsets.quickCode);
    writer.putBrReg('x16');

    writer.flush();
  });

  return offset;
}

const artQuickCodePrologueWriters = {
  ia32: writeArtQuickCodePrologueX86,
  x64: writeArtQuickCodePrologueX86,
  arm: writeArtQuickCodePrologueArm,
  arm64: writeArtQuickCodePrologueArm64
};

function writeArtQuickCodePrologueX86 (target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, code => {
    const writer = new X86Writer(code, { pc: target });

    writer.putJmpAddress(trampoline);
    writer.flush();
  });
}

function writeArtQuickCodePrologueArm (target, trampoline, redirectSize) {
  const targetAddress = target.and(THUMB_BIT_REMOVAL_MASK);

  Memory.patchCode(targetAddress, 16, code => {
    const writer = new ThumbWriter(code, { pc: targetAddress });

    writer.putLdrRegAddress('pc', trampoline.or(1));
    writer.flush();
  });
}

function writeArtQuickCodePrologueArm64 (target, trampoline, redirectSize) {
  Memory.patchCode(target, 16, code => {
    const writer = new Arm64Writer(code, { pc: target });

    if (redirectSize === 16) {
      writer.putLdrRegAddress('x16', trampoline);
    } else {
      writer.putAdrpRegAddress('x16', trampoline);
    }

    writer.putBrReg('x16');

    writer.flush();
  });
}

const artQuickCodeHookRedirectSize = {
  ia32: 5,
  x64: 16,
  arm: 8,
  arm64: 16
};

class ArtQuickCodeInterceptor {
  constructor (quickCode) {
    this.quickCode = quickCode;
    this.quickCodeAddress = (Process.arch === 'arm')
      ? quickCode.and(THUMB_BIT_REMOVAL_MASK)
      : quickCode;

    this.redirectSize = 0;
    this.trampoline = null;
    this.overwrittenPrologue = null;
    this.overwrittenPrologueLength = 0;
  }

  _canRelocateCode (relocationSize, constraints) {
    const Writer = thunkWriters[Process.arch];
    const Relocator = thunkRelocators[Process.arch];

    const { quickCodeAddress } = this;

    const writer = new Writer(quickCodeAddress);
    const relocator = new Relocator(quickCodeAddress, writer);

    let offset;
    if (Process.arch === 'arm64') {
      let availableScratchRegs = new Set(['x16', 'x17']);

      do {
        const nextOffset = relocator.readOne();

        const nextScratchRegs = new Set(availableScratchRegs);
        const { read, written } = relocator.input.regsAccessed;
        for (const regs of [read, written]) {
          for (const reg of regs) {
            let name;
            if (reg.startsWith('w')) {
              name = 'x' + reg.substring(1);
            } else {
              name = reg;
            }
            nextScratchRegs.delete(name);
          }
        }
        if (nextScratchRegs.size === 0) {
          break;
        }

        offset = nextOffset;
        availableScratchRegs = nextScratchRegs;
      } while (offset < relocationSize && !relocator.eoi);

      constraints.availableScratchRegs = availableScratchRegs;
    } else {
      do {
        offset = relocator.readOne();
      } while (offset < relocationSize && !relocator.eoi);
    }

    return offset >= relocationSize;
  }

  _allocateTrampoline () {
    if (trampolineAllocator === null) {
      const trampolineSize = (pointerSize === 4) ? 128 : 256;
      trampolineAllocator = makeCodeAllocator(trampolineSize);
    }

    const maxRedirectSize = artQuickCodeHookRedirectSize[Process.arch];

    let redirectSize, spec;
    let alignment = 1;
    const constraints = {};
    if (pointerSize === 4 || this._canRelocateCode(maxRedirectSize, constraints)) {
      redirectSize = maxRedirectSize;

      spec = {};
    } else {
      let maxDistance;
      if (Process.arch === 'x64') {
        redirectSize = 5;
        maxDistance = X86_JMP_MAX_DISTANCE;
      } else if (Process.arch === 'arm64') {
        redirectSize = 8;
        maxDistance = ARM64_ADRP_MAX_DISTANCE;
        alignment = 4096;
      }

      spec = { near: this.quickCodeAddress, maxDistance };
    }

    this.redirectSize = redirectSize;
    this.trampoline = trampolineAllocator.allocateSlice(spec, alignment);

    return constraints;
  }

  _destroyTrampoline () {
    trampolineAllocator.freeSlice(this.trampoline);
  }

  activate (vm) {
    const constraints = this._allocateTrampoline();

    const { trampoline, quickCode, redirectSize } = this;

    const writeTrampoline = artQuickCodeReplacementTrampolineWriters[Process.arch];
    const prologueLength = writeTrampoline(trampoline, quickCode, redirectSize, constraints, vm);
    this.overwrittenPrologueLength = prologueLength;

    this.overwrittenPrologue = Memory.dup(this.quickCodeAddress, prologueLength);

    const writePrologue = artQuickCodePrologueWriters[Process.arch];
    writePrologue(quickCode, trampoline, redirectSize);
  }

  deactivate () {
    const { quickCodeAddress, overwrittenPrologueLength: prologueLength } = this;

    const Writer = thunkWriters[Process.arch];
    Memory.patchCode(quickCodeAddress, prologueLength, code => {
      const writer = new Writer(code, { pc: quickCodeAddress });

      const { overwrittenPrologue } = this;

      writer.putBytes(overwrittenPrologue.readByteArray(prologueLength));
      writer.flush();
    });

    this._destroyTrampoline();
  }
}

function isArtQuickEntrypoint (address) {
  const api = getApi();

  const { module: m, artClassLinker } = api;

  return address.equals(artClassLinker.quickGenericJniTrampoline) ||
      address.equals(artClassLinker.quickToInterpreterBridgeTrampoline) ||
      address.equals(artClassLinker.quickResolutionTrampoline) ||
      address.equals(artClassLinker.quickImtConflictTrampoline) ||
      (address.compare(m.base) >= 0 && address.compare(m.base.add(m.size)) < 0);
}

class ArtMethodMangler {
  constructor (opaqueMethodId) {
    const methodId = unwrapMethodId(opaqueMethodId);

    this.methodId = methodId;
    this.originalMethod = null;
    this.hookedMethodId = methodId;
    this.replacementMethodId = null;

    this.interceptor = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { kAccCompileDontBother, artNterpEntryPoint } = api;

    this.originalMethod = fetchArtMethod(this.methodId, vm);

    const originalFlags = this.originalMethod.accessFlags;

    if ((originalFlags & kAccXposedHookedMethod) !== 0 && xposedIsSupported()) {
      const hookInfo = this.originalMethod.jniCode;
      this.hookedMethodId = hookInfo.add(2 * pointerSize).readPointer();
      this.originalMethod = fetchArtMethod(this.hookedMethodId, vm);
    }

    const { hookedMethodId } = this;

    const replacementMethodId = cloneArtMethod(hookedMethodId, vm);
    this.replacementMethodId = replacementMethodId;

    patchArtMethod(replacementMethodId, {
      jniCode: impl,
      accessFlags: ((originalFlags & ~(kAccCriticalNative | kAccFastNative | kAccNterpEntryPointFastPathFlag)) | kAccNative | kAccCompileDontBother) >>> 0,
      quickCode: api.artClassLinker.quickGenericJniTrampoline,
      interpreterCode: api.artInterpreterToCompiledCodeBridge
    }, vm);

    // Remove kAccFastInterpreterToInterpreterInvoke and kAccSkipAccessChecks to disable use_fast_path
    // in interpreter_common.h
    let hookedMethodRemovedFlags = kAccFastInterpreterToInterpreterInvoke | kAccSingleImplementation | kAccNterpEntryPointFastPathFlag;
    if ((originalFlags & kAccNative) === 0) {
      hookedMethodRemovedFlags |= kAccSkipAccessChecks;
    }

    patchArtMethod(hookedMethodId, {
      accessFlags: ((originalFlags & ~(hookedMethodRemovedFlags)) | kAccCompileDontBother) >>> 0
    }, vm);

    const quickCode = this.originalMethod.quickCode;

    // Replace Nterp quick entrypoints with art_quick_to_interpreter_bridge to force stepping out
    // of ART's next-generation interpreter and use the quick stub instead.
    if (artNterpEntryPoint !== null && quickCode.equals(artNterpEntryPoint)) {
      patchArtMethod(hookedMethodId, {
        quickCode: api.artQuickToInterpreterBridge
      }, vm);
    }

    if (!isArtQuickEntrypoint(quickCode)) {
      const interceptor = new ArtQuickCodeInterceptor(quickCode);
      interceptor.activate(vm);

      this.interceptor = interceptor;
    }

    artController.replacedMethods.set(hookedMethodId, replacementMethodId);

    notifyArtMethodHooked(hookedMethodId, vm);
  }

  revert (vm) {
    const { hookedMethodId, interceptor } = this;

    patchArtMethod(hookedMethodId, this.originalMethod, vm);

    artController.replacedMethods.delete(hookedMethodId);

    if (interceptor !== null) {
      interceptor.deactivate();

      this.interceptor = null;
    }
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    return this.hookedMethodId;
  }
}

function xposedIsSupported () {
  return getAndroidApiLevel() < 28;
}

function fetchArtMethod (methodId, vm) {
  const artMethodSpec = getArtMethodSpec(vm);
  const artMethodOffset = artMethodSpec.offset;
  return (['jniCode', 'accessFlags', 'quickCode', 'interpreterCode']
    .reduce((original, name) => {
      const offset = artMethodOffset[name];
      if (offset === undefined) {
        return original;
      }
      const address = methodId.add(offset);
      const read = (name === 'accessFlags') ? readU32 : readPointer;
      original[name] = read.call(address);
      return original;
    }, {}));
}

function patchArtMethod (methodId, patches, vm) {
  const artMethodSpec = getArtMethodSpec(vm);
  const artMethodOffset = artMethodSpec.offset;
  Object.keys(patches).forEach(name => {
    const offset = artMethodOffset[name];
    if (offset === undefined) {
      return;
    }
    const address = methodId.add(offset);
    const write = (name === 'accessFlags') ? writeU32 : writePointer;
    write.call(address, patches[name]);
  });
}

class DalvikMethodMangler {
  constructor (methodId) {
    this.methodId = methodId;
    this.originalMethod = null;
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { methodId } = this;

    this.originalMethod = Memory.dup(methodId, DVM_METHOD_SIZE);

    let argsSize = argTypes.reduce((acc, t) => (acc + t.size), 0);
    if (isInstanceMethod) {
      argsSize++;
    }

    /*
     * make method native (with kAccNative)
     * insSize and registersSize are set to arguments size
     */
    const accessFlags = (methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).readU32() | kAccNative) >>> 0;
    const registersSize = argsSize;
    const outsSize = 0;
    const insSize = argsSize;

    methodId.add(DVM_METHOD_OFFSET_ACCESS_FLAGS).writeU32(accessFlags);
    methodId.add(DVM_METHOD_OFFSET_REGISTERS_SIZE).writeU16(registersSize);
    methodId.add(DVM_METHOD_OFFSET_OUTS_SIZE).writeU16(outsSize);
    methodId.add(DVM_METHOD_OFFSET_INS_SIZE).writeU16(insSize);
    methodId.add(DVM_METHOD_OFFSET_JNI_ARG_INFO).writeU32(computeDalvikJniArgInfo(methodId));

    api.dvmUseJNIBridge(methodId, impl);
  }

  revert (vm) {
    Memory.copy(this.methodId, this.originalMethod, DVM_METHOD_SIZE);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

    let objectPtr;
    if (isInstanceMethod) {
      objectPtr = api.dvmDecodeIndirectRef(thread, wrapper.$h);
    } else {
      const h = wrapper.$borrowClassHandle(env);
      objectPtr = api.dvmDecodeIndirectRef(thread, h.value);
      h.unref(env);
    }

    let classObject;
    if (isInstanceMethod) {
      classObject = objectPtr.add(DVM_OBJECT_OFFSET_CLAZZ).readPointer();
    } else {
      classObject = objectPtr;
    }

    const classKey = classObject.toString(16);
    let entry = patchedClasses.get(classKey);
    if (entry === undefined) {
      const vtablePtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE);
      const vtableCountPtr = classObject.add(DVM_CLASS_OBJECT_OFFSET_VTABLE_COUNT);
      const vtable = vtablePtr.readPointer();
      const vtableCount = vtableCountPtr.readS32();

      const vtableSize = vtableCount * pointerSize;
      const shadowVtable = Memory.alloc(2 * vtableSize);
      Memory.copy(shadowVtable, vtable, vtableSize);
      vtablePtr.writePointer(shadowVtable);

      entry = {
        classObject,
        vtablePtr,
        vtableCountPtr,
        vtable,
        vtableCount,
        shadowVtable,
        shadowVtableCount: vtableCount,
        targetMethods: new Map()
      };
      patchedClasses.set(classKey, entry);
    }

    const methodKey = this.methodId.toString(16);
    let targetMethod = entry.targetMethods.get(methodKey);
    if (targetMethod === undefined) {
      targetMethod = Memory.dup(this.originalMethod, DVM_METHOD_SIZE);

      const methodIndex = entry.shadowVtableCount++;
      entry.shadowVtable.add(methodIndex * pointerSize).writePointer(targetMethod);
      targetMethod.add(DVM_METHOD_OFFSET_METHOD_INDEX).writeU16(methodIndex);
      entry.vtableCountPtr.writeS32(entry.shadowVtableCount);

      entry.targetMethods.set(methodKey, targetMethod);
    }

    return targetMethod;
  }
}

function computeDalvikJniArgInfo (methodId) {
  if (Process.arch !== 'ia32') {
    return DALVIK_JNI_NO_ARG_INFO;
  }

  // For the x86 ABI, valid hints should always be generated.
  const shorty = methodId.add(DVM_METHOD_OFFSET_SHORTY).readPointer().readCString();
  if (shorty === null || shorty.length === 0 || shorty.length > 0xffff) {
    return DALVIK_JNI_NO_ARG_INFO;
  }

  let returnType;
  switch (shorty[0]) {
    case 'V':
      returnType = DALVIK_JNI_RETURN_VOID;
      break;
    case 'F':
      returnType = DALVIK_JNI_RETURN_FLOAT;
      break;
    case 'D':
      returnType = DALVIK_JNI_RETURN_DOUBLE;
      break;
    case 'J':
      returnType = DALVIK_JNI_RETURN_S8;
      break;
    case 'Z':
    case 'B':
      returnType = DALVIK_JNI_RETURN_S1;
      break;
    case 'C':
      returnType = DALVIK_JNI_RETURN_U2;
      break;
    case 'S':
      returnType = DALVIK_JNI_RETURN_S2;
      break;
    default:
      returnType = DALVIK_JNI_RETURN_S4;
      break;
  }

  let hints = 0;
  for (let i = shorty.length - 1; i > 0; i--) {
    const ch = shorty[i];
    hints += (ch === 'D' || ch === 'J') ? 2 : 1;
  }

  return (returnType << DALVIK_JNI_RETURN_SHIFT) | hints;
}

function cloneArtMethod (method, vm) {
  const api = getApi();

  if (getAndroidApiLevel() < 23) {
    const thread = api['art::Thread::CurrentFromGdb']();
    return api['art::mirror::Object::Clone'](method, thread);
  }

  return Memory.dup(method, getArtMethodSpec(vm).size);
}

export function deoptimizeMethod (vm, env, method) {
  requestDeoptimization(vm, env, kSelectiveDeoptimization, method);
}

export function deoptimizeEverything (vm, env) {
  requestDeoptimization(vm, env, kFullDeoptimization);
}

export function deoptimizeBootImage (vm, env) {
  const api = getApi();

  if (getAndroidApiLevel() < 26) {
    throw new Error('This API is only available on Android >= 8.0');
  }

  withRunnableArtThread(vm, env, thread => {
    api['art::Runtime::DeoptimizeBootImage'](api.artRuntime);
  });
}

function requestDeoptimization (vm, env, kind, method) {
  const api = getApi();

  if (getAndroidApiLevel() < 24) {
    throw new Error('This API is only available on Android >= 7.0');
  }

  withRunnableArtThread(vm, env, thread => {
    if (getAndroidApiLevel() < 30) {
      if (!api.isJdwpStarted()) {
        const session = startJdwp(api);
        jdwpSessions.push(session);
      }

      if (!api.isDebuggerActive()) {
        api['art::Dbg::GoActive']();
      }

      const request = Memory.alloc(8 + pointerSize);
      request.writeU32(kind);

      switch (kind) {
        case kFullDeoptimization:
          break;
        case kSelectiveDeoptimization:
          request.add(8).writePointer(method);
          break;
        default:
          throw new Error('Unsupported deoptimization kind');
      }

      api['art::Dbg::RequestDeoptimization'](request);

      api['art::Dbg::ManageDeoptimization']();
    } else {
      const instrumentation = api.artInstrumentation;
      if (instrumentation === null) {
        throw new Error('Unable to find Instrumentation class in ART; please file a bug');
      }

      const enableDeopt = api['art::Instrumentation::EnableDeoptimization'];
      if (enableDeopt !== undefined) {
        const deoptimizationEnabled = !!instrumentation.add(getArtInstrumentationSpec().offset.deoptimizationEnabled).readU8();
        if (!deoptimizationEnabled) {
          enableDeopt(instrumentation);
        }
      }

      switch (kind) {
        case kFullDeoptimization:
          api['art::Instrumentation::DeoptimizeEverything'](instrumentation, Memory.allocUtf8String('frida'));
          break;
        case kSelectiveDeoptimization:
          api['art::Instrumentation::Deoptimize'](instrumentation, method);
          break;
        default:
          throw new Error('Unsupported deoptimization kind');
      }
    }
  });
}

class JdwpSession {
  constructor () {
    /*
     * We partially stub out the ADB JDWP transport to ensure we always
     * succeed in starting JDWP. Failure will crash the process.
     */
    const libart = Process.getModuleByName('libart.so');
    const acceptImpl = libart.getExportByName('_ZN3art4JDWP12JdwpAdbState6AcceptEv');
    const receiveClientFdImpl = libart.getExportByName('_ZN3art4JDWP12JdwpAdbState15ReceiveClientFdEv');

    const controlPair = makeSocketPair();
    const clientPair = makeSocketPair();

    this._controlFd = controlPair[0];
    this._clientFd = clientPair[0];

    let acceptListener = null;
    acceptListener = Interceptor.attach(acceptImpl, function (args) {
      const state = args[0];

      const controlSockPtr = Memory.scanSync(state.add(8252), 256, '00 ff ff ff ff 00')[0].address.add(1);

      /*
       * This will make JdwpAdbState::Accept() skip the control socket() and connect(),
       * and skip right to calling ReceiveClientFd(), replaced below.
       */
      controlSockPtr.writeS32(controlPair[1]);

      acceptListener.detach();
    });

    Interceptor.replace(receiveClientFdImpl, new NativeCallback(function (state) {
      Interceptor.revert(receiveClientFdImpl);

      return clientPair[1];
    }, 'int', ['pointer']));

    Interceptor.flush();

    this._handshakeRequest = this._performHandshake();
  }

  async _performHandshake () {
    const input = new UnixInputStream(this._clientFd, { autoClose: false });
    const output = new UnixOutputStream(this._clientFd, { autoClose: false });

    const handshakePacket = [0x4a, 0x44, 0x57, 0x50, 0x2d, 0x48, 0x61, 0x6e, 0x64, 0x73, 0x68, 0x61, 0x6b, 0x65];
    try {
      await output.writeAll(handshakePacket);
      await input.readAll(handshakePacket.length);
    } catch (e) { /* empty */ }
  }
}

function startJdwp (api) {
  const session = new JdwpSession();

  api['art::Dbg::SetJdwpAllowed'](1);

  const options = makeJdwpOptions();
  api['art::Dbg::ConfigureJdwp'](options);

  const startDebugger = api['art::InternalDebuggerControlCallback::StartDebugger'];
  if (startDebugger !== undefined) {
    startDebugger(NULL);
  } else {
    api['art::Dbg::StartJdwp']();
  }

  return session;
}

function makeJdwpOptions () {
  const kJdwpTransportAndroidAdb = getAndroidApiLevel() < 28 ? 2 : 3;
  const kJdwpPortFirstAvailable = 0;

  const transport = kJdwpTransportAndroidAdb;
  const server = true;
  const suspend = false;
  const port = kJdwpPortFirstAvailable;

  const size = 8 + STD_STRING_SIZE + 2;
  const result = Memory.alloc(size);
  result
    .writeU32(transport).add(4)
    .writeU8(server ? 1 : 0).add(1)
    .writeU8(suspend ? 1 : 0).add(1)
    .add(STD_STRING_SIZE) // We leave `host` zeroed, i.e. empty string
    .writeU16(port);
  return result;
}

function makeSocketPair () {
  if (socketpair === null) {
    socketpair = new NativeFunction(
      Process.getModuleByName('libc.so').getExportByName('socketpair'),
      'int',
      ['int', 'int', 'int', 'pointer']);
  }

  const buf = Memory.alloc(8);
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, buf) === -1) {
    throw new Error('Unable to create socketpair for JDWP');
  }

  return [
    buf.readS32(),
    buf.add(4).readS32()
  ];
}

function makeAddGlobalRefFallbackForAndroid5 (api) {
  const offset = getArtVMSpec().offset;
  const lock = api.vm.add(offset.globalsLock);
  const table = api.vm.add(offset.globals);

  const add = api['art::IndirectReferenceTable::Add'];
  const acquire = api['art::ReaderWriterMutex::ExclusiveLock'];
  const release = api['art::ReaderWriterMutex::ExclusiveUnlock'];

  const IRT_FIRST_SEGMENT = 0;

  return function (vm, thread, obj) {
    acquire(lock, thread);
    try {
      return add(table, IRT_FIRST_SEGMENT, obj);
    } finally {
      release(lock, thread);
    }
  };
}

function makeDecodeGlobalFallback (api) {
  /*
   * Fallback for art::JavaVMExt::DecodeGlobal, which is
   * unavailable in Android versions <= 5 and >= 15.
   */
  const decode = api['art::Thread::DecodeJObject'];
  if (decode === undefined) {
    throw new Error('art::Thread::DecodeJObject is not available; please file a bug');
  }

  return function (vm, thread, ref) {
    return decode(thread, ref);
  };
}

/*
 * In order to call internal ART APIs we need to transition our native thread's
 * art::Thread to the proper state. The ScopedObjectAccess (SOA) helper that ART
 * uses internally is what we would like to use to accomplish this goal.
 *
 * There is however a challenge. The SOA implementation is fully inlined, so
 * we cannot just allocate a chunk of memory and call its constructor and
 * destructor to get the desired setup and teardown.
 *
 * We could however precompile such code using a C++ compiler, but considering
 * how many versions of ART we would need to compile it for, multiplied by the
 * number of supported architectures, we really don't want to go there.
 *
 * Reimplementing it in JavaScript is not desirable either, as we would need
 * to keep track of even more internals prone to change as ART evolves.
 *
 * So our least terrible option is to find a really simple C++ method in ART
 * that sets up a SOA object, performs as few and distinct operations as
 * possible, and then returns. If we clone that implementation we can swap
 * out the few/distinct operations with our own.
 *
 * We can accomplish this by using Frida's relocator API, and detecting the
 * few/distinct operations happening between setup and teardown of the scope.
 * We skip those when making our copy and instead put a call to a NativeCallback
 * there. Our NativeCallback is thus able to call internal ART APIs safely.
 *
 * The ExceptionClear() implementation that's part of the JNIEnv's vtable is
 * a perfect fit, as all it does is clear one field of the art::Thread.
 * (Except on older versions where it also clears a bit more... but still
 * pretty simple.)
 *
 * However, checked JNI might be enabled, making ExceptionClear() a bit more
 * complex, and essentially a wrapper around the unchecked version.
 *
 * One last thing to note is that we also look up the address of FatalError(),
 * as ExceptionClear() typically ends with a __stack_chk_fail() noreturn call
 * that's followed by the next JNIEnv vtable method, FatalError(). We don't want
 * to recompile its code as well, so we try to detect it. There might however be
 * padding between the two functions, which we need to ignore. Ideally we would
 * know that the call is to __stack_chk_fail(), so we can stop at that point,
 * but detecting that isn't trivial.
 */

const threadStateTransitionRecompilers = {
  ia32: recompileExceptionClearForX86,
  x64: recompileExceptionClearForX86,
  arm: recompileExceptionClearForArm,
  arm64: recompileExceptionClearForArm64
};

function makeArtThreadStateTransitionImpl (vm, env, callback) {
  const api = getApi();
  const envVtable = env.handle.readPointer();

  let exceptionClearImpl;
  const innerExceptionClearImpl = api.find('_ZN3art3JNIILb1EE14ExceptionClearEP7_JNIEnv');
  if (innerExceptionClearImpl !== null) {
    exceptionClearImpl = innerExceptionClearImpl;
  } else {
    exceptionClearImpl = envVtable.add(ENV_VTABLE_OFFSET_EXCEPTION_CLEAR).readPointer();
  }

  let nextFuncImpl;
  const innerNextFuncImpl = api.find('_ZN3art3JNIILb1EE10FatalErrorEP7_JNIEnvPKc');
  if (innerNextFuncImpl !== null) {
    nextFuncImpl = innerNextFuncImpl;
  } else {
    nextFuncImpl = envVtable.add(ENV_VTABLE_OFFSET_FATAL_ERROR).readPointer();
  }

  const recompile = threadStateTransitionRecompilers[Process.arch];
  if (recompile === undefined) {
    throw new Error('Not yet implemented for ' + Process.arch);
  }

  let perform = null;

  const threadOffsets = getArtThreadSpec(vm).offset;

  const exceptionOffset = threadOffsets.exception;

  const neuteredOffsets = new Set();
  const isReportedOffset = threadOffsets.isExceptionReportedToInstrumentation;
  if (isReportedOffset !== null) {
    neuteredOffsets.add(isReportedOffset);
  }
  const throwLocationStartOffset = threadOffsets.throwLocation;
  if (throwLocationStartOffset !== null) {
    neuteredOffsets.add(throwLocationStartOffset);
    neuteredOffsets.add(throwLocationStartOffset + pointerSize);
    neuteredOffsets.add(throwLocationStartOffset + (2 * pointerSize));
  }

  const codeSize = 65536;
  const code = Memory.alloc(codeSize);
  Memory.patchCode(code, codeSize, buffer => {
    perform = recompile(buffer, code, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback);
  });

  perform._code = code;
  perform._callback = callback;

  return perform;
}

function recompileExceptionClearForX86 (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const blockAddressKey = current.toString();

    let block = {
      begin: current
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      const insn = Instruction.parse(current);
      lastInsn = insn;

      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      let branchTarget = null;
      switch (insn.mnemonic) {
        case 'jmp':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new X86Writer(buffer, { pc });

  let foundCore = false;
  let threadReg = null;

  blocksOrdered.forEach(block => {
    const size = block.end.sub(block.begin).toInt32();

    const relocator = new X86Relocator(block.begin, writer);

    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;

      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'jmp':
          writer.putJmpNearLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'je':
        case 'jg':
        case 'jle':
        case 'jne':
        case 'js':
          writer.putJccNearLabel(mnemonic, branchLabelFromOperand(insn.operands[0]), 'no-hint');
          keep = false;
          break;
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'mov': {
          const [dst, src] = insn.operands;

          if (dst.type === 'mem' && src.type === 'imm') {
            const dstValue = dst.value;
            const dstOffset = dstValue.disp;

            if (dstOffset === exceptionOffset && src.value.valueOf() === 0) {
              threadReg = dstValue.base;

              writer.putPushfx();
              writer.putPushax();
              writer.putMovRegReg('xbp', 'xsp');
              if (pointerSize === 4) {
                writer.putAndRegU32('esp', 0xfffffff0);
              } else {
                const scratchReg = (threadReg !== 'rdi') ? 'rdi' : 'rsi';
                writer.putMovRegU64(scratchReg, uint64('0xfffffffffffffff0'));
                writer.putAndRegReg('rsp', scratchReg);
              }
              writer.putCallAddressWithAlignedArguments(callback, [threadReg]);
              writer.putMovRegReg('xsp', 'xbp');
              writer.putPopax();
              writer.putPopfx();

              foundCore = true;
              keep = false;
            } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
              keep = false;
            }
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'call': {
          const target = insn.operands[0];
          if (target.type === 'mem' && target.value.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            /*
             * Get art::Thread * from JNIEnv *
             */
            if (pointerSize === 4) {
              writer.putPopReg('eax');
              writer.putMovRegRegOffsetPtr('eax', 'eax', 4);
              writer.putPushReg('eax');
            } else {
              writer.putMovRegRegOffsetPtr('rdi', 'rdi', 8);
            }

            writer.putCallAddressWithArguments(callback, []);

            foundCore = true;
            keep = false;
          }

          break;
        }
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }

      if (offset === size) {
        break;
      }
    }

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const thumbBitRemovalMask = ptr(1).not();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const begin = current.and(thumbBitRemovalMask);
    const blockId = begin.toString();
    const thumbBit = current.and(1);

    let block = {
      begin
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    let ifThenBlockRemaining = 0;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      const insn = Instruction.parse(current);
      const { mnemonic } = insn;
      lastInsn = insn;

      const currentAddress = current.and(thumbBitRemovalMask);
      const insnId = currentAddress.toString();

      const existingBlock = blocks[insnId];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockId] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      const isOutsideIfThenBlock = ifThenBlockRemaining === 0;

      let branchTarget = null;

      switch (mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = isOutsideIfThenBlock;
          break;
        case 'beq.w':
        case 'beq':
        case 'bne':
        case 'bne.w':
        case 'bgt':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;
        case 'pop.w':
          if (isOutsideIfThenBlock) {
            reachedEndOfBlock = insn.operands.filter(op => op.value === 'pc').length === 1;
          }
          break;
      }

      switch (mnemonic) {
        case 'it':
          ifThenBlockRemaining = 1;
          break;
        case 'itt':
          ifThenBlockRemaining = 2;
          break;
        case 'ittt':
          ifThenBlockRemaining = 3;
          break;
        case 'itttt':
          ifThenBlockRemaining = 4;
          break;
        default:
          if (ifThenBlockRemaining > 0) {
            ifThenBlockRemaining--;
          }
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget.or(thumbBit));
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockId] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.and(thumbBitRemovalMask).toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new ThumbWriter(buffer, { pc });

  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;

  blocksOrdered.forEach(block => {
    const relocator = new ThumbRelocator(block.begin, writer);

    let address = block.begin;
    const end = block.end;
    let size = 0;
    do {
      const offset = relocator.readOne();
      if (offset === 0) {
        throw new Error('Unexpected end of block');
      }
      const insn = relocator.input;
      address = insn.address;
      size = insn.size;
      const { mnemonic } = insn;

      const insnAddressId = address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'beq.w':
          writer.putBCondLabelWide('eq', branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'bne.w':
          writer.putBCondLabelWide('ne', branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'beq':
        case 'bne':
        case 'bgt':
          writer.putBCondLabelWide(mnemonic.substr(1), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'cbz': {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'cbnz': {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'str':
        case 'str.w': {
          const dstValue = insn.operands[1].value;
          const dstOffset = dstValue.disp;

          if (dstOffset === exceptionOffset) {
            threadReg = dstValue.base;

            const nzcvqReg = (threadReg !== 'r4') ? 'r4' : 'r5';
            const clobberedRegs = ['r0', 'r1', 'r2', 'r3', nzcvqReg, 'r9', 'r12', 'lr'];

            writer.putPushRegs(clobberedRegs);
            writer.putMrsRegReg(nzcvqReg, 'apsr-nzcvq');

            writer.putCallAddressWithArguments(callback, [threadReg]);

            writer.putMsrRegReg('apsr-nzcvq', nzcvqReg);
            writer.putPopRegs(clobberedRegs);

            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'ldr': {
          const [dstOp, srcOp] = insn.operands;

          if (srcOp.type === 'mem') {
            const src = srcOp.value;

            if (src.base[0] === 'r' && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
              realImplReg = dstOp.value;
            }
          }

          break;
        }
        case 'blx':
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset('r0', 'r0', 4); // Get art::Thread * from JNIEnv *
            writer.putCallAddressWithArguments(callback, ['r0']);

            foundCore = true;
            realImplReg = null;
            keep = false;
          }

          break;
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }
    } while (!address.add(size).equals(end));

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc.or(1), 'void', ['pointer'], nativeFunctionOptions);
}

function recompileExceptionClearForArm64 (buffer, pc, exceptionClearImpl, nextFuncImpl, exceptionOffset, neuteredOffsets, callback) {
  const blocks = {};
  const branchTargets = new Set();

  const pending = [exceptionClearImpl];
  while (pending.length > 0) {
    let current = pending.shift();

    const alreadyCovered = Object.values(blocks).some(({ begin, end }) => current.compare(begin) >= 0 && current.compare(end) < 0);
    if (alreadyCovered) {
      continue;
    }

    const blockAddressKey = current.toString();

    let block = {
      begin: current
    };
    let lastInsn = null;

    let reachedEndOfBlock = false;
    do {
      if (current.equals(nextFuncImpl)) {
        reachedEndOfBlock = true;
        break;
      }

      let insn;
      try {
        insn = Instruction.parse(current);
      } catch (e) {
        if (current.readU32() === 0x00000000) {
          reachedEndOfBlock = true;
          break;
        } else {
          throw e;
        }
      }
      lastInsn = insn;

      const existingBlock = blocks[insn.address.toString()];
      if (existingBlock !== undefined) {
        delete blocks[existingBlock.begin.toString()];
        blocks[blockAddressKey] = existingBlock;
        existingBlock.begin = block.begin;
        block = null;
        break;
      }

      let branchTarget = null;
      switch (insn.mnemonic) {
        case 'b':
          branchTarget = ptr(insn.operands[0].value);
          reachedEndOfBlock = true;
          break;
        case 'b.eq':
        case 'b.ne':
        case 'b.le':
        case 'b.gt':
          branchTarget = ptr(insn.operands[0].value);
          break;
        case 'cbz':
        case 'cbnz':
          branchTarget = ptr(insn.operands[1].value);
          break;
        case 'tbz':
        case 'tbnz':
          branchTarget = ptr(insn.operands[2].value);
          break;
        case 'ret':
          reachedEndOfBlock = true;
          break;
      }

      if (branchTarget !== null) {
        branchTargets.add(branchTarget.toString());

        pending.push(branchTarget);
        pending.sort((a, b) => a.compare(b));
      }

      current = insn.next;
    } while (!reachedEndOfBlock);

    if (block !== null) {
      block.end = lastInsn.address.add(lastInsn.size);
      blocks[blockAddressKey] = block;
    }
  }

  const blocksOrdered = Object.keys(blocks).map(key => blocks[key]);
  blocksOrdered.sort((a, b) => a.begin.compare(b.begin));

  const entryBlock = blocks[exceptionClearImpl.toString()];
  blocksOrdered.splice(blocksOrdered.indexOf(entryBlock), 1);
  blocksOrdered.unshift(entryBlock);

  const writer = new Arm64Writer(buffer, { pc });

  writer.putBLabel('performTransition');

  const invokeCallback = pc.add(writer.offset);
  writer.putPushAllXRegisters();
  writer.putCallAddressWithArguments(callback, ['x0']);
  writer.putPopAllXRegisters();
  writer.putRet();

  writer.putLabel('performTransition');

  let foundCore = false;
  let threadReg = null;
  let realImplReg = null;

  blocksOrdered.forEach(block => {
    const size = block.end.sub(block.begin).toInt32();

    const relocator = new Arm64Relocator(block.begin, writer);

    let offset;
    while ((offset = relocator.readOne()) !== 0) {
      const insn = relocator.input;
      const { mnemonic } = insn;

      const insnAddressId = insn.address.toString();
      if (branchTargets.has(insnAddressId)) {
        writer.putLabel(insnAddressId);
      }

      let keep = true;

      switch (mnemonic) {
        case 'b':
          writer.putBLabel(branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'b.eq':
        case 'b.ne':
        case 'b.le':
        case 'b.gt':
          writer.putBCondLabel(mnemonic.substr(2), branchLabelFromOperand(insn.operands[0]));
          keep = false;
          break;
        case 'cbz': {
          const ops = insn.operands;
          writer.putCbzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'cbnz': {
          const ops = insn.operands;
          writer.putCbnzRegLabel(ops[0].value, branchLabelFromOperand(ops[1]));
          keep = false;
          break;
        }
        case 'tbz': {
          const ops = insn.operands;
          writer.putTbzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        case 'tbnz': {
          const ops = insn.operands;
          writer.putTbnzRegImmLabel(ops[0].value, ops[1].value.valueOf(), branchLabelFromOperand(ops[2]));
          keep = false;
          break;
        }
        /*
         * JNI::ExceptionClear(), when checked JNI is off.
         */
        case 'str': {
          const ops = insn.operands;
          const srcReg = ops[0].value;
          const dstValue = ops[1].value;
          const dstOffset = dstValue.disp;

          if (srcReg === 'xzr' && dstOffset === exceptionOffset) {
            threadReg = dstValue.base;

            writer.putPushRegReg('x0', 'lr');
            writer.putMovRegReg('x0', threadReg);
            writer.putBlImm(invokeCallback);
            writer.putPopRegReg('x0', 'lr');

            foundCore = true;
            keep = false;
          } else if (neuteredOffsets.has(dstOffset) && dstValue.base === threadReg) {
            keep = false;
          }

          break;
        }
        /*
         * CheckJNI::ExceptionClear, when checked JNI is on. Wrapper that calls JNI::ExceptionClear().
         */
        case 'ldr': {
          const ops = insn.operands;

          const src = ops[1].value;
          if (src.base[0] === 'x' && src.disp === ENV_VTABLE_OFFSET_EXCEPTION_CLEAR) {
            realImplReg = ops[0].value;
          }

          break;
        }
        case 'blr':
          if (insn.operands[0].value === realImplReg) {
            writer.putLdrRegRegOffset('x0', 'x0', 8); // Get art::Thread * from JNIEnv *
            writer.putCallAddressWithArguments(callback, ['x0']);

            foundCore = true;
            realImplReg = null;
            keep = false;
          }

          break;
      }

      if (keep) {
        relocator.writeAll();
      } else {
        relocator.skipOne();
      }

      if (offset === size) {
        break;
      }
    }

    relocator.dispose();
  });

  writer.dispose();

  if (!foundCore) {
    throwThreadStateTransitionParseError();
  }

  return new NativeFunction(pc, 'void', ['pointer'], nativeFunctionOptions);
}

function throwThreadStateTransitionParseError () {
  throw new Error('Unable to parse ART internals; please file a bug');
}

function fixupArtQuickDeliverExceptionBug (api) {
  const prettyMethod = api['art::ArtMethod::PrettyMethod'];
  if (prettyMethod === undefined) {
    return;
  }

  /*
   * There is a bug in art::Thread::QuickDeliverException() where it assumes
   * there is a Java stack frame present on the art::Thread's stack. This is
   * not the case if a native thread calls a throwing method like FindClass().
   *
   * We work around this bug here by detecting when method->PrettyMethod()
   * happens with method == nullptr.
   */
  Interceptor.attach(prettyMethod.impl, artController.hooks.ArtMethod.prettyMethod);
  Interceptor.flush();
}

function branchLabelFromOperand (op) {
  return ptr(op.value).toString();
}

function makeCxxMethodWrapperReturningPointerByValueGeneric (address, argTypes) {
  return new NativeFunction(address, 'pointer', argTypes, nativeFunctionOptions);
}

function makeCxxMethodWrapperReturningPointerByValueInFirstArg (address, argTypes) {
  const impl = new NativeFunction(address, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
  return function () {
    const resultPtr = Memory.alloc(pointerSize);
    impl(resultPtr, ...arguments);
    return resultPtr.readPointer();
  };
}

function makeCxxMethodWrapperReturningStdStringByValue (impl, argTypes) {
  const { arch } = Process;
  switch (arch) {
    case 'ia32':
    case 'arm64': {
      let thunk;
      if (arch === 'ia32') {
        thunk = makeThunk(64, writer => {
          const argCount = 1 + argTypes.length;
          const argvSize = argCount * 4;
          writer.putSubRegImm('esp', argvSize);
          for (let i = 0; i !== argCount; i++) {
            const offset = i * 4;
            writer.putMovRegRegOffsetPtr('eax', 'esp', argvSize + 4 + offset);
            writer.putMovRegOffsetPtrReg('esp', offset, 'eax');
          }
          writer.putCallAddress(impl);
          writer.putAddRegImm('esp', argvSize - 4);
          writer.putRet();
        });
      } else {
        thunk = makeThunk(32, writer => {
          writer.putMovRegReg('x8', 'x0');
          argTypes.forEach((t, i) => {
            writer.putMovRegReg('x' + i, 'x' + (i + 1));
          });
          writer.putLdrRegAddress('x7', impl);
          writer.putBrReg('x7');
        });
      }

      const invokeThunk = new NativeFunction(thunk, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
      const wrapper = function (...args) {
        invokeThunk(...args);
      };
      wrapper.handle = thunk;
      wrapper.impl = impl;
      return wrapper;
    }
    default: {
      const result = new NativeFunction(impl, 'void', ['pointer'].concat(argTypes), nativeFunctionOptions);
      result.impl = impl;
      return result;
    }
  }
}

class StdString {
  constructor () {
    this.handle = Memory.alloc(STD_STRING_SIZE);
  }

  dispose () {
    const [data, isTiny] = this._getData();
    if (!isTiny) {
      getApi().$delete(data);
    }
  }

  disposeToString () {
    const result = this.toString();
    this.dispose();
    return result;
  }

  toString () {
    const [data] = this._getData();
    return data.readUtf8String();
  }

  _getData () {
    const str = this.handle;
    const isTiny = (str.readU8() & 1) === 0;
    const data = isTiny ? str.add(1) : str.add(2 * pointerSize).readPointer();
    return [data, isTiny];
  }
}

class StdVector {
  $delete () {
    this.dispose();
    getApi().$delete(this);
  }

  constructor (storage, elementSize) {
    this.handle = storage;

    this._begin = storage;
    this._end = storage.add(pointerSize);
    this._storage = storage.add(2 * pointerSize);

    this._elementSize = elementSize;
  }

  init () {
    this.begin = NULL;
    this.end = NULL;
    this.storage = NULL;
  }

  dispose () {
    getApi().$delete(this.begin);
  }

  get begin () {
    return this._begin.readPointer();
  }

  set begin (value) {
    this._begin.writePointer(value);
  }

  get end () {
    return this._end.readPointer();
  }

  set end (value) {
    this._end.writePointer(value);
  }

  get storage () {
    return this._storage.readPointer();
  }

  set storage (value) {
    this._storage.writePointer(value);
  }

  get size () {
    return this.end.sub(this.begin).toInt32() / this._elementSize;
  }
}

export class HandleVector extends StdVector {
  static $new () {
    const vector = new HandleVector(getApi().$new(STD_VECTOR_SIZE));
    vector.init();
    return vector;
  }

  constructor (storage) {
    super(storage, pointerSize);
  }

  get handles () {
    const result = [];

    let cur = this.begin;
    const end = this.end;
    while (!cur.equals(end)) {
      result.push(cur.readPointer());
      cur = cur.add(pointerSize);
    }

    return result;
  }
}

const BHS_OFFSET_LINK = 0;
const BHS_OFFSET_NUM_REFS = pointerSize;
const BHS_SIZE = BHS_OFFSET_NUM_REFS + 4;

const kNumReferencesVariableSized = -1;

class BaseHandleScope {
  $delete () {
    this.dispose();
    getApi().$delete(this);
  }

  constructor (storage) {
    this.handle = storage;

    this._link = storage.add(BHS_OFFSET_LINK);
    this._numberOfReferences = storage.add(BHS_OFFSET_NUM_REFS);
  }

  init (link, numberOfReferences) {
    this.link = link;
    this.numberOfReferences = numberOfReferences;
  }

  dispose () {
  }

  get link () {
    return new BaseHandleScope(this._link.readPointer());
  }

  set link (value) {
    this._link.writePointer(value);
  }

  get numberOfReferences () {
    return this._numberOfReferences.readS32();
  }

  set numberOfReferences (value) {
    this._numberOfReferences.writeS32(value);
  }
}

const VSHS_OFFSET_SELF = alignPointerOffset(BHS_SIZE);
const VSHS_OFFSET_CURRENT_SCOPE = VSHS_OFFSET_SELF + pointerSize;
const VSHS_SIZE = VSHS_OFFSET_CURRENT_SCOPE + pointerSize;

export class VariableSizedHandleScope extends BaseHandleScope {
  static $new (thread, vm) {
    const scope = new VariableSizedHandleScope(getApi().$new(VSHS_SIZE));
    scope.init(thread, vm);
    return scope;
  }

  constructor (storage) {
    super(storage);

    this._self = storage.add(VSHS_OFFSET_SELF);
    this._currentScope = storage.add(VSHS_OFFSET_CURRENT_SCOPE);

    const kLocalScopeSize = 64;
    const kSizeOfReferencesPerScope = kLocalScopeSize - pointerSize - 4 - 4;
    const kNumReferencesPerScope = kSizeOfReferencesPerScope / 4;
    this._scopeLayout = FixedSizeHandleScope.layoutForCapacity(kNumReferencesPerScope);
    this._topHandleScopePtr = null;
  }

  init (thread, vm) {
    const topHandleScopePtr = thread.add(getArtThreadSpec(vm).offset.topHandleScope);
    this._topHandleScopePtr = topHandleScopePtr;

    super.init(topHandleScopePtr.readPointer(), kNumReferencesVariableSized);

    this.self = thread;
    this.currentScope = FixedSizeHandleScope.$new(this._scopeLayout);

    topHandleScopePtr.writePointer(this);
  }

  dispose () {
    this._topHandleScopePtr.writePointer(this.link);

    let scope;
    while ((scope = this.currentScope) !== null) {
      const next = scope.link;
      scope.$delete();
      this.currentScope = next;
    }
  }

  get self () {
    return this._self.readPointer();
  }

  set self (value) {
    this._self.writePointer(value);
  }

  get currentScope () {
    const storage = this._currentScope.readPointer();
    if (storage.isNull()) {
      return null;
    }
    return new FixedSizeHandleScope(storage, this._scopeLayout);
  }

  set currentScope (value) {
    this._currentScope.writePointer(value);
  }

  newHandle (object) {
    return this.currentScope.newHandle(object);
  }
}

class FixedSizeHandleScope extends BaseHandleScope {
  static $new (layout) {
    const scope = new FixedSizeHandleScope(getApi().$new(layout.size), layout);
    scope.init();
    return scope;
  }

  constructor (storage, layout) {
    super(storage);

    const { offset } = layout;
    this._refsStorage = storage.add(offset.refsStorage);
    this._pos = storage.add(offset.pos);

    this._layout = layout;
  }

  init () {
    super.init(NULL, this._layout.numberOfReferences);

    this.pos = 0;
  }

  get pos () {
    return this._pos.readU32();
  }

  set pos (value) {
    this._pos.writeU32(value);
  }

  newHandle (object) {
    const pos = this.pos;
    const handle = this._refsStorage.add(pos * 4);
    handle.writeS32(object.toInt32());
    this.pos = pos + 1;
    return handle;
  }

  static layoutForCapacity (numRefs) {
    const refsStorage = BHS_SIZE;
    const pos = refsStorage + (numRefs * 4);

    return {
      size: pos + 4,
      numberOfReferences: numRefs,
      offset: {
        refsStorage,
        pos
      }
    };
  }
}

const objectVisitorPredicateFactories = {
  arm: function (needle, onMatch) {
    const size = Process.pageSize;

    const predicate = Memory.alloc(size);

    Memory.protect(predicate, size, 'rwx');

    const onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
    predicate._onMatchCallback = onMatchCallback;

    const instructions = [
      0x6801, // ldr r1, [r0]
      0x4a03, // ldr r2, =needle
      0x4291, // cmp r1, r2
      0xd101, // bne mismatch
      0x4b02, // ldr r3, =onMatch
      0x4718, // bx r3
      0x4770, // bx lr
      0xbf00 // nop
    ];
    const needleOffset = instructions.length * 2;
    const onMatchOffset = needleOffset + 4;
    const codeSize = onMatchOffset + 4;

    Memory.patchCode(predicate, codeSize, function (address) {
      instructions.forEach((instruction, index) => {
        address.add(index * 2).writeU16(instruction);
      });
      address.add(needleOffset).writeS32(needle);
      address.add(onMatchOffset).writePointer(onMatchCallback);
    });

    return predicate.or(1);
  },
  arm64: function (needle, onMatch) {
    const size = Process.pageSize;

    const predicate = Memory.alloc(size);

    Memory.protect(predicate, size, 'rwx');

    const onMatchCallback = new NativeCallback(onMatch, 'void', ['pointer']);
    predicate._onMatchCallback = onMatchCallback;

    const instructions = [
      0xb9400001, // ldr w1, [x0]
      0x180000c2, // ldr w2, =needle
      0x6b02003f, // cmp w1, w2
      0x54000061, // b.ne mismatch
      0x58000083, // ldr x3, =onMatch
      0xd61f0060, // br x3
      0xd65f03c0 // ret
    ];
    const needleOffset = instructions.length * 4;
    const onMatchOffset = needleOffset + 4;
    const codeSize = onMatchOffset + 8;

    Memory.patchCode(predicate, codeSize, function (address) {
      instructions.forEach((instruction, index) => {
        address.add(index * 4).writeU32(instruction);
      });
      address.add(needleOffset).writeS32(needle);
      address.add(onMatchOffset).writePointer(onMatchCallback);
    });

    return predicate;
  }
};

export function makeObjectVisitorPredicate (needle, onMatch) {
  const factory = objectVisitorPredicateFactories[Process.arch] || makeGenericObjectVisitorPredicate;
  return factory(needle, onMatch);
}

function makeGenericObjectVisitorPredicate (needle, onMatch) {
  return new NativeCallback(object => {
    const klass = object.readS32();
    if (klass === needle) {
      onMatch(object);
    }
  }, 'void', ['pointer', 'pointer']);
}

function alignPointerOffset (offset) {
  const remainder = offset % pointerSize;
  if (remainder !== 0) {
    return offset + pointerSize - remainder;
  }
  return offset;
}

✄
import { getApi as androidGetApi, getAndroidVersion } from './android.js';
import { getApi as jvmGetApi } from './jvm.js';
let getApi = androidGetApi;
try {
  getAndroidVersion();
} catch (e) {
  getApi = jvmGetApi;
}
export default getApi;

✄
import Env from './env.js';
import * as android from './android.js';
import { ensureClassInitialized as jvmEnsureClassInitialized, makeMethodMangler as jvmMakeMethodMangler } from './jvm.js';
import ClassModel from './class-model.js';
import LRU from './lru.js';
import mkdex from './mkdex.js';
import {
  getType,
  getPrimitiveType,
  getArrayType,
  makeJniObjectTypeName
} from './types.js';
const jsizeSize = 4;
let {
  ensureClassInitialized,
  makeMethodMangler
} = android;

const kAccStatic = 0x0008;

const CONSTRUCTOR_METHOD = 1;
const STATIC_METHOD = 2;
const INSTANCE_METHOD = 3;

const STATIC_FIELD = 1;
const INSTANCE_FIELD = 2;

const STRATEGY_VIRTUAL = 1;
const STRATEGY_DIRECT = 2;

const PENDING_USE = Symbol('PENDING_USE');

const DEFAULT_CACHE_DIR = '/data/local/tmp';

const {
  getCurrentThreadId,
  pointerSize
} = Process;

const factoryCache = {
  state: 'empty',
  factories: [],
  loaders: null,
  Integer: null
};

let vm = null;
let api = null;
let isArtVm = null;

let wrapperHandler = null;
let dispatcherPrototype = null;
let methodPrototype = null;
let valueOfPrototype = null;

let cachedLoaderInvoke = null;
let cachedLoaderMethod = null;

const ignoredThreads = new Map();

export default class ClassFactory {
  static _initialize (_vm, _api) {
    vm = _vm;
    api = _api;
    isArtVm = _api.flavor === 'art';
    if (_api.flavor === 'jvm') {
      ensureClassInitialized = jvmEnsureClassInitialized;
      makeMethodMangler = jvmMakeMethodMangler;
    }
  }

  static _disposeAll (env) {
    factoryCache.factories.forEach(factory => {
      factory._dispose(env);
    });
  }

  static get (classLoader) {
    const cache = getFactoryCache();

    const defaultFactory = cache.factories[0];

    if (classLoader === null) {
      return defaultFactory;
    }

    const indexObj = cache.loaders.get(classLoader);
    if (indexObj !== null) {
      const index = defaultFactory.cast(indexObj, cache.Integer);
      return cache.factories[index.intValue()];
    }

    const factory = new ClassFactory();
    factory.loader = classLoader;
    factory.cacheDir = defaultFactory.cacheDir;
    addFactoryToCache(factory, classLoader);

    return factory;
  }

  constructor () {
    this.cacheDir = DEFAULT_CACHE_DIR;
    this.codeCacheDir = DEFAULT_CACHE_DIR + '/dalvik-cache';

    this.tempFileNaming = {
      prefix: 'frida',
      suffix: ''
    };

    this._classes = {};
    this._classHandles = new LRU(10, releaseClassHandle);
    this._patchedMethods = new Set();
    this._loader = null;
    this._types = [{}, {}];

    factoryCache.factories.push(this);
  }

  _dispose (env) {
    Array.from(this._patchedMethods).forEach(method => {
      method.implementation = null;
    });
    this._patchedMethods.clear();

    android.revertGlobalPatches();

    this._classHandles.dispose(env);
    this._classes = {};
  }

  get loader () {
    return this._loader;
  }

  set loader (value) {
    const isInitial = this._loader === null && value !== null;

    this._loader = value;

    if (isInitial && factoryCache.state === 'ready' && this === factoryCache.factories[0]) {
      addFactoryToCache(this, value);
    }
  }

  use (className, options = {}) {
    const allowCached = options.cache !== 'skip';

    let C = allowCached ? this._getUsedClass(className) : undefined;
    if (C === undefined) {
      try {
        const env = vm.getEnv();

        const { _loader: loader } = this;
        const getClassHandle = (loader !== null)
          ? makeLoaderClassHandleGetter(className, loader, env)
          : makeBasicClassHandleGetter(className);

        C = this._make(className, getClassHandle, env);
      } finally {
        if (allowCached) {
          this._setUsedClass(className, C);
        }
      }
    }

    return C;
  }

  _getUsedClass (className) {
    let c;
    while ((c = this._classes[className]) === PENDING_USE) {
      Thread.sleep(0.05);
    }
    if (c === undefined) {
      this._classes[className] = PENDING_USE;
    }
    return c;
  }

  _setUsedClass (className, c) {
    if (c !== undefined) {
      this._classes[className] = c;
    } else {
      delete this._classes[className];
    }
  }

  _make (name, getClassHandle, env) {
    const C = makeClassWrapperConstructor();
    const proto = Object.create(Wrapper.prototype, {
      [Symbol.for('n')]: {
        value: name
      },
      $n: {
        get () {
          return this[Symbol.for('n')];
        }
      },
      [Symbol.for('C')]: {
        value: C
      },
      $C: {
        get () {
          return this[Symbol.for('C')];
        }
      },
      [Symbol.for('w')]: {
        value: null,
        writable: true
      },
      $w: {
        get () {
          return this[Symbol.for('w')];
        },
        set (val) {
          this[Symbol.for('w')] = val;
        }
      },
      [Symbol.for('_s')]: {
        writable: true
      },
      $_s: {
        get () {
          return this[Symbol.for('_s')];
        },
        set (val) {
          this[Symbol.for('_s')] = val;
        }
      },
      [Symbol.for('c')]: {
        value: [null]
      },
      $c: {
        get () {
          return this[Symbol.for('c')];
        }
      },
      [Symbol.for('m')]: {
        value: new Map()
      },
      $m: {
        get () {
          return this[Symbol.for('m')];
        }
      },
      [Symbol.for('l')]: {
        value: null,
        writable: true
      },
      $l: {
        get () {
          return this[Symbol.for('l')];
        },
        set (val) {
          this[Symbol.for('l')] = val;
        }
      },
      [Symbol.for('gch')]: {
        value: getClassHandle
      },
      $gch: {
        get () {
          return this[Symbol.for('gch')];
        }
      },
      [Symbol.for('f')]: {
        value: this
      },
      $f: {
        get () {
          return this[Symbol.for('f')];
        }
      }
    });
    C.prototype = proto;

    const classWrapper = new C(null);
    proto[Symbol.for('w')] = classWrapper;
    proto.$w = classWrapper;

    const h = classWrapper.$borrowClassHandle(env);
    try {
      const classHandle = h.value;

      ensureClassInitialized(env, classHandle);

      proto.$l = ClassModel.build(classHandle, env);
    } finally {
      h.unref(env);
    }

    return classWrapper;
  }

  retain (obj) {
    const env = vm.getEnv();
    return obj.$clone(env);
  }

  cast (obj, klass, owned) {
    const env = vm.getEnv();

    let handle = obj.$h;
    if (handle === undefined) {
      handle = obj;
    }

    const h = klass.$borrowClassHandle(env);
    try {
      const isValidCast = env.isInstanceOf(handle, h.value);
      if (!isValidCast) {
        throw new Error(`Cast from '${env.getObjectClassName(handle)}' to '${klass.$n}' isn't possible`);
      }
    } finally {
      h.unref(env);
    }

    const C = klass.$C;
    return new C(handle, STRATEGY_VIRTUAL, env, owned);
  }

  wrap (handle, klass, env) {
    const C = klass.$C;
    const wrapper = new C(handle, STRATEGY_VIRTUAL, env, false);
    wrapper.$r = Script.bindWeak(wrapper, vm.makeHandleDestructor(handle));
    return wrapper;
  }

  array (type, elements) {
    const env = vm.getEnv();

    const primitiveType = getPrimitiveType(type);
    if (primitiveType !== null) {
      type = primitiveType.name;
    }
    const arrayType = getArrayType('[' + type, false, this);

    const rawArray = arrayType.toJni(elements, env);
    return arrayType.fromJni(rawArray, env, true);
  }

  registerClass (spec) {
    const env = vm.getEnv();

    const tempHandles = [];
    try {
      const Class = this.use('java.lang.Class');
      const Method = env.javaLangReflectMethod();
      const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);

      const className = spec.name;
      const interfaces = (spec.implements || []);
      const superClass = (spec.superClass || this.use('java.lang.Object'));

      const dexFields = [];
      const dexMethods = [];
      const dexSpec = {
        name: makeJniObjectTypeName(className),
        sourceFileName: makeSourceFileName(className),
        superClass: makeJniObjectTypeName(superClass.$n),
        interfaces: interfaces.map(iface => makeJniObjectTypeName(iface.$n)),
        fields: dexFields,
        methods: dexMethods
      };

      const allInterfaces = interfaces.slice();
      interfaces.forEach(iface => {
        Array.prototype.slice.call(iface.class.getInterfaces())
          .forEach(baseIface => {
            const baseIfaceName = this.cast(baseIface, Class).getCanonicalName();
            allInterfaces.push(this.use(baseIfaceName));
          });
      });

      const fields = spec.fields || {};
      Object.getOwnPropertyNames(fields).forEach(name => {
        const fieldType = this._getType(fields[name]);
        dexFields.push([name, fieldType.name]);
      });

      const baseMethods = {};
      const pendingOverloads = {};
      allInterfaces.forEach(iface => {
        const h = iface.$borrowClassHandle(env);
        tempHandles.push(h);
        const ifaceHandle = h.value;

        iface.$ownMembers
          .filter(name => {
            return iface[name].overloads !== undefined;
          })
          .forEach(name => {
            const method = iface[name];

            const overloads = method.overloads;
            const overloadIds = overloads.map(overload => makeOverloadId(name, overload.returnType, overload.argumentTypes));

            baseMethods[name] = [method, overloadIds, ifaceHandle];
            overloads.forEach((overload, index) => {
              const id = overloadIds[index];
              pendingOverloads[id] = [overload, ifaceHandle];
            });
          });
      });

      const methods = spec.methods || {};
      const methodNames = Object.keys(methods);
      const methodEntries = methodNames.reduce((result, name) => {
        const entry = methods[name];
        const rawName = (name === '$init') ? '<init>' : name;
        if (entry instanceof Array) {
          result.push(...entry.map(e => [rawName, e]));
        } else {
          result.push([rawName, entry]);
        }
        return result;
      }, []);

      const implMethods = [];

      methodEntries.forEach(([name, methodValue]) => {
        let type = INSTANCE_METHOD;
        let returnType;
        let argumentTypes;
        let thrownTypeNames = [];
        let impl;

        if (typeof methodValue === 'function') {
          const m = baseMethods[name];
          if (m !== undefined && Array.isArray(m)) {
            const [baseMethod, overloadIds, parentTypeHandle] = m;

            if (overloadIds.length > 1) {
              throw new Error(`More than one overload matching '${name}': signature must be specified`);
            }
            delete pendingOverloads[overloadIds[0]];
            const overload = baseMethod.overloads[0];

            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;
            impl = methodValue;

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          } else {
            returnType = this._getType('void');
            argumentTypes = [];
            impl = methodValue;
          }
        } else {
          if (methodValue.isStatic) {
            type = STATIC_METHOD;
          }
          returnType = this._getType(methodValue.returnType || 'void');
          argumentTypes = (methodValue.argumentTypes || []).map(name => this._getType(name));
          impl = methodValue.implementation;
          if (typeof impl !== 'function') {
            throw new Error('Expected a function implementation for method: ' + name);
          }

          const id = makeOverloadId(name, returnType, argumentTypes);
          const pendingOverload = pendingOverloads[id];
          if (pendingOverload !== undefined) {
            const [overload, parentTypeHandle] = pendingOverload;
            delete pendingOverloads[id];

            type = overload.type;
            returnType = overload.returnType;
            argumentTypes = overload.argumentTypes;

            const reflectedMethod = env.toReflectedMethod(parentTypeHandle, overload.handle, 0);
            const thrownTypes = invokeObjectMethodNoArgs(env.handle, reflectedMethod, Method.getGenericExceptionTypes);
            thrownTypeNames = readTypeNames(env, thrownTypes).map(makeJniObjectTypeName);
            env.deleteLocalRef(thrownTypes);
            env.deleteLocalRef(reflectedMethod);
          }
        }

        const returnTypeName = returnType.name;
        const argumentTypeNames = argumentTypes.map(t => t.name);
        const signature = '(' + argumentTypeNames.join('') + ')' + returnTypeName;

        dexMethods.push([name, returnTypeName, argumentTypeNames, thrownTypeNames, (type === STATIC_METHOD) ? kAccStatic : 0]);
        implMethods.push([name, signature, type, returnType, argumentTypes, impl]);
      });

      const unimplementedMethodIds = Object.keys(pendingOverloads);
      if (unimplementedMethodIds.length > 0) {
        throw new Error('Missing implementation for: ' + unimplementedMethodIds.join(', '));
      }

      const dex = DexFile.fromBuffer(mkdex(dexSpec), this);
      try {
        dex.load();
      } finally {
        dex.file.delete();
      }

      const classWrapper = this.use(spec.name);

      const numMethods = methodEntries.length;
      if (numMethods > 0) {
        const methodElementSize = 3 * pointerSize;
        const methodElements = Memory.alloc(numMethods * methodElementSize);

        const nativeMethods = [];
        const temporaryHandles = [];

        implMethods.forEach(([name, signature, type, returnType, argumentTypes, impl], index) => {
          const rawName = Memory.allocUtf8String(name);
          const rawSignature = Memory.allocUtf8String(signature);
          const rawImpl = implement(name, classWrapper, type, returnType, argumentTypes, impl);

          methodElements.add(index * methodElementSize).writePointer(rawName);
          methodElements.add((index * methodElementSize) + pointerSize).writePointer(rawSignature);
          methodElements.add((index * methodElementSize) + (2 * pointerSize)).writePointer(rawImpl);

          temporaryHandles.push(rawName, rawSignature);
          nativeMethods.push(rawImpl);
        });

        const h = classWrapper.$borrowClassHandle(env);
        tempHandles.push(h);
        const classHandle = h.value;

        env.registerNatives(classHandle, methodElements, numMethods);
        env.throwIfExceptionPending();

        classWrapper.$nativeMethods = nativeMethods;
      }

      return classWrapper;
    } finally {
      tempHandles.forEach(h => { h.unref(env); });
    }
  }

  choose (specifier, callbacks) {
    const env = vm.getEnv();
    const { flavor } = api;
    if (flavor === 'jvm') {
      this._chooseObjectsJvm(specifier, env, callbacks);
    } else if (flavor === 'art') {
      const legacyApiMissing = api['art::gc::Heap::VisitObjects'] === undefined;
      if (legacyApiMissing) {
        const preA12ApiMissing = api['art::gc::Heap::GetInstances'] === undefined;
        if (preA12ApiMissing) {
          return this._chooseObjectsJvm(specifier, env, callbacks);
        }
      }
      android.withRunnableArtThread(vm, env, thread => {
        if (legacyApiMissing) {
          this._chooseObjectsArtPreA12(specifier, env, thread, callbacks);
        } else {
          this._chooseObjectsArtLegacy(specifier, env, thread, callbacks);
        }
      });
    } else {
      this._chooseObjectsDalvik(specifier, env, callbacks);
    }
  }

  _chooseObjectsJvm (className, env, callbacks) {
    const classWrapper = this.use(className);
    const { jvmti } = api;
    const JVMTI_ITERATION_CONTINUE = 1;
    const JVMTI_HEAP_OBJECT_EITHER = 3;

    const h = classWrapper.$borrowClassHandle(env);
    const tag = int64(h.value.toString());
    try {
      const heapObjectCallback = new NativeCallback((classTag, size, tagPtr, userData) => {
        tagPtr.writeS64(tag);
        return JVMTI_ITERATION_CONTINUE;
      }, 'int', ['int64', 'int64', 'pointer', 'pointer']);
      jvmti.iterateOverInstancesOfClass(h.value, JVMTI_HEAP_OBJECT_EITHER, heapObjectCallback, h.value);

      const tagPtr = Memory.alloc(8);
      tagPtr.writeS64(tag);
      const countPtr = Memory.alloc(jsizeSize);
      const objectsPtr = Memory.alloc(pointerSize);
      jvmti.getObjectsWithTags(1, tagPtr, countPtr, objectsPtr, NULL);

      const count = countPtr.readS32();
      const objects = objectsPtr.readPointer();
      const handles = [];
      for (let i = 0; i !== count; i++) {
        handles.push(objects.add(i * pointerSize).readPointer());
      }
      jvmti.deallocate(objects);

      try {
        for (const handle of handles) {
          const instance = this.cast(handle, classWrapper);
          const result = callbacks.onMatch(instance);
          if (result === 'stop') {
            break;
          }
        }

        callbacks.onComplete();
      } finally {
        handles.forEach(handle => {
          env.deleteLocalRef(handle);
        });
      }
    } finally {
      h.unref(env);
    }
  }

  _chooseObjectsArtPreA12 (className, env, thread, callbacks) {
    const classWrapper = this.use(className);

    const scope = android.VariableSizedHandleScope.$new(thread, vm);

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      const object = api['art::JavaVMExt::DecodeGlobal'](api.vm, thread, h.value);
      needle = scope.newHandle(object);
    } finally {
      h.unref(env);
    }

    const maxCount = 0;

    const instances = android.HandleVector.$new();

    api['art::gc::Heap::GetInstances'](api.artHeap, scope, needle, maxCount, instances);

    const instanceHandles = instances.handles.map(handle => env.newGlobalRef(handle));

    instances.$delete();
    scope.$delete();

    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
        const result = callbacks.onMatch(instance);
        if (result === 'stop') {
          break;
        }
      }

      callbacks.onComplete();
    } finally {
      instanceHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }
  }

  _chooseObjectsArtLegacy (className, env, thread, callbacks) {
    const classWrapper = this.use(className);

    const instanceHandles = [];
    const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
    const vmHandle = api.vm;

    let needle;
    const h = classWrapper.$borrowClassHandle(env);
    try {
      needle = api['art::JavaVMExt::DecodeGlobal'](vmHandle, thread, h.value).toInt32();
    } finally {
      h.unref(env);
    }

    const collectMatchingInstanceHandles = android.makeObjectVisitorPredicate(needle, object => {
      instanceHandles.push(addGlobalReference(vmHandle, thread, object));
    });

    api['art::gc::Heap::VisitObjects'](api.artHeap, collectMatchingInstanceHandles, NULL);

    try {
      for (const handle of instanceHandles) {
        const instance = this.cast(handle, classWrapper);
        const result = callbacks.onMatch(instance);
        if (result === 'stop') {
          break;
        }
      }
    } finally {
      instanceHandles.forEach(handle => {
        env.deleteGlobalRef(handle);
      });
    }

    callbacks.onComplete();
  }

  _chooseObjectsDalvik (className, callerEnv, callbacks) {
    const classWrapper = this.use(className);

    if (api.addLocalReference === null) {
      const libdvm = Process.getModuleByName('libdvm.so');

      let pattern;
      switch (Process.arch) {
        case 'arm':
          // Verified with 4.3.1 and 4.4.4
          pattern = '2d e9 f0 41 05 46 15 4e 0c 46 7e 44 11 b3 43 68';
          break;
        case 'ia32':
          // Verified with 4.3.1 and 4.4.2
          pattern = '8d 64 24 d4 89 5c 24 1c 89 74 24 20 e8 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 85 d2';
          break;
      }

      Memory.scan(libdvm.base, libdvm.size, pattern, {
        onMatch: (address, size) => {
          let wrapper;
          if (Process.arch === 'arm') {
            address = address.or(1); // Thumb
            wrapper = new NativeFunction(address, 'pointer', ['pointer', 'pointer']);
          } else {
            const thunk = Memory.alloc(Process.pageSize);
            Memory.patchCode(thunk, 16, code => {
              const cw = new X86Writer(code, { pc: thunk });
              cw.putMovRegRegOffsetPtr('eax', 'esp', 4);
              cw.putMovRegRegOffsetPtr('edx', 'esp', 8);
              cw.putJmpAddress(address);
              cw.flush();
            });
            wrapper = new NativeFunction(thunk, 'pointer', ['pointer', 'pointer']);
            wrapper._thunk = thunk;
          }
          api.addLocalReference = wrapper;

          vm.perform(env => {
            enumerateInstances(this, env);
          });

          return 'stop';
        },
        onError (reason) {},
        onComplete () {
          if (api.addLocalReference === null) {
            callbacks.onComplete();
          }
        }
      });
    } else {
      enumerateInstances(this, callerEnv);
    }

    function enumerateInstances (factory, env) {
      const { DVM_JNI_ENV_OFFSET_SELF } = android;
      const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

      let ptrClassObject;
      const h = classWrapper.$borrowClassHandle(env);
      try {
        ptrClassObject = api.dvmDecodeIndirectRef(thread, h.value);
      } finally {
        h.unref(env);
      }

      const pattern = ptrClassObject.toMatchPattern();
      const heapSourceBase = api.dvmHeapSourceGetBase();
      const heapSourceLimit = api.dvmHeapSourceGetLimit();
      const size = heapSourceLimit.sub(heapSourceBase).toInt32();

      Memory.scan(heapSourceBase, size, pattern, {
        onMatch: (address, size) => {
          if (api.dvmIsValidObject(address)) {
            vm.perform(env => {
              const thread = env.handle.add(DVM_JNI_ENV_OFFSET_SELF).readPointer();

              let instance;
              const localReference = api.addLocalReference(thread, address);
              try {
                instance = factory.cast(localReference, classWrapper);
              } finally {
                env.deleteLocalRef(localReference);
              }

              const result = callbacks.onMatch(instance);
              if (result === 'stop') {
                return 'stop';
              }
            });
          }
        },
        onError (reason) {},
        onComplete () {
          callbacks.onComplete();
        }
      });
    }
  }

  openClassFile (filePath) {
    return new DexFile(filePath, null, this);
  }

  _getType (typeName, unbox = true) {
    return getType(typeName, unbox, this);
  }
}

function makeClassWrapperConstructor () {
  return function (handle, strategy, env, owned) {
    return Wrapper.call(this, handle, strategy, env, owned);
  };
}

function Wrapper (handle, strategy, env, owned = true) {
  if (handle !== null) {
    if (owned) {
      const h = env.newGlobalRef(handle);
      this.$h = h;
      this.$r = Script.bindWeak(this, vm.makeHandleDestructor(h));
    } else {
      this.$h = handle;
      this.$r = null;
    }
  } else {
    this.$h = null;
    this.$r = null;
  }

  this.$t = strategy;

  return new Proxy(this, wrapperHandler);
}

wrapperHandler = {
  has (target, property) {
    if (property in target) {
      return true;
    }

    return target.$has(property);
  },
  get (target, property, receiver) {
    if (typeof property !== 'string' || property.startsWith('$') || property === 'class') {
      return target[property];
    }

    const unwrap = target.$find(property);
    if (unwrap !== null) {
      return unwrap(receiver);
    }

    return target[property];
  },
  set (target, property, value, receiver) {
    target[property] = value;
    return true;
  },
  ownKeys (target) {
    return target.$list();
  },
  getOwnPropertyDescriptor (target, property) {
    if (Object.prototype.hasOwnProperty.call(target, property)) {
      return Object.getOwnPropertyDescriptor(target, property);
    }

    return {
      writable: false,
      configurable: true,
      enumerable: true
    };
  }
};

Object.defineProperties(Wrapper.prototype, {
  [Symbol.for('new')]: {
    enumerable: false,
    get () {
      return this.$getCtor('allocAndInit');
    }
  },
  $new: {
    enumerable: true,
    get () {
      return this[Symbol.for('new')];
    }
  },
  [Symbol.for('alloc')]: {
    enumerable: false,
    value () {
      const env = vm.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const obj = env.allocObject(h.value);
        const factory = this.$f;
        return factory.cast(obj, this);
      } finally {
        h.unref(env);
      }
    }
  },
  $alloc: {
    enumerable: true,
    get () {
      return this[Symbol.for('alloc')];
    }
  },
  [Symbol.for('init')]: {
    enumerable: false,
    get () {
      return this.$getCtor('initOnly');
    }
  },
  $init: {
    enumerable: true,
    get () {
      return this[Symbol.for('init')];
    }
  },
  [Symbol.for('dispose')]: {
    enumerable: false,
    value () {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }

      if (this.$h !== null) {
        this.$h = undefined;
      }
    }
  },
  $dispose: {
    enumerable: true,
    get () {
      return this[Symbol.for('dispose')];
    }
  },
  [Symbol.for('clone')]: {
    enumerable: false,
    value (env) {
      const C = this.$C;
      return new C(this.$h, this.$t, env);
    }
  },
  $clone: {
    value (env) {
      return this[Symbol.for('clone')](env);
    }
  },
  [Symbol.for('class')]: {
    enumerable: false,
    get () {
      const env = vm.getEnv();
      const h = this.$borrowClassHandle(env);
      try {
        const factory = this.$f;
        return factory.cast(h.value, factory.use('java.lang.Class'));
      } finally {
        h.unref(env);
      }
    }
  },
  class: {
    enumerable: true,
    get () {
      return this[Symbol.for('class')];
    }
  },
  [Symbol.for('className')]: {
    enumerable: false,
    get () {
      const handle = this.$h;
      if (handle === null) {
        return this.$n;
      }

      return vm.getEnv().getObjectClassName(handle);
    }
  },
  $className: {
    enumerable: true,
    get () {
      return this[Symbol.for('className')];
    }
  },
  [Symbol.for('ownMembers')]: {
    enumerable: false,
    get () {
      const model = this.$l;
      return model.list();
    }
  },
  $ownMembers: {
    enumerable: true,
    get () {
      return this[Symbol.for('ownMembers')];
    }
  },
  [Symbol.for('super')]: {
    enumerable: false,
    get () {
      const env = vm.getEnv();
      const C = this.$s.$C;
      return new C(this.$h, STRATEGY_DIRECT, env);
    }
  },
  $super: {
    enumerable: true,
    get () {
      return this[Symbol.for('super')];
    }
  },
  [Symbol.for('s')]: {
    enumerable: false,
    get () {
      const proto = Object.getPrototypeOf(this);

      let superWrapper = proto.$_s;
      if (superWrapper === undefined) {
        const env = vm.getEnv();

        const h = this.$borrowClassHandle(env);
        try {
          const superHandle = env.getSuperclass(h.value);
          if (!superHandle.isNull()) {
            try {
              const superClassName = env.getClassName(superHandle);
              const factory = proto.$f;
              superWrapper = factory._getUsedClass(superClassName);
              if (superWrapper === undefined) {
                try {
                  const getSuperClassHandle = makeSuperHandleGetter(this);
                  superWrapper = factory._make(superClassName, getSuperClassHandle, env);
                } finally {
                  factory._setUsedClass(superClassName, superWrapper);
                }
              }
            } finally {
              env.deleteLocalRef(superHandle);
            }
          } else {
            superWrapper = null;
          }
        } finally {
          h.unref(env);
        }

        proto.$_s = superWrapper;
      }

      return superWrapper;
    }
  },
  $s: {
    get () {
      return this[Symbol.for('s')];
    }
  },
  [Symbol.for('isSameObject')]: {
    enumerable: false,
    value (obj) {
      const env = vm.getEnv();
      return env.isSameObject(obj.$h, this.$h);
    }
  },
  $isSameObject: {
    value (obj) {
      return this[Symbol.for('isSameObject')](obj);
    }
  },
  [Symbol.for('getCtor')]: {
    enumerable: false,
    value (type) {
      const slot = this.$c;

      let ctor = slot[0];
      if (ctor === null) {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          ctor = makeConstructor(h.value, this.$w, env);
          slot[0] = ctor;
        } finally {
          h.unref(env);
        }
      }

      return ctor[type];
    }
  },
  $getCtor: {
    value (type) {
      return this[Symbol.for('getCtor')](type);
    }
  },
  [Symbol.for('borrowClassHandle')]: {
    enumerable: false,
    value (env) {
      const className = this.$n;
      const classHandles = this.$f._classHandles;

      let handle = classHandles.get(className);
      if (handle === undefined) {
        handle = new ClassHandle(this.$gch(env), env);
        classHandles.set(className, handle, env);
      }

      return handle.ref();
    }
  },
  $borrowClassHandle: {
    value (env) {
      return this[Symbol.for('borrowClassHandle')](env);
    }
  },
  [Symbol.for('copyClassHandle')]: {
    enumerable: false,
    value (env) {
      const h = this.$borrowClassHandle(env);
      try {
        return env.newLocalRef(h.value);
      } finally {
        h.unref(env);
      }
    }
  },
  $copyClassHandle: {
    value (env) {
      return this[Symbol.for('copyClassHandle')](env);
    }
  },
  [Symbol.for('getHandle')]: {
    enumerable: false,
    value (env) {
      const handle = this.$h;

      const isDisposed = handle === undefined;
      if (isDisposed) {
        throw new Error('Wrapper is disposed; perhaps it was borrowed from a hook ' +
            'instead of calling Java.retain() to make a long-lived wrapper?');
      }

      return handle;
    }
  },
  $getHandle: {
    value (env) {
      return this[Symbol.for('getHandle')](env);
    }
  },
  [Symbol.for('list')]: {
    enumerable: false,
    value () {
      const superWrapper = this.$s;
      const superMembers = (superWrapper !== null) ? superWrapper.$list() : [];

      const model = this.$l;
      return Array.from(new Set(superMembers.concat(model.list())));
    }
  },
  $list: {
    get () {
      return this[Symbol.for('list')];
    }
  },
  [Symbol.for('has')]: {
    enumerable: false,
    value (member) {
      const members = this.$m;
      if (members.has(member)) {
        return true;
      }

      const model = this.$l;
      if (model.has(member)) {
        return true;
      }

      const superWrapper = this.$s;
      if (superWrapper !== null && superWrapper.$has(member)) {
        return true;
      }

      return false;
    }
  },
  $has: {
    value (member) {
      return this[Symbol.for('has')](member);
    }
  },
  [Symbol.for('find')]: {
    enumerable: false,
    value (member) {
      const members = this.$m;

      let value = members.get(member);
      if (value !== undefined) {
        return value;
      }

      const model = this.$l;
      const spec = model.find(member);
      if (spec !== null) {
        const env = vm.getEnv();
        const h = this.$borrowClassHandle(env);
        try {
          value = makeMember(member, spec, h.value, this.$w, env);
        } finally {
          h.unref(env);
        }
        members.set(member, value);
        return value;
      }

      const superWrapper = this.$s;
      if (superWrapper !== null) {
        return superWrapper.$find(member);
      }

      return null;
    }
  },
  $find: {
    value (member) {
      return this[Symbol.for('find')](member);
    }
  },
  [Symbol.for('toJSON')]: {
    enumerable: false,
    value () {
      const wrapperName = this.$n;

      const handle = this.$h;
      if (handle === null) {
        return `<class: ${wrapperName}>`;
      }

      const actualName = this.$className;
      if (wrapperName === actualName) {
        return `<instance: ${wrapperName}>`;
      }

      return `<instance: ${wrapperName}, $className: ${actualName}>`;
    }
  },
  toJSON: {
    get () {
      return this[Symbol.for('toJSON')];
    }
  }
});

function ClassHandle (value, env) {
  this.value = env.newGlobalRef(value);
  env.deleteLocalRef(value);

  this.refs = 1;
}

ClassHandle.prototype.ref = function () {
  this.refs++;
  return this;
};

ClassHandle.prototype.unref = function (env) {
  if (--this.refs === 0) {
    env.deleteGlobalRef(this.value);
  }
};

function releaseClassHandle (handle, env) {
  handle.unref(env);
}

function makeBasicClassHandleGetter (className) {
  const canonicalClassName = className.replace(/\./g, '/');

  return function (env) {
    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      return env.findClass(canonicalClassName);
    } finally {
      unignore(tid);
    }
  };
}

function makeLoaderClassHandleGetter (className, usedLoader, callerEnv) {
  if (cachedLoaderMethod === null) {
    cachedLoaderInvoke = callerEnv.vaMethod('pointer', ['pointer']);
    cachedLoaderMethod = usedLoader.loadClass.overload('java.lang.String').handle;
  }

  callerEnv = null;

  return function (env) {
    const classNameValue = env.newStringUtf(className);

    const tid = getCurrentThreadId();
    ignore(tid);
    try {
      const result = cachedLoaderInvoke(env.handle, usedLoader.$h, cachedLoaderMethod, classNameValue);
      env.throwIfExceptionPending();
      return result;
    } finally {
      unignore(tid);
      env.deleteLocalRef(classNameValue);
    }
  };
}

function makeSuperHandleGetter (classWrapper) {
  return function (env) {
    const h = classWrapper.$borrowClassHandle(env);
    try {
      return env.getSuperclass(h.value);
    } finally {
      h.unref(env);
    }
  };
}

function makeConstructor (classHandle, classWrapper, env) {
  const { $n: className, $f: factory } = classWrapper;
  const methodName = basename(className);
  const Class = env.javaLangClass();
  const Constructor = env.javaLangReflectConstructor();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const jsCtorMethods = [];
  const jsInitMethods = [];
  const jsRetType = factory._getType(className, false);
  const jsVoidType = factory._getType('void', false);

  const constructors = invokeObjectMethodNoArgs(env.handle, classHandle, Class.getDeclaredConstructors);
  try {
    const n = env.getArrayLength(constructors);

    if (n !== 0) {
      for (let i = 0; i !== n; i++) {
        let methodId, types;
        const constructor = env.getObjectArrayElement(constructors, i);
        try {
          methodId = env.fromReflectedMethod(constructor);
          types = invokeObjectMethodNoArgs(env.handle, constructor, Constructor.getGenericParameterTypes);
        } finally {
          env.deleteLocalRef(constructor);
        }

        let jsArgTypes;
        try {
          jsArgTypes = readTypeNames(env, types).map(name => factory._getType(name));
        } finally {
          env.deleteLocalRef(types);
        }

        jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, methodId, jsRetType, jsArgTypes, env));
        jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, methodId, jsVoidType, jsArgTypes, env));
      }
    } else {
      const isInterface = invokeUInt8MethodNoArgs(env.handle, classHandle, Class.isInterface);
      if (isInterface) {
        throw new Error('cannot instantiate an interface');
      }

      const defaultClass = env.javaLangObject();
      const defaultConstructor = env.getMethodId(defaultClass, '<init>', '()V');

      jsCtorMethods.push(makeMethod(methodName, classWrapper, CONSTRUCTOR_METHOD, defaultConstructor, jsRetType, [], env));
      jsInitMethods.push(makeMethod(methodName, classWrapper, INSTANCE_METHOD, defaultConstructor, jsVoidType, [], env));
    }
  } finally {
    env.deleteLocalRef(constructors);
  }

  if (jsInitMethods.length === 0) {
    throw new Error('no supported overloads');
  }

  return {
    allocAndInit: makeMethodDispatcher(jsCtorMethods),
    initOnly: makeMethodDispatcher(jsInitMethods)
  };
}

function makeMember (name, spec, classHandle, classWrapper, env) {
  if (spec.startsWith('m')) {
    return makeMethodFromSpec(name, spec, classHandle, classWrapper, env);
  }

  return makeFieldFromSpec(name, spec, classHandle, classWrapper, env);
}

function makeMethodFromSpec (name, spec, classHandle, classWrapper, env) {
  const { $f: factory } = classWrapper;
  const overloads = spec.split(':').slice(1);

  const Method = env.javaLangReflectMethod();
  const invokeObjectMethodNoArgs = env.vaMethod('pointer', []);
  const invokeUInt8MethodNoArgs = env.vaMethod('uint8', []);

  const methods = overloads.map(params => {
    const type = (params[0] === 's') ? STATIC_METHOD : INSTANCE_METHOD;
    const methodId = ptr(params.substr(1));

    let jsRetType;
    const jsArgTypes = [];
    const handle = env.toReflectedMethod(classHandle, methodId, (type === STATIC_METHOD) ? 1 : 0);
    try {
      const isVarArgs = !!invokeUInt8MethodNoArgs(env.handle, handle, Method.isVarArgs);

      const retType = invokeObjectMethodNoArgs(env.handle, handle, Method.getGenericReturnType);
      env.throwIfExceptionPending();
      try {
        jsRetType = factory._getType(env.getTypeName(retType));
      } finally {
        env.deleteLocalRef(retType);
      }

      const argTypes = invokeObjectMethodNoArgs(env.handle, handle, Method.getParameterTypes);
      try {
        const n = env.getArrayLength(argTypes);

        for (let i = 0; i !== n; i++) {
          const t = env.getObjectArrayElement(argTypes, i);

          let argClassName;
          try {
            argClassName = (isVarArgs && i === n - 1) ? env.getArrayTypeName(t) : env.getTypeName(t);
          } finally {
            env.deleteLocalRef(t);
          }

          const argType = factory._getType(argClassName);
          jsArgTypes.push(argType);
        }
      } finally {
        env.deleteLocalRef(argTypes);
      }
    } catch (e) {
      return null;
    } finally {
      env.deleteLocalRef(handle);
    }

    return makeMethod(name, classWrapper, type, methodId, jsRetType, jsArgTypes, env);
  })
    .filter(m => m !== null);

  if (methods.length === 0) {
    throw new Error('No supported overloads');
  }

  if (name === 'valueOf') {
    ensureDefaultValueOfImplemented(methods);
  }

  const result = makeMethodDispatcher(methods);

  return function (receiver) {
    return result;
  };
}

function makeMethodDispatcher (overloads) {
  const m = makeMethodDispatcherCallable();
  Object.setPrototypeOf(m, dispatcherPrototype);
  m._o = overloads;
  return m;
}

function makeMethodDispatcherCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

dispatcherPrototype = Object.create(Function.prototype, {
  overloads: {
    enumerable: true,
    get () {
      return this._o;
    }
  },
  overload: {
    value (...args) {
      const overloads = this._o;

      const numArgs = args.length;
      const signature = args.join(':');

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];
        const { argumentTypes } = method;

        if (argumentTypes.length !== numArgs) {
          continue;
        }

        const s = argumentTypes.map(t => t.className).join(':');
        if (s === signature) {
          return method;
        }
      }

      throwOverloadError(this.methodName, this.overloads, 'specified argument types do not match any of:');
    }
  },
  methodName: {
    enumerable: true,
    get () {
      return this._o[0].methodName;
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._o[0].holder;
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._o[0].type;
    }
  },
  handle: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].handle;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].implementation;
    },
    set (fn) {
      throwIfDispatcherAmbiguous(this);
      this._o[0].implementation = fn;
    }
  },
  returnType: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].returnType;
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].argumentTypes;
    }
  },
  canInvokeWith: {
    enumerable: true,
    get (args) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].canInvokeWith;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throwIfDispatcherAmbiguous(this);
      return this._o[0].clone(options);
    }
  },
  invoke: {
    value (receiver, args) {
      const overloads = this._o;

      const isInstance = receiver.$h !== null;

      for (let i = 0; i !== overloads.length; i++) {
        const method = overloads[i];

        if (!method.canInvokeWith(args)) {
          continue;
        }

        if (method.type === INSTANCE_METHOD && !isInstance) {
          const name = this.methodName;

          if (name === 'toString') {
            return `<class: ${receiver.$n}>`;
          }

          throw new Error(name + ': cannot call instance method without an instance');
        }

        return method.apply(receiver, args);
      }

      if (this.methodName === 'toString') {
        return `<class: ${receiver.$n}>`;
      }

      throwOverloadError(this.methodName, this.overloads, 'argument types do not match any of:');
    }
  }
});

function makeOverloadId (name, returnType, argumentTypes) {
  return `${returnType.className} ${name}(${argumentTypes.map(t => t.className).join(', ')})`;
}

function throwIfDispatcherAmbiguous (dispatcher) {
  const methods = dispatcher._o;
  if (methods.length > 1) {
    throwOverloadError(methods[0].methodName, methods, 'has more than one overload, use .overload(<signature>) to choose from:');
  }
}

function throwOverloadError (name, methods, message) {
  const methodsSortedByArity = methods.slice().sort((a, b) => a.argumentTypes.length - b.argumentTypes.length);
  const overloads = methodsSortedByArity.map(m => {
    const argTypes = m.argumentTypes;
    if (argTypes.length > 0) {
      return '.overload(\'' + m.argumentTypes.map(t => t.className).join('\', \'') + '\')';
    } else {
      return '.overload()';
    }
  });
  throw new Error(`${name}(): ${message}\n\t${overloads.join('\n\t')}`);
}

function makeMethod (methodName, classWrapper, type, methodId, retType, argTypes, env, invocationOptions) {
  const rawRetType = retType.type;
  const rawArgTypes = argTypes.map((t) => t.type);

  if (env === null) {
    env = vm.getEnv();
  }

  let callVirtually, callDirectly;
  if (type === INSTANCE_METHOD) {
    callVirtually = env.vaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = env.nonvirtualVaMethod(rawRetType, rawArgTypes, invocationOptions);
  } else if (type === STATIC_METHOD) {
    callVirtually = env.staticVaMethod(rawRetType, rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  } else {
    callVirtually = env.constructor(rawArgTypes, invocationOptions);
    callDirectly = callVirtually;
  }

  return makeMethodInstance([methodName, classWrapper, type, methodId, retType, argTypes, callVirtually, callDirectly]);
}

function makeMethodInstance (params) {
  const m = makeMethodCallable();
  Object.setPrototypeOf(m, methodPrototype);
  m._p = params;
  return m;
}

function makeMethodCallable () {
  const m = function () {
    return m.invoke(this, arguments);
  };
  return m;
}

methodPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return this._p[3];
    }
  },
  implementation: {
    enumerable: true,
    get () {
      const replacement = this._r;
      return (replacement !== undefined) ? replacement : null;
    },
    set (fn) {
      const params = this._p;
      const holder = params[1];
      const type = params[2];

      if (type === CONSTRUCTOR_METHOD) {
        throw new Error('Reimplementing $new is not possible; replace implementation of $init instead');
      }

      const existingReplacement = this._r;
      if (existingReplacement !== undefined) {
        holder.$f._patchedMethods.delete(this);

        const mangler = existingReplacement._m;
        mangler.revert(vm);

        this._r = undefined;
      }

      if (fn !== null) {
        const [methodName, classWrapper, type, methodId, retType, argTypes] = params;

        const replacement = implement(methodName, classWrapper, type, retType, argTypes, fn, this);
        const mangler = makeMethodMangler(methodId);
        replacement._m = mangler;
        this._r = replacement;

        mangler.replace(replacement, type === INSTANCE_METHOD, argTypes, vm, api);

        holder.$f._patchedMethods.add(this);
      }
    }
  },
  returnType: {
    enumerable: true,
    get () {
      return this._p[4];
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return this._p[5];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      const argTypes = this._p[5];

      if (args.length !== argTypes.length) {
        return false;
      }

      return argTypes.every((t, i) => {
        return t.isCompatible(args[i]);
      });
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      const params = this._p.slice(0, 6);
      return makeMethod(...params, null, options);
    }
  },
  invoke: {
    value (receiver, args) {
      const env = vm.getEnv();

      const params = this._p;
      const type = params[2];
      const retType = params[4];
      const argTypes = params[5];

      const replacement = this._r;

      const isInstanceMethod = type === INSTANCE_METHOD;
      const numArgs = args.length;

      const frameCapacity = 2 + numArgs;
      env.pushLocalFrame(frameCapacity);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (isInstanceMethod) {
          jniThis = receiver.$getHandle();
        } else {
          borrowedHandle = receiver.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        let methodId;
        let strategy = receiver.$t;
        if (replacement === undefined) {
          methodId = params[3];
        } else {
          const mangler = replacement._m;
          methodId = mangler.resolveTarget(receiver, isInstanceMethod, env, api);

          if (isArtVm) {
            const pendingCalls = replacement._c;
            if (pendingCalls.has(getCurrentThreadId())) {
              strategy = STRATEGY_DIRECT;
            }
          }
        }

        const jniArgs = [
          env.handle,
          jniThis,
          methodId
        ];
        for (let i = 0; i !== numArgs; i++) {
          jniArgs.push(argTypes[i].toJni(args[i], env));
        }

        let jniCall;
        if (strategy === STRATEGY_VIRTUAL) {
          jniCall = params[6];
        } else {
          jniCall = params[7];

          if (isInstanceMethod) {
            jniArgs.splice(2, 0, receiver.$copyClassHandle(env));
          }
        }

        const jniRetval = jniCall.apply(null, jniArgs);
        env.throwIfExceptionPending();

        return retType.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  toString: {
    enumerable: true,
    value () {
      return `function ${this.methodName}(${this.argumentTypes.map(t => t.className).join(', ')}): ${this.returnType.className}`;
    }
  }
});

function implement (methodName, classWrapper, type, retType, argTypes, handler, fallback = null) {
  const pendingCalls = new Set();

  const f = makeMethodImplementation([methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls]);

  const impl = new NativeCallback(f, retType.type, ['pointer', 'pointer'].concat(argTypes.map(t => t.type)));
  impl._c = pendingCalls;

  return impl;
}

function makeMethodImplementation (params) {
  return function () {
    return handleMethodInvocation(arguments, params);
  };
}

function handleMethodInvocation (jniArgs, params) {
  const env = new Env(jniArgs[0], vm);

  const [methodName, classWrapper, type, retType, argTypes, handler, fallback, pendingCalls] = params;

  const ownedObjects = [];

  let self;
  if (type === INSTANCE_METHOD) {
    const C = classWrapper.$C;
    self = new C(jniArgs[1], STRATEGY_VIRTUAL, env, false);
  } else {
    self = classWrapper;
  }

  const tid = getCurrentThreadId();

  env.pushLocalFrame(3);
  let haveFrame = true;

  vm.link(tid, env);

  try {
    pendingCalls.add(tid);

    let fn;
    if (fallback === null || !ignoredThreads.has(tid)) {
      fn = handler;
    } else {
      fn = fallback;
    }

    const args = [];
    const numArgs = jniArgs.length - 2;
    for (let i = 0; i !== numArgs; i++) {
      const t = argTypes[i];

      const value = t.fromJni(jniArgs[2 + i], env, false);
      args.push(value);

      ownedObjects.push(value);
    }

    const retval = fn.apply(self, args);

    if (!retType.isCompatible(retval)) {
      throw new Error(`Implementation for ${methodName} expected return value compatible with ${retType.className}`);
    }

    let jniRetval = retType.toJni(retval, env);

    if (retType.type === 'pointer') {
      jniRetval = env.popLocalFrame(jniRetval);
      haveFrame = false;

      ownedObjects.push(retval);
    }

    return jniRetval;
  } catch (e) {
    const jniException = e.$h;
    if (jniException !== undefined) {
      env.throw(jniException);
    } else {
      Script.nextTick(() => { throw e; });
    }

    return retType.defaultValue;
  } finally {
    vm.unlink(tid);

    if (haveFrame) {
      env.popLocalFrame(NULL);
    }

    pendingCalls.delete(tid);

    ownedObjects.forEach(obj => {
      if (obj === null) {
        return;
      }

      const dispose = obj.$dispose;
      if (dispose !== undefined) {
        dispose.call(obj);
      }
    });
  }
}

function ensureDefaultValueOfImplemented (methods) {
  const { holder, type } = methods[0];

  const hasDefaultValueOf = methods.some(m => m.type === type && m.argumentTypes.length === 0);
  if (hasDefaultValueOf) {
    return;
  }

  methods.push(makeValueOfMethod([holder, type]));
}

function makeValueOfMethod (params) {
  const m = makeValueOfCallable();
  Object.setPrototypeOf(m, valueOfPrototype);
  m._p = params;
  return m;
}

function makeValueOfCallable () {
  const m = function () {
    return this;
  };
  return m;
}

valueOfPrototype = Object.create(Function.prototype, {
  methodName: {
    enumerable: true,
    get () {
      return 'valueOf';
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  type: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  handle: {
    enumerable: true,
    get () {
      return NULL;
    }
  },
  implementation: {
    enumerable: true,
    get () {
      return null;
    },
    set (fn) {
    }
  },
  returnType: {
    enumerable: true,
    get () {
      const classWrapper = this.holder;
      return classWrapper.$f.use(classWrapper.$n);
    }
  },
  argumentTypes: {
    enumerable: true,
    get () {
      return [];
    }
  },
  canInvokeWith: {
    enumerable: true,
    value (args) {
      return args.length === 0;
    }
  },
  clone: {
    enumerable: true,
    value (options) {
      throw new Error('Invalid operation');
    }
  }
});

function makeFieldFromSpec (name, spec, classHandle, classWrapper, env) {
  const type = (spec[2] === 's') ? STATIC_FIELD : INSTANCE_FIELD;
  const id = ptr(spec.substr(3));
  const { $f: factory } = classWrapper;

  let fieldType;
  const field = env.toReflectedField(classHandle, id, (type === STATIC_FIELD) ? 1 : 0);
  try {
    fieldType = env.vaMethod('pointer', [])(env.handle, field, env.javaLangReflectField().getGenericType);
    env.throwIfExceptionPending();
  } finally {
    env.deleteLocalRef(field);
  }

  let rtype;
  try {
    rtype = factory._getType(env.getTypeName(fieldType));
  } finally {
    env.deleteLocalRef(fieldType);
  }

  let getValue, setValue;
  const rtypeJni = rtype.type;
  if (type === STATIC_FIELD) {
    getValue = env.getStaticField(rtypeJni);
    setValue = env.setStaticField(rtypeJni);
  } else {
    getValue = env.getField(rtypeJni);
    setValue = env.setField(rtypeJni);
  }

  return makeFieldFromParams([type, rtype, id, getValue, setValue]);
}

function makeFieldFromParams (params) {
  return function (receiver) {
    return new Field([receiver].concat(params));
  };
}

function Field (params) {
  this._p = params;
}

Object.defineProperties(Field.prototype, {
  value: {
    enumerable: true,
    get () {
      const [holder, type, rtype, id, getValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        const jniRetval = getValue(env.handle, jniThis, id);
        env.throwIfExceptionPending();

        return rtype.fromJni(jniRetval, env, true);
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    },
    set (value) {
      const [holder, type, rtype, id, , setValue] = this._p;

      const env = vm.getEnv();
      env.pushLocalFrame(4);

      let borrowedHandle = null;
      try {
        let jniThis;
        if (type === INSTANCE_FIELD) {
          jniThis = holder.$getHandle();
          if (jniThis === null) {
            throw new Error('Cannot access an instance field without an instance');
          }
        } else {
          borrowedHandle = holder.$borrowClassHandle(env);
          jniThis = borrowedHandle.value;
        }

        if (!rtype.isCompatible(value)) {
          throw new Error(`Expected value compatible with ${rtype.className}`);
        }
        const jniValue = rtype.toJni(value, env);

        setValue(env.handle, jniThis, id, jniValue);
        env.throwIfExceptionPending();
      } finally {
        if (borrowedHandle !== null) {
          borrowedHandle.unref(env);
        }

        env.popLocalFrame(NULL);
      }
    }
  },
  holder: {
    enumerable: true,
    get () {
      return this._p[0];
    }
  },
  fieldType: {
    enumerable: true,
    get () {
      return this._p[1];
    }
  },
  fieldReturnType: {
    enumerable: true,
    get () {
      return this._p[2];
    }
  },
  toString: {
    enumerable: true,
    value () {
      const inlineString = `Java.Field{holder: ${this.holder}, fieldType: ${this.fieldType}, fieldReturnType: ${this.fieldReturnType}, value: ${this.value}}`;
      if (inlineString.length < 200) {
        return inlineString;
      }
      const multilineString = `Java.Field{
\tholder: ${this.holder},
\tfieldType: ${this.fieldType},
\tfieldReturnType: ${this.fieldReturnType},
\tvalue: ${this.value},
}`;
      return multilineString.split('\n').map(l => l.length > 200 ? l.slice(0, l.indexOf(' ') + 1) + '...,' : l).join('\n');
    }
  }
});

class DexFile {
  static fromBuffer (buffer, factory) {
    const fileValue = createTemporaryDex(factory);
    const filePath = fileValue.getCanonicalPath().toString();

    const file = new File(filePath, 'w');
    file.write(buffer.buffer);
    file.close();
    setReadOnlyDex(filePath, factory);

    return new DexFile(filePath, fileValue, factory);
  }

  constructor (path, file, factory) {
    this.path = path;
    this.file = file;

    this._factory = factory;
  }

  load () {
    const { _factory: factory } = this;
    const { codeCacheDir } = factory;
    const DexClassLoader = factory.use('dalvik.system.DexClassLoader');
    const JFile = factory.use('java.io.File');

    let file = this.file;
    if (file === null) {
      file = factory.use('java.io.File').$new(this.path);
    }
    if (!file.exists()) {
      throw new Error('File not found');
    }

    JFile.$new(codeCacheDir).mkdirs();

    factory.loader = DexClassLoader.$new(file.getCanonicalPath(), codeCacheDir, null, factory.loader);

    vm.preventDetachDueToClassLoader();
  }

  getClassNames () {
    const { _factory: factory } = this;
    const DexFile = factory.use('dalvik.system.DexFile');

    const optimizedDex = createTemporaryDex(factory);
    const dx = DexFile.loadDex(this.path, optimizedDex.getCanonicalPath(), 0);

    const classNames = [];
    const enumeratorClassNames = dx.entries();
    while (enumeratorClassNames.hasMoreElements()) {
      classNames.push(enumeratorClassNames.nextElement().toString());
    }
    return classNames;
  }
}

function createTemporaryDex (factory) {
  const { cacheDir, tempFileNaming } = factory;
  const JFile = factory.use('java.io.File');

  const cacheDirValue = JFile.$new(cacheDir);
  cacheDirValue.mkdirs();

  return JFile.createTempFile(tempFileNaming.prefix, tempFileNaming.suffix + '.dex', cacheDirValue);
}

function setReadOnlyDex (filePath, factory) {
  const JFile = factory.use('java.io.File');
  const file = JFile.$new(filePath);
  file.setWritable(false, false);
}

function getFactoryCache () {
  switch (factoryCache.state) {
    case 'empty': {
      factoryCache.state = 'pending';

      const defaultFactory = factoryCache.factories[0];

      const HashMap = defaultFactory.use('java.util.HashMap');
      const Integer = defaultFactory.use('java.lang.Integer');

      factoryCache.loaders = HashMap.$new();
      factoryCache.Integer = Integer;

      const loader = defaultFactory.loader;
      if (loader !== null) {
        addFactoryToCache(defaultFactory, loader);
      }

      factoryCache.state = 'ready';

      return factoryCache;
    }
    case 'pending':
      do {
        Thread.sleep(0.05);
      } while (factoryCache.state === 'pending');
      return factoryCache;
    case 'ready':
      return factoryCache;
  }
}

function addFactoryToCache (factory, loader) {
  const { factories, loaders, Integer } = factoryCache;

  const index = Integer.$new(factories.indexOf(factory));
  loaders.put(loader, index);

  for (let l = loader.getParent(); l !== null; l = l.getParent()) {
    if (loaders.containsKey(l)) {
      break;
    }

    loaders.put(l, index);
  }
}

function ignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    count = 0;
  }
  count++;
  ignoredThreads.set(threadId, count);
}

function unignore (threadId) {
  let count = ignoredThreads.get(threadId);
  if (count === undefined) {
    throw new Error(`Thread ${threadId} is not ignored`);
  }
  count--;
  if (count === 0) {
    ignoredThreads.delete(threadId);
  } else {
    ignoredThreads.set(threadId, count);
  }
}

function basename (className) {
  return className.slice(className.lastIndexOf('.') + 1);
}

function readTypeNames (env, types) {
  const names = [];

  const n = env.getArrayLength(types);
  for (let i = 0; i !== n; i++) {
    const t = env.getObjectArrayElement(types, i);
    try {
      names.push(env.getTypeName(t));
    } finally {
      env.deleteLocalRef(t);
    }
  }

  return names;
}

function makeSourceFileName (className) {
  const tokens = className.split('.');
  return tokens[tokens.length - 1] + '.java';
}

✄
import { withRunnableArtThread, getArtClassSpec, getArtMethodSpec, getArtFieldSpec } from './android.js';
import getApi from './api.js';

const code = `#include <json-glib/json-glib.h>
#include <string.h>

#define kAccStatic 0x0008
#define kAccConstructor 0x00010000

typedef struct _Model Model;
typedef struct _EnumerateMethodsContext EnumerateMethodsContext;

typedef struct _JavaApi JavaApi;
typedef struct _JavaClassApi JavaClassApi;
typedef struct _JavaMethodApi JavaMethodApi;
typedef struct _JavaFieldApi JavaFieldApi;

typedef struct _JNIEnv JNIEnv;
typedef guint8 jboolean;
typedef gint32 jint;
typedef jint jsize;
typedef gpointer jobject;
typedef jobject jclass;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef gpointer jfieldID;
typedef gpointer jmethodID;

typedef struct _jvmtiEnv jvmtiEnv;
typedef enum
{
  JVMTI_ERROR_NONE = 0
} jvmtiError;

typedef struct _ArtApi ArtApi;
typedef guint32 ArtHeapReference;
typedef struct _ArtObject ArtObject;
typedef struct _ArtClass ArtClass;
typedef struct _ArtClassLinker ArtClassLinker;
typedef struct _ArtClassVisitor ArtClassVisitor;
typedef struct _ArtClassVisitorVTable ArtClassVisitorVTable;
typedef struct _ArtMethod ArtMethod;
typedef struct _ArtString ArtString;

typedef union _StdString StdString;
typedef struct _StdStringShort StdStringShort;
typedef struct _StdStringLong StdStringLong;

typedef void (* ArtVisitClassesFunc) (ArtClassLinker * linker, ArtClassVisitor * visitor);
typedef const char * (* ArtGetClassDescriptorFunc) (ArtClass * klass, StdString * storage);
typedef void (* ArtPrettyMethodFunc) (StdString * result, ArtMethod * method, jboolean with_signature);

struct _Model
{
  GHashTable * members;
};

struct _EnumerateMethodsContext
{
  GPatternSpec * class_query;
  GPatternSpec * method_query;
  jboolean include_signature;
  jboolean ignore_case;
  jboolean skip_system_classes;
  GHashTable * groups;
};

struct _JavaClassApi
{
  jmethodID get_declared_methods;
  jmethodID get_declared_fields;
};

struct _JavaMethodApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaFieldApi
{
  jmethodID get_name;
  jmethodID get_modifiers;
};

struct _JavaApi
{
  jvmtiEnv * jvmti;
  JavaClassApi clazz;
  JavaMethodApi method;
  JavaFieldApi field;
};

struct _JNIEnv
{
  gpointer * functions;
};

struct _jvmtiEnv
{
  gpointer * functions;
};

struct _ArtApi
{
  gboolean available;

  guint class_offset_ifields;
  guint class_offset_methods;
  guint class_offset_sfields;
  guint class_offset_copied_methods_offset;

  guint method_size;
  guint method_offset_access_flags;

  guint field_size;
  guint field_offset_access_flags;

  guint alignment_padding;

  ArtClassLinker * linker;
  ArtVisitClassesFunc visit_classes;
  ArtGetClassDescriptorFunc get_class_descriptor;
  ArtPrettyMethodFunc pretty_method;

  void (* free) (gpointer mem);
};

struct _ArtObject
{
  ArtHeapReference klass;
  ArtHeapReference monitor;
};

struct _ArtClass
{
  ArtObject parent;

  ArtHeapReference class_loader;
};

struct _ArtClassVisitor
{
  ArtClassVisitorVTable * vtable;
  gpointer user_data;
};

struct _ArtClassVisitorVTable
{
  void (* reserved1) (ArtClassVisitor * self);
  void (* reserved2) (ArtClassVisitor * self);
  jboolean (* visit) (ArtClassVisitor * self, ArtClass * klass);
};

struct _ArtString
{
  ArtObject parent;

  gint32 count;
  guint32 hash_code;

  union
  {
    guint16 value[0];
    guint8 value_compressed[0];
  };
};

struct _StdStringShort
{
  guint8 size;
  gchar data[(3 * sizeof (gpointer)) - sizeof (guint8)];
};

struct _StdStringLong
{
  gsize capacity;
  gsize size;
  gchar * data;
};

union _StdString
{
  StdStringShort s;
  StdStringLong l;
};

static void model_add_method (Model * self, const gchar * name, jmethodID id, jint modifiers);
static void model_add_field (Model * self, const gchar * name, jfieldID id, jint modifiers);
static void model_free (Model * model);

static jboolean collect_matching_class_methods (ArtClassVisitor * self, ArtClass * klass);
static gchar * finalize_method_groups_to_json (GHashTable * groups);
static GPatternSpec * make_pattern_spec (const gchar * pattern, jboolean ignore_case);
static gchar * class_name_from_signature (const gchar * signature);
static gchar * format_method_signature (const gchar * name, const gchar * signature);
static void append_type (GString * output, const gchar ** type);

static gpointer read_art_array (gpointer object_base, guint field_offset, guint length_size, guint * length);

static void std_string_destroy (StdString * str);
static gchar * std_string_c_str (StdString * self);

extern GMutex lock;
extern GArray * models;
extern JavaApi java_api;
extern ArtApi art_api;

void
init (void)
{
  g_mutex_init (&lock);
  models = g_array_new (FALSE, FALSE, sizeof (Model *));
}

void
finalize (void)
{
  guint n, i;

  n = models->len;
  for (i = 0; i != n; i++)
  {
    Model * model = g_array_index (models, Model *, i);
    model_free (model);
  }

  g_array_unref (models);
  g_mutex_clear (&lock);
}

Model *
model_new (jclass class_handle,
           gpointer class_object,
           JNIEnv * env)
{
  Model * model;
  GHashTable * members;
  jvmtiEnv * jvmti = java_api.jvmti;
  gpointer * funcs = env->functions;
  jmethodID (* from_reflected_method) (JNIEnv *, jobject) = funcs[7];
  jfieldID (* from_reflected_field) (JNIEnv *, jobject) = funcs[8];
  jobject (* to_reflected_method) (JNIEnv *, jclass, jmethodID, jboolean) = funcs[9];
  jobject (* to_reflected_field) (JNIEnv *, jclass, jfieldID, jboolean) = funcs[12];
  void (* delete_local_ref) (JNIEnv *, jobject) = funcs[23];
  jobject (* call_object_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[34];
  jint (* call_int_method) (JNIEnv *, jobject, jmethodID, ...) = funcs[49];
  const char * (* get_string_utf_chars) (JNIEnv *, jstring, jboolean *) = funcs[169];
  void (* release_string_utf_chars) (JNIEnv *, jstring, const char *) = funcs[170];
  jsize (* get_array_length) (JNIEnv *, jarray) = funcs[171];
  jobject (* get_object_array_element) (JNIEnv *, jobjectArray, jsize) = funcs[173];
  jsize n, i;

  model = g_new (Model, 1);

  members = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
  model->members = members;

  if (jvmti != NULL)
  {
    gpointer * jf = jvmti->functions - 1;
    jvmtiError (* deallocate) (jvmtiEnv *, void * mem) = jf[47];
    jvmtiError (* get_class_methods) (jvmtiEnv *, jclass, jint *, jmethodID **) = jf[52];
    jvmtiError (* get_class_fields) (jvmtiEnv *, jclass, jint *, jfieldID **) = jf[53];
    jvmtiError (* get_field_name) (jvmtiEnv *, jclass, jfieldID, char **, char **, char **) = jf[60];
    jvmtiError (* get_field_modifiers) (jvmtiEnv *, jclass, jfieldID, jint *) = jf[62];
    jvmtiError (* get_method_name) (jvmtiEnv *, jmethodID, char **, char **, char **) = jf[64];
    jvmtiError (* get_method_modifiers) (jvmtiEnv *, jmethodID, jint *) = jf[66];
    jint method_count;
    jmethodID * methods;
    jint field_count;
    jfieldID * fields;
    char * name;
    jint modifiers;

    get_class_methods (jvmti, class_handle, &method_count, &methods);
    for (i = 0; i != method_count; i++)
    {
      jmethodID method = methods[i];

      get_method_name (jvmti, method, &name, NULL, NULL);
      get_method_modifiers (jvmti, method, &modifiers);

      model_add_method (model, name, method, modifiers);

      deallocate (jvmti, name);
    }
    deallocate (jvmti, methods);

    get_class_fields (jvmti, class_handle, &field_count, &fields);
    for (i = 0; i != field_count; i++)
    {
      jfieldID field = fields[i];

      get_field_name (jvmti, class_handle, field, &name, NULL, NULL);
      get_field_modifiers (jvmti, class_handle, field, &modifiers);

      model_add_field (model, name, field, modifiers);

      deallocate (jvmti, name);
    }
    deallocate (jvmti, fields);
  }
  else if (art_api.available)
  {
    gpointer elements;
    guint n, i;
    const guint field_arrays[] = {
      art_api.class_offset_ifields,
      art_api.class_offset_sfields
    };
    guint field_array_cursor;
    gboolean merged_fields = art_api.class_offset_sfields == 0;

    elements = read_art_array (class_object, art_api.class_offset_methods, sizeof (gsize), NULL);
    n = *(guint16 *) (class_object + art_api.class_offset_copied_methods_offset);
    for (i = 0; i != n; i++)
    {
      jmethodID id;
      guint32 access_flags;
      jboolean is_static;
      jobject method, name;
      const char * name_str;
      jint modifiers;

      id = elements + (i * art_api.method_size);

      access_flags = *(guint32 *) (id + art_api.method_offset_access_flags);
      if ((access_flags & kAccConstructor) != 0)
        continue;
      is_static = (access_flags & kAccStatic) != 0;
      method = to_reflected_method (env, class_handle, id, is_static);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      modifiers = access_flags & 0xffff;

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }

    for (field_array_cursor = 0; field_array_cursor != G_N_ELEMENTS (field_arrays); field_array_cursor++)
    {
      jboolean is_static;

      if (field_arrays[field_array_cursor] == 0)
        continue;

      if (!merged_fields)
        is_static = field_array_cursor == 1;

      elements = read_art_array (class_object, field_arrays[field_array_cursor], sizeof (guint32), &n);
      for (i = 0; i != n; i++)
      {
        jfieldID id;
        guint32 access_flags;
        jobject field, name;
        const char * name_str;
        jint modifiers;

        id = elements + (i * art_api.field_size);

        access_flags = *(guint32 *) (id + art_api.field_offset_access_flags);
        if (merged_fields)
          is_static = (access_flags & kAccStatic) != 0;
        field = to_reflected_field (env, class_handle, id, is_static);
        name = call_object_method (env, field, java_api.field.get_name);
        name_str = get_string_utf_chars (env, name, NULL);
        modifiers = access_flags & 0xffff;

        model_add_field (model, name_str, id, modifiers);

        release_string_utf_chars (env, name, name_str);
        delete_local_ref (env, name);
        delete_local_ref (env, field);
      }
    }
  }
  else
  {
    jobject elements;

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_methods);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject method, name;
      const char * name_str;
      jmethodID id;
      jint modifiers;

      method = get_object_array_element (env, elements, i);
      name = call_object_method (env, method, java_api.method.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_method (env, method);
      modifiers = call_int_method (env, method, java_api.method.get_modifiers);

      model_add_method (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, method);
    }
    delete_local_ref (env, elements);

    elements = call_object_method (env, class_handle, java_api.clazz.get_declared_fields);
    n = get_array_length (env, elements);
    for (i = 0; i != n; i++)
    {
      jobject field, name;
      const char * name_str;
      jfieldID id;
      jint modifiers;

      field = get_object_array_element (env, elements, i);
      name = call_object_method (env, field, java_api.field.get_name);
      name_str = get_string_utf_chars (env, name, NULL);
      id = from_reflected_field (env, field);
      modifiers = call_int_method (env, field, java_api.field.get_modifiers);

      model_add_field (model, name_str, id, modifiers);

      release_string_utf_chars (env, name, name_str);
      delete_local_ref (env, name);
      delete_local_ref (env, field);
    }
    delete_local_ref (env, elements);
  }

  g_mutex_lock (&lock);
  g_array_append_val (models, model);
  g_mutex_unlock (&lock);

  return model;
}

static void
model_add_method (Model * self,
                  const gchar * name,
                  jmethodID id,
                  jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key, type;
  const gchar * value;

  if (name[0] == '$')
    key = g_strdup_printf ("_%s", name);
  else
    key = g_strdup (name);

  type = (modifiers & kAccStatic) != 0 ? 's' : 'i';

  value = g_hash_table_lookup (members, key);
  if (value == NULL)
    g_hash_table_insert (members, key, g_strdup_printf ("m:%c0x%zx", type, id));
  else
    g_hash_table_insert (members, key, g_strdup_printf ("%s:%c0x%zx", value, type, id));
}

static void
model_add_field (Model * self,
                 const gchar * name,
                 jfieldID id,
                 jint modifiers)
{
  GHashTable * members = self->members;
  gchar * key, type;

  if (name[0] == '$')
    key = g_strdup_printf ("_%s", name);
  else
    key = g_strdup (name);
  while (g_hash_table_contains (members, key))
  {
    gchar * new_key = g_strdup_printf ("_%s", key);
    g_free (key);
    key = new_key;
  }

  type = (modifiers & kAccStatic) != 0 ? 's' : 'i';

  g_hash_table_insert (members, key, g_strdup_printf ("f:%c0x%zx", type, id));
}

static void
model_free (Model * model)
{
  g_hash_table_unref (model->members);

  g_free (model);
}

gboolean
model_has (Model * self,
           const gchar * member)
{
  return g_hash_table_contains (self->members, member);
}

const gchar *
model_find (Model * self,
            const gchar * member)
{
  return g_hash_table_lookup (self->members, member);
}

gchar *
model_list (Model * self)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  const gchar * name;

  result = g_string_sized_new (128);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, self->members);
  for (i = 0; g_hash_table_iter_next (&iter, (gpointer *) &name, NULL); i++)
  {
    if (i > 0)
      g_string_append_c (result, ',');

    g_string_append_c (result, '"');
    g_string_append (result, name);
    g_string_append_c (result, '"');
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

gchar *
enumerate_methods_art (const gchar * class_query,
                       const gchar * method_query,
                       jboolean include_signature,
                       jboolean ignore_case,
                       jboolean skip_system_classes)
{
  gchar * result;
  EnumerateMethodsContext ctx;
  ArtClassVisitor visitor;
  ArtClassVisitorVTable visitor_vtable = { NULL, };

  ctx.class_query = make_pattern_spec (class_query, ignore_case);
  ctx.method_query = make_pattern_spec (method_query, ignore_case);
  ctx.include_signature = include_signature;
  ctx.ignore_case = ignore_case;
  ctx.skip_system_classes = skip_system_classes;
  ctx.groups = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  visitor.vtable = &visitor_vtable;
  visitor.user_data = &ctx;

  visitor_vtable.visit = collect_matching_class_methods;

  art_api.visit_classes (art_api.linker, &visitor);

  result = finalize_method_groups_to_json (ctx.groups);

  g_hash_table_unref (ctx.groups);
  g_pattern_spec_free (ctx.method_query);
  g_pattern_spec_free (ctx.class_query);

  return result;
}

static jboolean
collect_matching_class_methods (ArtClassVisitor * self,
                                ArtClass * klass)
{
  EnumerateMethodsContext * ctx = self->user_data;
  const char * descriptor;
  StdString descriptor_storage = { 0, };
  gchar * class_name = NULL;
  gchar * class_name_copy = NULL;
  const gchar * normalized_class_name;
  JsonBuilder * group;
  size_t class_name_length;
  GHashTable * seen_method_names;
  gpointer elements;
  guint n, i;

  if (ctx->skip_system_classes && klass->class_loader == 0)
    goto skip_class;

  descriptor = art_api.get_class_descriptor (klass, &descriptor_storage);
  if (descriptor[0] != 'L')
    goto skip_class;

  class_name = class_name_from_signature (descriptor);

  if (ctx->ignore_case)
  {
    class_name_copy = g_utf8_strdown (class_name, -1);
    normalized_class_name = class_name_copy;
  }
  else
  {
    normalized_class_name = class_name;
  }

  if (!g_pattern_match_string (ctx->class_query, normalized_class_name))
    goto skip_class;

  group = NULL;
  class_name_length = strlen (class_name);
  seen_method_names = ctx->include_signature ? NULL : g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  elements = read_art_array (klass, art_api.class_offset_methods, sizeof (gsize), NULL);
  n = *(guint16 *) ((gpointer) klass + art_api.class_offset_copied_methods_offset);
  for (i = 0; i != n; i++)
  {
    ArtMethod * method;
    guint32 access_flags;
    jboolean is_constructor;
    StdString method_name = { 0, };
    const gchar * bare_method_name;
    gchar * bare_method_name_copy = NULL;
    const gchar * normalized_method_name;
    gchar * normalized_method_name_copy = NULL;

    method = elements + (i * art_api.method_size);

    access_flags = *(guint32 *) ((gpointer) method + art_api.method_offset_access_flags);
    is_constructor = (access_flags & kAccConstructor) != 0;

    art_api.pretty_method (&method_name, method, ctx->include_signature);
    bare_method_name = std_string_c_str (&method_name);
    if (ctx->include_signature)
    {
      const gchar * return_type_end, * name_begin;
      GString * name;

      return_type_end = strchr (bare_method_name, ' ');
      name_begin = return_type_end + 1 + class_name_length + 1;
      if (is_constructor && g_str_has_prefix (name_begin, "<clinit>"))
        goto skip_method;

      name = g_string_sized_new (64);

      if (is_constructor)
      {
        g_string_append (name, "$init");
        g_string_append (name, strchr (name_begin, '>') + 1);
      }
      else
      {
        g_string_append (name, name_begin);
      }
      g_string_append (name, ": ");
      g_string_append_len (name, bare_method_name, return_type_end - bare_method_name);

      bare_method_name_copy = g_string_free (name, FALSE);
      bare_method_name = bare_method_name_copy;
    }
    else
    {
      const gchar * name_begin;

      name_begin = bare_method_name + class_name_length + 1;
      if (is_constructor && strcmp (name_begin, "<clinit>") == 0)
        goto skip_method;

      if (is_constructor)
        bare_method_name = "$init";
      else
        bare_method_name += class_name_length + 1;
    }

    if (seen_method_names != NULL && g_hash_table_contains (seen_method_names, bare_method_name))
      goto skip_method;

    if (ctx->ignore_case)
    {
      normalized_method_name_copy = g_utf8_strdown (bare_method_name, -1);
      normalized_method_name = normalized_method_name_copy;
    }
    else
    {
      normalized_method_name = bare_method_name;
    }

    if (!g_pattern_match_string (ctx->method_query, normalized_method_name))
      goto skip_method;

    if (group == NULL)
    {
      group = g_hash_table_lookup (ctx->groups, GUINT_TO_POINTER (klass->class_loader));
      if (group == NULL)
      {
        group = json_builder_new_immutable ();
        g_hash_table_insert (ctx->groups, GUINT_TO_POINTER (klass->class_loader), group);

        json_builder_begin_object (group);

        json_builder_set_member_name (group, "loader");
        json_builder_add_int_value (group, klass->class_loader);

        json_builder_set_member_name (group, "classes");
        json_builder_begin_array (group);
      }

      json_builder_begin_object (group);

      json_builder_set_member_name (group, "name");
      json_builder_add_string_value (group, class_name);

      json_builder_set_member_name (group, "methods");
      json_builder_begin_array (group);
    }

    json_builder_add_string_value (group, bare_method_name);

    if (seen_method_names != NULL)
      g_hash_table_add (seen_method_names, g_strdup (bare_method_name));

skip_method:
    g_free (normalized_method_name_copy);
    g_free (bare_method_name_copy);
    std_string_destroy (&method_name);
  }

  if (seen_method_names != NULL)
    g_hash_table_unref (seen_method_names);

  if (group == NULL)
    goto skip_class;

  json_builder_end_array (group);
  json_builder_end_object (group);

skip_class:
  g_free (class_name_copy);
  g_free (class_name);
  std_string_destroy (&descriptor_storage);

  return TRUE;
}

gchar *
enumerate_methods_jvm (const gchar * class_query,
                       const gchar * method_query,
                       jboolean include_signature,
                       jboolean ignore_case,
                       jboolean skip_system_classes,
                       JNIEnv * env)
{
  gchar * result;
  GPatternSpec * class_pattern, * method_pattern;
  GHashTable * groups;
  gpointer * ef = env->functions;
  jobject (* new_global_ref) (JNIEnv *, jobject) = ef[21];
  void (* delete_local_ref) (JNIEnv *, jobject) = ef[23];
  jboolean (* is_same_object) (JNIEnv *, jobject, jobject) = ef[24];
  jvmtiEnv * jvmti = java_api.jvmti;
  gpointer * jf = jvmti->functions - 1;
  jvmtiError (* deallocate) (jvmtiEnv *, void * mem) = jf[47];
  jvmtiError (* get_class_signature) (jvmtiEnv *, jclass, char **, char **) = jf[48];
  jvmtiError (* get_class_methods) (jvmtiEnv *, jclass, jint *, jmethodID **) = jf[52];
  jvmtiError (* get_class_loader) (jvmtiEnv *, jclass, jobject *) = jf[57];
  jvmtiError (* get_method_name) (jvmtiEnv *, jmethodID, char **, char **, char **) = jf[64];
  jvmtiError (* get_loaded_classes) (jvmtiEnv *, jint *, jclass **) = jf[78];
  jint class_count, class_index;
  jclass * classes;

  class_pattern = make_pattern_spec (class_query, ignore_case);
  method_pattern = make_pattern_spec (method_query, ignore_case);
  groups = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  if (get_loaded_classes (jvmti, &class_count, &classes) != JVMTI_ERROR_NONE)
    goto emit_results;

  for (class_index = 0; class_index != class_count; class_index++)
  {
    jclass klass = classes[class_index];
    jobject loader = NULL;
    gboolean have_loader = FALSE;
    char * signature = NULL;
    gchar * class_name = NULL;
    gchar * class_name_copy = NULL;
    const gchar * normalized_class_name;
    jint method_count, method_index;
    jmethodID * methods = NULL;
    JsonBuilder * group = NULL;
    GHashTable * seen_method_names = NULL;

    if (skip_system_classes)
    {
      if (get_class_loader (jvmti, klass, &loader) != JVMTI_ERROR_NONE)
        goto skip_class;
      have_loader = TRUE;

      if (loader == NULL)
        goto skip_class;
    }

    if (get_class_signature (jvmti, klass, &signature, NULL) != JVMTI_ERROR_NONE)
      goto skip_class;

    class_name = class_name_from_signature (signature);

    if (ignore_case)
    {
      class_name_copy = g_utf8_strdown (class_name, -1);
      normalized_class_name = class_name_copy;
    }
    else
    {
      normalized_class_name = class_name;
    }

    if (!g_pattern_match_string (class_pattern, normalized_class_name))
      goto skip_class;

    if (get_class_methods (jvmti, klass, &method_count, &methods) != JVMTI_ERROR_NONE)
      goto skip_class;

    if (!include_signature)
      seen_method_names = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

    for (method_index = 0; method_index != method_count; method_index++)
    {
      jmethodID method = methods[method_index];
      const gchar * method_name;
      char * method_name_value = NULL;
      char * method_signature_value = NULL;
      gchar * method_name_copy = NULL;
      const gchar * normalized_method_name;
      gchar * normalized_method_name_copy = NULL;

      if (get_method_name (jvmti, method, &method_name_value, include_signature ? &method_signature_value : NULL, NULL) != JVMTI_ERROR_NONE)
        goto skip_method;
      method_name = method_name_value;

      if (method_name[0] == '<')
      {
        if (strcmp (method_name, "<init>") == 0)
          method_name = "$init";
        else if (strcmp (method_name, "<clinit>") == 0)
          goto skip_method;
      }

      if (include_signature)
      {
        method_name_copy = format_method_signature (method_name, method_signature_value);
        method_name = method_name_copy;
      }

      if (seen_method_names != NULL && g_hash_table_contains (seen_method_names, method_name))
        goto skip_method;

      if (ignore_case)
      {
        normalized_method_name_copy = g_utf8_strdown (method_name, -1);
        normalized_method_name = normalized_method_name_copy;
      }
      else
      {
        normalized_method_name = method_name;
      }

      if (!g_pattern_match_string (method_pattern, normalized_method_name))
        goto skip_method;

      if (group == NULL)
      {
        if (!have_loader && get_class_loader (jvmti, klass, &loader) != JVMTI_ERROR_NONE)
          goto skip_method;

        if (loader == NULL)
        {
          group = g_hash_table_lookup (groups, NULL);
        }
        else
        {
          GHashTableIter iter;
          jobject cur_loader;
          JsonBuilder * cur_group;

          g_hash_table_iter_init (&iter, groups);
          while (g_hash_table_iter_next (&iter, (gpointer *) &cur_loader, (gpointer *) &cur_group))
          {
            if (cur_loader != NULL && is_same_object (env, cur_loader, loader))
            {
              group = cur_group;
              break;
            }
          }
        }

        if (group == NULL)
        {
          jobject l;
          gchar * str;

          l = (loader != NULL) ? new_global_ref (env, loader) : NULL;

          group = json_builder_new_immutable ();
          g_hash_table_insert (groups, l, group);

          json_builder_begin_object (group);

          json_builder_set_member_name (group, "loader");
          str = g_strdup_printf ("0x%" G_GSIZE_MODIFIER "x", GPOINTER_TO_SIZE (l));
          json_builder_add_string_value (group, str);
          g_free (str);

          json_builder_set_member_name (group, "classes");
          json_builder_begin_array (group);
        }

        json_builder_begin_object (group);

        json_builder_set_member_name (group, "name");
        json_builder_add_string_value (group, class_name);

        json_builder_set_member_name (group, "methods");
        json_builder_begin_array (group);
      }

      json_builder_add_string_value (group, method_name);

      if (seen_method_names != NULL)
        g_hash_table_add (seen_method_names, g_strdup (method_name));

skip_method:
      g_free (normalized_method_name_copy);
      g_free (method_name_copy);
      deallocate (jvmti, method_signature_value);
      deallocate (jvmti, method_name_value);
    }

skip_class:
    if (group != NULL)
    {
      json_builder_end_array (group);
      json_builder_end_object (group);
    }

    if (seen_method_names != NULL)
      g_hash_table_unref (seen_method_names);

    deallocate (jvmti, methods);

    g_free (class_name_copy);
    g_free (class_name);
    deallocate (jvmti, signature);

    if (loader != NULL)
      delete_local_ref (env, loader);

    delete_local_ref (env, klass);
  }

  deallocate (jvmti, classes);

emit_results:
  result = finalize_method_groups_to_json (groups);

  g_hash_table_unref (groups);
  g_pattern_spec_free (method_pattern);
  g_pattern_spec_free (class_pattern);

  return result;
}

static gchar *
finalize_method_groups_to_json (GHashTable * groups)
{
  GString * result;
  GHashTableIter iter;
  guint i;
  JsonBuilder * group;

  result = g_string_sized_new (1024);

  g_string_append_c (result, '[');

  g_hash_table_iter_init (&iter, groups);
  for (i = 0; g_hash_table_iter_next (&iter, NULL, (gpointer *) &group); i++)
  {
    JsonNode * root;
    gchar * json;

    if (i > 0)
      g_string_append_c (result, ',');

    json_builder_end_array (group);
    json_builder_end_object (group);

    root = json_builder_get_root (group);
    json = json_to_string (root, FALSE);
    g_string_append (result, json);
    g_free (json);
    json_node_unref (root);

    g_object_unref (group);
  }

  g_string_append_c (result, ']');

  return g_string_free (result, FALSE);
}

static GPatternSpec *
make_pattern_spec (const gchar * pattern,
                   jboolean ignore_case)
{
  GPatternSpec * spec;

  if (ignore_case)
  {
    gchar * str = g_utf8_strdown (pattern, -1);
    spec = g_pattern_spec_new (str);
    g_free (str);
  }
  else
  {
    spec = g_pattern_spec_new (pattern);
  }

  return spec;
}

static gchar *
class_name_from_signature (const gchar * descriptor)
{
  gchar * result, * c;

  result = g_strdup (descriptor + 1);

  for (c = result; *c != '\\0'; c++)
  {
    if (*c == '/')
      *c = '.';
  }

  c[-1] = '\\0';

  return result;
}

static gchar *
format_method_signature (const gchar * name,
                         const gchar * signature)
{
  GString * sig;
  const gchar * cursor;
  gint arg_index;

  sig = g_string_sized_new (128);

  g_string_append (sig, name);

  cursor = signature;
  arg_index = -1;
  while (TRUE)
  {
    const gchar c = *cursor;

    if (c == '(')
    {
      g_string_append_c (sig, c);
      cursor++;
      arg_index = 0;
    }
    else if (c == ')')
    {
      g_string_append_c (sig, c);
      cursor++;
      break;
    }
    else
    {
      if (arg_index >= 1)
        g_string_append (sig, ", ");

      append_type (sig, &cursor);

      if (arg_index != -1)
        arg_index++;
    }
  }

  g_string_append (sig, ": ");
  append_type (sig, &cursor);

  return g_string_free (sig, FALSE);
}

static void
append_type (GString * output,
             const gchar ** type)
{
  const gchar * cursor = *type;

  switch (*cursor)
  {
    case 'Z':
      g_string_append (output, "boolean");
      cursor++;
      break;
    case 'B':
      g_string_append (output, "byte");
      cursor++;
      break;
    case 'C':
      g_string_append (output, "char");
      cursor++;
      break;
    case 'S':
      g_string_append (output, "short");
      cursor++;
      break;
    case 'I':
      g_string_append (output, "int");
      cursor++;
      break;
    case 'J':
      g_string_append (output, "long");
      cursor++;
      break;
    case 'F':
      g_string_append (output, "float");
      cursor++;
      break;
    case 'D':
      g_string_append (output, "double");
      cursor++;
      break;
    case 'V':
      g_string_append (output, "void");
      cursor++;
      break;
    case 'L':
    {
      gchar ch;

      cursor++;
      for (; (ch = *cursor) != ';'; cursor++)
      {
        g_string_append_c (output, (ch != '/') ? ch : '.');
      }
      cursor++;

      break;
    }
    case '[':
      *type = cursor + 1;
      append_type (output, type);
      g_string_append (output, "[]");
      return;
    default:
      g_string_append (output, "BUG");
      cursor++;
  }

  *type = cursor;
}

void
dealloc (gpointer mem)
{
  g_free (mem);
}

static gpointer
read_art_array (gpointer object_base,
                guint field_offset,
                guint length_size,
                guint * length)
{
  gpointer result, header;
  guint n;

  header = GSIZE_TO_POINTER (*(guint64 *) (object_base + field_offset));
  if (header != NULL)
  {
    result = header + length_size;
    if (length_size == sizeof (guint32))
      n = *(guint32 *) header;
    else
      n = *(guint64 *) header;
  }
  else
  {
    result = NULL;
    n = 0;
  }

  if (length != NULL)
    *length = n;

  return result;
}

static void
std_string_destroy (StdString * str)
{
  if ((str->l.capacity & 1) != 0)
    art_api.free (str->l.data);
}

static gchar *
std_string_c_str (StdString * self)
{
  if ((self->l.capacity & 1) != 0)
    return self->l.data;

  return self->s.data;
}
`;

const methodQueryPattern = /(.+)!([^/]+)\/?([isu]+)?/;

let cm = null;
let unwrap = null;

export default class Model {
  static build (handle, env) {
    ensureInitialized(env);

    return unwrap(handle, env, object => {
      return new Model(cm.new(handle, object, env));
    });
  }

  static enumerateMethods (query, api, env) {
    ensureInitialized(env);

    const params = query.match(methodQueryPattern);
    if (params === null) {
      throw new Error('Invalid query; format is: class!method -- see documentation of Java.enumerateMethods(query) for details');
    }

    const classQuery = Memory.allocUtf8String(params[1]);
    const methodQuery = Memory.allocUtf8String(params[2]);

    let includeSignature = false;
    let ignoreCase = false;
    let skipSystemClasses = false;

    const modifiers = params[3];
    if (modifiers !== undefined) {
      includeSignature = modifiers.indexOf('s') !== -1;
      ignoreCase = modifiers.indexOf('i') !== -1;
      skipSystemClasses = modifiers.indexOf('u') !== -1;
    }

    let result;
    if (api.jvmti !== null) {
      const json = cm.enumerateMethodsJvm(classQuery, methodQuery,
        boolToNative(includeSignature), boolToNative(ignoreCase), boolToNative(skipSystemClasses),
        env);
      try {
        result = JSON.parse(json.readUtf8String())
          .map(group => {
            const loaderRef = ptr(group.loader);
            group.loader = !loaderRef.isNull() ? loaderRef : null;
            return group;
          });
      } finally {
        cm.dealloc(json);
      }
    } else {
      withRunnableArtThread(env.vm, env, thread => {
        const json = cm.enumerateMethodsArt(classQuery, methodQuery,
          boolToNative(includeSignature), boolToNative(ignoreCase), boolToNative(skipSystemClasses));
        try {
          const addGlobalReference = api['art::JavaVMExt::AddGlobalRef'];
          const { vm: vmHandle } = api;
          result = JSON.parse(json.readUtf8String())
            .map(group => {
              const loaderObj = group.loader;
              group.loader = (loaderObj !== 0) ? addGlobalReference(vmHandle, thread, ptr(loaderObj)) : null;
              return group;
            });
        } finally {
          cm.dealloc(json);
        }
      });
    }

    return result;
  }

  constructor (handle) {
    this.handle = handle;
  }

  has (member) {
    return cm.has(this.handle, Memory.allocUtf8String(member)) !== 0;
  }

  find (member) {
    return cm.find(this.handle, Memory.allocUtf8String(member)).readUtf8String();
  }

  list () {
    const str = cm.list(this.handle);
    try {
      return JSON.parse(str.readUtf8String());
    } finally {
      cm.dealloc(str);
    }
  }
}

function ensureInitialized (env) {
  if (cm === null) {
    cm = compileModule(env);
    unwrap = makeHandleUnwrapper(cm, env.vm);
  }
}

function compileModule (env) {
  const api = getApi();
  const { jvmti = null } = api;

  const { pointerSize } = Process;

  const lockSize = 8;
  const modelsSize = pointerSize;
  const javaApiSize = 7 * pointerSize;
  const artApiSize = (10 * 4) + (5 * pointerSize);

  const dataSize = lockSize + modelsSize + javaApiSize + artApiSize;
  const data = Memory.alloc(dataSize);

  const lock = data;

  const models = lock.add(lockSize);

  const javaApi = models.add(modelsSize);
  const { getDeclaredMethods, getDeclaredFields } = env.javaLangClass();
  const method = env.javaLangReflectMethod();
  const field = env.javaLangReflectField();
  let j = javaApi;
  [
    (jvmti !== null) ? jvmti : NULL,
    getDeclaredMethods, getDeclaredFields,
    method.getName, method.getModifiers,
    field.getName, field.getModifiers
  ]
    .forEach(value => {
      j = j.writePointer(value).add(pointerSize);
    });

  const artApi = javaApi.add(javaApiSize);
  const { vm } = env;
  if (api.flavor === 'art') {
    let artClassOffsets;
    if (jvmti !== null) {
      artClassOffsets = [0, 0, 0, 0];
    } else {
      const c = getArtClassSpec(vm).offset;
      artClassOffsets = [c.ifields, c.methods, c.sfields, c.copiedMethodsOffset];
    }

    const m = getArtMethodSpec(vm);
    const f = getArtFieldSpec(vm);

    let s = artApi;
    [
      1,
      ...artClassOffsets,
      m.size, m.offset.accessFlags,
      f.size, f.offset.accessFlags,
      0xffffffff
    ]
      .forEach(value => {
        s = s.writeUInt(value).add(4);
      });

    [
      api.artClassLinker.address,
      api['art::ClassLinker::VisitClasses'],
      api['art::mirror::Class::GetDescriptor'],
      api['art::ArtMethod::PrettyMethod'],
      Process.getModuleByName('libc.so').getExportByName('free')
    ]
      .forEach((value, i) => {
        if (value === undefined) {
          value = NULL;
        }
        s = s.writePointer(value).add(pointerSize);
      });
  }

  const cm = new CModule(code, {
    lock,
    models,
    java_api: javaApi,
    art_api: artApi
  });

  const reentrantOptions = { exceptions: 'propagate' };
  const fastOptions = { exceptions: 'propagate', scheduling: 'exclusive' };

  return {
    handle: cm,
    new: new NativeFunction(cm.model_new, 'pointer', ['pointer', 'pointer', 'pointer'], reentrantOptions),
    has: new NativeFunction(cm.model_has, 'bool', ['pointer', 'pointer'], fastOptions),
    find: new NativeFunction(cm.model_find, 'pointer', ['pointer', 'pointer'], fastOptions),
    list: new NativeFunction(cm.model_list, 'pointer', ['pointer'], fastOptions),
    enumerateMethodsArt: new NativeFunction(cm.enumerate_methods_art, 'pointer', ['pointer', 'pointer', 'bool', 'bool', 'bool'],
      reentrantOptions),
    enumerateMethodsJvm: new NativeFunction(cm.enumerate_methods_jvm, 'pointer', ['pointer', 'pointer', 'bool', 'bool', 'bool',
      'pointer'], reentrantOptions),
    dealloc: new NativeFunction(cm.dealloc, 'void', ['pointer'], fastOptions)
  };
}

function makeHandleUnwrapper (cm, vm) {
  const api = getApi();

  if (api.flavor !== 'art') {
    return nullUnwrap;
  }

  const decodeGlobal = api['art::JavaVMExt::DecodeGlobal'];

  return function (handle, env, fn) {
    let result;

    withRunnableArtThread(vm, env, thread => {
      const object = decodeGlobal(vm, thread, handle);
      result = fn(object);
    });

    return result;
  };
}

function nullUnwrap (handle, env, fn) {
  return fn(NULL);
}

function boolToNative (val) {
  return val ? 1 : 0;
}

✄
export default function Env (handle, vm) {
  this.handle = handle;
  this.vm = vm;
}

const pointerSize = Process.pointerSize;

const JNI_ABORT = 2;

const CALL_CONSTRUCTOR_METHOD_OFFSET = 28;

const CALL_OBJECT_METHOD_OFFSET = 34;
const CALL_BOOLEAN_METHOD_OFFSET = 37;
const CALL_BYTE_METHOD_OFFSET = 40;
const CALL_CHAR_METHOD_OFFSET = 43;
const CALL_SHORT_METHOD_OFFSET = 46;
const CALL_INT_METHOD_OFFSET = 49;
const CALL_LONG_METHOD_OFFSET = 52;
const CALL_FLOAT_METHOD_OFFSET = 55;
const CALL_DOUBLE_METHOD_OFFSET = 58;
const CALL_VOID_METHOD_OFFSET = 61;

const CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET = 64;
const CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET = 67;
const CALL_NONVIRTUAL_BYTE_METHOD_OFFSET = 70;
const CALL_NONVIRTUAL_CHAR_METHOD_OFFSET = 73;
const CALL_NONVIRTUAL_SHORT_METHOD_OFFSET = 76;
const CALL_NONVIRTUAL_INT_METHOD_OFFSET = 79;
const CALL_NONVIRTUAL_LONG_METHOD_OFFSET = 82;
const CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET = 85;
const CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET = 88;
const CALL_NONVIRTUAL_VOID_METHOD_OFFSET = 91;

const CALL_STATIC_OBJECT_METHOD_OFFSET = 114;
const CALL_STATIC_BOOLEAN_METHOD_OFFSET = 117;
const CALL_STATIC_BYTE_METHOD_OFFSET = 120;
const CALL_STATIC_CHAR_METHOD_OFFSET = 123;
const CALL_STATIC_SHORT_METHOD_OFFSET = 126;
const CALL_STATIC_INT_METHOD_OFFSET = 129;
const CALL_STATIC_LONG_METHOD_OFFSET = 132;
const CALL_STATIC_FLOAT_METHOD_OFFSET = 135;
const CALL_STATIC_DOUBLE_METHOD_OFFSET = 138;
const CALL_STATIC_VOID_METHOD_OFFSET = 141;

const GET_OBJECT_FIELD_OFFSET = 95;
const GET_BOOLEAN_FIELD_OFFSET = 96;
const GET_BYTE_FIELD_OFFSET = 97;
const GET_CHAR_FIELD_OFFSET = 98;
const GET_SHORT_FIELD_OFFSET = 99;
const GET_INT_FIELD_OFFSET = 100;
const GET_LONG_FIELD_OFFSET = 101;
const GET_FLOAT_FIELD_OFFSET = 102;
const GET_DOUBLE_FIELD_OFFSET = 103;

const SET_OBJECT_FIELD_OFFSET = 104;
const SET_BOOLEAN_FIELD_OFFSET = 105;
const SET_BYTE_FIELD_OFFSET = 106;
const SET_CHAR_FIELD_OFFSET = 107;
const SET_SHORT_FIELD_OFFSET = 108;
const SET_INT_FIELD_OFFSET = 109;
const SET_LONG_FIELD_OFFSET = 110;
const SET_FLOAT_FIELD_OFFSET = 111;
const SET_DOUBLE_FIELD_OFFSET = 112;

const GET_STATIC_OBJECT_FIELD_OFFSET = 145;
const GET_STATIC_BOOLEAN_FIELD_OFFSET = 146;
const GET_STATIC_BYTE_FIELD_OFFSET = 147;
const GET_STATIC_CHAR_FIELD_OFFSET = 148;
const GET_STATIC_SHORT_FIELD_OFFSET = 149;
const GET_STATIC_INT_FIELD_OFFSET = 150;
const GET_STATIC_LONG_FIELD_OFFSET = 151;
const GET_STATIC_FLOAT_FIELD_OFFSET = 152;
const GET_STATIC_DOUBLE_FIELD_OFFSET = 153;

const SET_STATIC_OBJECT_FIELD_OFFSET = 154;
const SET_STATIC_BOOLEAN_FIELD_OFFSET = 155;
const SET_STATIC_BYTE_FIELD_OFFSET = 156;
const SET_STATIC_CHAR_FIELD_OFFSET = 157;
const SET_STATIC_SHORT_FIELD_OFFSET = 158;
const SET_STATIC_INT_FIELD_OFFSET = 159;
const SET_STATIC_LONG_FIELD_OFFSET = 160;
const SET_STATIC_FLOAT_FIELD_OFFSET = 161;
const SET_STATIC_DOUBLE_FIELD_OFFSET = 162;

const callMethodOffset = {
  pointer: CALL_OBJECT_METHOD_OFFSET,
  uint8: CALL_BOOLEAN_METHOD_OFFSET,
  int8: CALL_BYTE_METHOD_OFFSET,
  uint16: CALL_CHAR_METHOD_OFFSET,
  int16: CALL_SHORT_METHOD_OFFSET,
  int32: CALL_INT_METHOD_OFFSET,
  int64: CALL_LONG_METHOD_OFFSET,
  float: CALL_FLOAT_METHOD_OFFSET,
  double: CALL_DOUBLE_METHOD_OFFSET,
  void: CALL_VOID_METHOD_OFFSET
};

const callNonvirtualMethodOffset = {
  pointer: CALL_NONVIRTUAL_OBJECT_METHOD_OFFSET,
  uint8: CALL_NONVIRTUAL_BOOLEAN_METHOD_OFFSET,
  int8: CALL_NONVIRTUAL_BYTE_METHOD_OFFSET,
  uint16: CALL_NONVIRTUAL_CHAR_METHOD_OFFSET,
  int16: CALL_NONVIRTUAL_SHORT_METHOD_OFFSET,
  int32: CALL_NONVIRTUAL_INT_METHOD_OFFSET,
  int64: CALL_NONVIRTUAL_LONG_METHOD_OFFSET,
  float: CALL_NONVIRTUAL_FLOAT_METHOD_OFFSET,
  double: CALL_NONVIRTUAL_DOUBLE_METHOD_OFFSET,
  void: CALL_NONVIRTUAL_VOID_METHOD_OFFSET
};

const callStaticMethodOffset = {
  pointer: CALL_STATIC_OBJECT_METHOD_OFFSET,
  uint8: CALL_STATIC_BOOLEAN_METHOD_OFFSET,
  int8: CALL_STATIC_BYTE_METHOD_OFFSET,
  uint16: CALL_STATIC_CHAR_METHOD_OFFSET,
  int16: CALL_STATIC_SHORT_METHOD_OFFSET,
  int32: CALL_STATIC_INT_METHOD_OFFSET,
  int64: CALL_STATIC_LONG_METHOD_OFFSET,
  float: CALL_STATIC_FLOAT_METHOD_OFFSET,
  double: CALL_STATIC_DOUBLE_METHOD_OFFSET,
  void: CALL_STATIC_VOID_METHOD_OFFSET
};

const getFieldOffset = {
  pointer: GET_OBJECT_FIELD_OFFSET,
  uint8: GET_BOOLEAN_FIELD_OFFSET,
  int8: GET_BYTE_FIELD_OFFSET,
  uint16: GET_CHAR_FIELD_OFFSET,
  int16: GET_SHORT_FIELD_OFFSET,
  int32: GET_INT_FIELD_OFFSET,
  int64: GET_LONG_FIELD_OFFSET,
  float: GET_FLOAT_FIELD_OFFSET,
  double: GET_DOUBLE_FIELD_OFFSET
};

const setFieldOffset = {
  pointer: SET_OBJECT_FIELD_OFFSET,
  uint8: SET_BOOLEAN_FIELD_OFFSET,
  int8: SET_BYTE_FIELD_OFFSET,
  uint16: SET_CHAR_FIELD_OFFSET,
  int16: SET_SHORT_FIELD_OFFSET,
  int32: SET_INT_FIELD_OFFSET,
  int64: SET_LONG_FIELD_OFFSET,
  float: SET_FLOAT_FIELD_OFFSET,
  double: SET_DOUBLE_FIELD_OFFSET
};

const getStaticFieldOffset = {
  pointer: GET_STATIC_OBJECT_FIELD_OFFSET,
  uint8: GET_STATIC_BOOLEAN_FIELD_OFFSET,
  int8: GET_STATIC_BYTE_FIELD_OFFSET,
  uint16: GET_STATIC_CHAR_FIELD_OFFSET,
  int16: GET_STATIC_SHORT_FIELD_OFFSET,
  int32: GET_STATIC_INT_FIELD_OFFSET,
  int64: GET_STATIC_LONG_FIELD_OFFSET,
  float: GET_STATIC_FLOAT_FIELD_OFFSET,
  double: GET_STATIC_DOUBLE_FIELD_OFFSET
};

const setStaticFieldOffset = {
  pointer: SET_STATIC_OBJECT_FIELD_OFFSET,
  uint8: SET_STATIC_BOOLEAN_FIELD_OFFSET,
  int8: SET_STATIC_BYTE_FIELD_OFFSET,
  uint16: SET_STATIC_CHAR_FIELD_OFFSET,
  int16: SET_STATIC_SHORT_FIELD_OFFSET,
  int32: SET_STATIC_INT_FIELD_OFFSET,
  int64: SET_STATIC_LONG_FIELD_OFFSET,
  float: SET_STATIC_FLOAT_FIELD_OFFSET,
  double: SET_STATIC_DOUBLE_FIELD_OFFSET
};

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

let cachedVtable = null;
let globalRefs = [];
Env.dispose = function (env) {
  globalRefs.forEach(env.deleteGlobalRef, env);
  globalRefs = [];
};

function register (globalRef) {
  globalRefs.push(globalRef);
  return globalRef;
}

function vtable (instance) {
  if (cachedVtable === null) {
    cachedVtable = instance.handle.readPointer();
  }
  return cachedVtable;
}

function proxy (offset, retType, argTypes, wrapper) {
  let impl = null;
  return function () {
    if (impl === null) {
      impl = new NativeFunction(vtable(this).add(offset * pointerSize).readPointer(), retType, argTypes, nativeFunctionOptions);
    }
    let args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}

Env.prototype.getVersion = proxy(4, 'int32', ['pointer'], function (impl) {
  return impl(this.handle);
});

Env.prototype.findClass = proxy(6, 'pointer', ['pointer', 'pointer'], function (impl, name) {
  const result = impl(this.handle, Memory.allocUtf8String(name));
  this.throwIfExceptionPending();
  return result;
});

Env.prototype.throwIfExceptionPending = function () {
  const throwable = this.exceptionOccurred();
  if (throwable.isNull()) {
    return;
  }
  this.exceptionClear();
  const handle = this.newGlobalRef(throwable);
  this.deleteLocalRef(throwable);

  const description = this.vaMethod('pointer', [])(this.handle, handle, this.javaLangObject().toString);
  const descriptionStr = this.stringFromJni(description);
  this.deleteLocalRef(description);

  const error = new Error(descriptionStr);
  error.$h = handle;
  Script.bindWeak(error, makeErrorHandleDestructor(this.vm, handle));

  throw error;
};

function makeErrorHandleDestructor (vm, handle) {
  return function () {
    vm.perform(env => {
      env.deleteGlobalRef(handle);
    });
  };
}

Env.prototype.fromReflectedMethod = proxy(7, 'pointer', ['pointer', 'pointer'], function (impl, method) {
  return impl(this.handle, method);
});

Env.prototype.fromReflectedField = proxy(8, 'pointer', ['pointer', 'pointer'], function (impl, method) {
  return impl(this.handle, method);
});

Env.prototype.toReflectedMethod = proxy(9, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'], function (impl, klass, methodId, isStatic) {
  return impl(this.handle, klass, methodId, isStatic);
});

Env.prototype.getSuperclass = proxy(10, 'pointer', ['pointer', 'pointer'], function (impl, klass) {
  return impl(this.handle, klass);
});

Env.prototype.isAssignableFrom = proxy(11, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, klass1, klass2) {
  return !!impl(this.handle, klass1, klass2);
});

Env.prototype.toReflectedField = proxy(12, 'pointer', ['pointer', 'pointer', 'pointer', 'uint8'], function (impl, klass, fieldId, isStatic) {
  return impl(this.handle, klass, fieldId, isStatic);
});

Env.prototype.throw = proxy(13, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.exceptionOccurred = proxy(15, 'pointer', ['pointer'], function (impl) {
  return impl(this.handle);
});

Env.prototype.exceptionDescribe = proxy(16, 'void', ['pointer'], function (impl) {
  impl(this.handle);
});

Env.prototype.exceptionClear = proxy(17, 'void', ['pointer'], function (impl) {
  impl(this.handle);
});

Env.prototype.pushLocalFrame = proxy(19, 'int32', ['pointer', 'int32'], function (impl, capacity) {
  return impl(this.handle, capacity);
});

Env.prototype.popLocalFrame = proxy(20, 'pointer', ['pointer', 'pointer'], function (impl, result) {
  return impl(this.handle, result);
});

Env.prototype.newGlobalRef = proxy(21, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.deleteGlobalRef = proxy(22, 'void', ['pointer', 'pointer'], function (impl, globalRef) {
  impl(this.handle, globalRef);
});

Env.prototype.deleteLocalRef = proxy(23, 'void', ['pointer', 'pointer'], function (impl, localRef) {
  impl(this.handle, localRef);
});

Env.prototype.isSameObject = proxy(24, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, ref1, ref2) {
  return !!impl(this.handle, ref1, ref2);
});

Env.prototype.newLocalRef = proxy(25, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.allocObject = proxy(27, 'pointer', ['pointer', 'pointer'], function (impl, clazz) {
  return impl(this.handle, clazz);
});

Env.prototype.getObjectClass = proxy(31, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.isInstanceOf = proxy(32, 'uint8', ['pointer', 'pointer', 'pointer'], function (impl, obj, klass) {
  return !!impl(this.handle, obj, klass);
});

Env.prototype.getMethodId = proxy(33, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getFieldId = proxy(94, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getIntField = proxy(100, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});

Env.prototype.getStaticMethodId = proxy(113, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getStaticFieldId = proxy(144, 'pointer', ['pointer', 'pointer', 'pointer', 'pointer'], function (impl, klass, name, sig) {
  return impl(this.handle, klass, Memory.allocUtf8String(name), Memory.allocUtf8String(sig));
});

Env.prototype.getStaticIntField = proxy(150, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, obj, fieldId) {
  return impl(this.handle, obj, fieldId);
});

Env.prototype.getStringLength = proxy(164, 'int32', ['pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str);
});

Env.prototype.getStringChars = proxy(165, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str, NULL);
});

Env.prototype.releaseStringChars = proxy(166, 'void', ['pointer', 'pointer', 'pointer'], function (impl, str, utf) {
  impl(this.handle, str, utf);
});

Env.prototype.newStringUtf = proxy(167, 'pointer', ['pointer', 'pointer'], function (impl, str) {
  const utf = Memory.allocUtf8String(str);
  return impl(this.handle, utf);
});

Env.prototype.getStringUtfChars = proxy(169, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, str) {
  return impl(this.handle, str, NULL);
});

Env.prototype.releaseStringUtfChars = proxy(170, 'void', ['pointer', 'pointer', 'pointer'], function (impl, str, utf) {
  impl(this.handle, str, utf);
});

Env.prototype.getArrayLength = proxy(171, 'int32', ['pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array);
});

Env.prototype.newObjectArray = proxy(172, 'pointer', ['pointer', 'int32', 'pointer', 'pointer'], function (impl, length, elementClass, initialElement) {
  return impl(this.handle, length, elementClass, initialElement);
});

Env.prototype.getObjectArrayElement = proxy(173, 'pointer', ['pointer', 'pointer', 'int32'], function (impl, array, index) {
  return impl(this.handle, array, index);
});

Env.prototype.setObjectArrayElement = proxy(174, 'void', ['pointer', 'pointer', 'int32', 'pointer'], function (impl, array, index, value) {
  impl(this.handle, array, index, value);
});

Env.prototype.newBooleanArray = proxy(175, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newByteArray = proxy(176, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newCharArray = proxy(177, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newShortArray = proxy(178, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newIntArray = proxy(179, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newLongArray = proxy(180, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newFloatArray = proxy(181, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.newDoubleArray = proxy(182, 'pointer', ['pointer', 'int32'], function (impl, length) {
  return impl(this.handle, length);
});

Env.prototype.getBooleanArrayElements = proxy(183, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getByteArrayElements = proxy(184, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getCharArrayElements = proxy(185, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getShortArrayElements = proxy(186, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getIntArrayElements = proxy(187, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getLongArrayElements = proxy(188, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getFloatArrayElements = proxy(189, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.getDoubleArrayElements = proxy(190, 'pointer', ['pointer', 'pointer', 'pointer'], function (impl, array) {
  return impl(this.handle, array, NULL);
});

Env.prototype.releaseBooleanArrayElements = proxy(191, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseByteArrayElements = proxy(192, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseCharArrayElements = proxy(193, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseShortArrayElements = proxy(194, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseIntArrayElements = proxy(195, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseLongArrayElements = proxy(196, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseFloatArrayElements = proxy(197, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.releaseDoubleArrayElements = proxy(198, 'pointer', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, array, cArray) {
  impl(this.handle, array, cArray, JNI_ABORT);
});

Env.prototype.getByteArrayRegion = proxy(200, 'void', ['pointer', 'pointer', 'int', 'int', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setBooleanArrayRegion = proxy(207, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setByteArrayRegion = proxy(208, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setCharArrayRegion = proxy(209, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setShortArrayRegion = proxy(210, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setIntArrayRegion = proxy(211, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setLongArrayRegion = proxy(212, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setFloatArrayRegion = proxy(213, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.setDoubleArrayRegion = proxy(214, 'void', ['pointer', 'pointer', 'int32', 'int32', 'pointer'], function (impl, array, start, length, cArray) {
  impl(this.handle, array, start, length, cArray);
});

Env.prototype.registerNatives = proxy(215, 'int32', ['pointer', 'pointer', 'pointer', 'int32'], function (impl, klass, methods, numMethods) {
  return impl(this.handle, klass, methods, numMethods);
});

Env.prototype.monitorEnter = proxy(217, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.monitorExit = proxy(218, 'int32', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.getDirectBufferAddress = proxy(230, 'pointer', ['pointer', 'pointer'], function (impl, obj) {
  return impl(this.handle, obj);
});

Env.prototype.getObjectRefType = proxy(232, 'int32', ['pointer', 'pointer'], function (impl, ref) {
  return impl(this.handle, ref);
});

const cachedMethods = new Map();

function plainMethod (offset, retType, argTypes, options) {
  return getOrMakeMethod(this, 'p', makePlainMethod, offset, retType, argTypes, options);
}

function vaMethod (offset, retType, argTypes, options) {
  return getOrMakeMethod(this, 'v', makeVaMethod, offset, retType, argTypes, options);
}

function nonvirtualVaMethod (offset, retType, argTypes, options) {
  return getOrMakeMethod(this, 'n', makeNonvirtualVaMethod, offset, retType, argTypes, options);
}

function getOrMakeMethod (env, flavor, construct, offset, retType, argTypes, options) {
  if (options !== undefined) {
    return construct(env, offset, retType, argTypes, options);
  }

  const key = [offset, flavor, retType].concat(argTypes).join('|');
  let m = cachedMethods.get(key);
  if (m === undefined) {
    m = construct(env, offset, retType, argTypes, nativeFunctionOptions);
    cachedMethods.set(key, m);
  }
  return m;
}

function makePlainMethod (env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize).readPointer(),
    retType,
    ['pointer', 'pointer', 'pointer'].concat(argTypes),
    options);
}

function makeVaMethod (env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize).readPointer(),
    retType,
    ['pointer', 'pointer', 'pointer', '...'].concat(argTypes),
    options);
}

function makeNonvirtualVaMethod (env, offset, retType, argTypes, options) {
  return new NativeFunction(
    vtable(env).add(offset * pointerSize).readPointer(),
    retType,
    ['pointer', 'pointer', 'pointer', 'pointer', '...'].concat(argTypes),
    options);
}

Env.prototype.constructor = function (argTypes, options) {
  return vaMethod.call(this, CALL_CONSTRUCTOR_METHOD_OFFSET, 'pointer', argTypes, options);
};

Env.prototype.vaMethod = function (retType, argTypes, options) {
  const offset = callMethodOffset[retType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }
  return vaMethod.call(this, offset, retType, argTypes, options);
};

Env.prototype.nonvirtualVaMethod = function (retType, argTypes, options) {
  const offset = callNonvirtualMethodOffset[retType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }
  return nonvirtualVaMethod.call(this, offset, retType, argTypes, options);
};

Env.prototype.staticVaMethod = function (retType, argTypes, options) {
  const offset = callStaticMethodOffset[retType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + retType);
  }
  return vaMethod.call(this, offset, retType, argTypes, options);
};

Env.prototype.getField = function (fieldType) {
  const offset = getFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, fieldType, []);
};

Env.prototype.getStaticField = function (fieldType) {
  const offset = getStaticFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, fieldType, []);
};

Env.prototype.setField = function (fieldType) {
  const offset = setFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, 'void', [fieldType]);
};

Env.prototype.setStaticField = function (fieldType) {
  const offset = setStaticFieldOffset[fieldType];
  if (offset === undefined) {
    throw new Error('Unsupported type: ' + fieldType);
  }
  return plainMethod.call(this, offset, 'void', [fieldType]);
};

let javaLangClass = null;
Env.prototype.javaLangClass = function () {
  if (javaLangClass === null) {
    const handle = this.findClass('java/lang/Class');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangClass = {
        handle: register(this.newGlobalRef(handle)),
        getName: get('getName', '()Ljava/lang/String;'),
        getSimpleName: get('getSimpleName', '()Ljava/lang/String;'),
        getGenericSuperclass: get('getGenericSuperclass', '()Ljava/lang/reflect/Type;'),
        getDeclaredConstructors: get('getDeclaredConstructors', '()[Ljava/lang/reflect/Constructor;'),
        getDeclaredMethods: get('getDeclaredMethods', '()[Ljava/lang/reflect/Method;'),
        getDeclaredFields: get('getDeclaredFields', '()[Ljava/lang/reflect/Field;'),
        isArray: get('isArray', '()Z'),
        isPrimitive: get('isPrimitive', '()Z'),
        isInterface: get('isInterface', '()Z'),
        getComponentType: get('getComponentType', '()Ljava/lang/Class;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangClass;
};

let javaLangObject = null;
Env.prototype.javaLangObject = function () {
  if (javaLangObject === null) {
    const handle = this.findClass('java/lang/Object');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangObject = {
        handle: register(this.newGlobalRef(handle)),
        toString: get('toString', '()Ljava/lang/String;'),
        getClass: get('getClass', '()Ljava/lang/Class;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangObject;
};

let javaLangReflectConstructor = null;
Env.prototype.javaLangReflectConstructor = function () {
  if (javaLangReflectConstructor === null) {
    const handle = this.findClass('java/lang/reflect/Constructor');
    try {
      javaLangReflectConstructor = {
        getGenericParameterTypes: this.getMethodId(handle, 'getGenericParameterTypes', '()[Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectConstructor;
};

let javaLangReflectMethod = null;
Env.prototype.javaLangReflectMethod = function () {
  if (javaLangReflectMethod === null) {
    const handle = this.findClass('java/lang/reflect/Method');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectMethod = {
        getName: get('getName', '()Ljava/lang/String;'),
        getGenericParameterTypes: get('getGenericParameterTypes', '()[Ljava/lang/reflect/Type;'),
        getParameterTypes: get('getParameterTypes', '()[Ljava/lang/Class;'),
        getGenericReturnType: get('getGenericReturnType', '()Ljava/lang/reflect/Type;'),
        getGenericExceptionTypes: get('getGenericExceptionTypes', '()[Ljava/lang/reflect/Type;'),
        getModifiers: get('getModifiers', '()I'),
        isVarArgs: get('isVarArgs', '()Z')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectMethod;
};

let javaLangReflectField = null;
Env.prototype.javaLangReflectField = function () {
  if (javaLangReflectField === null) {
    const handle = this.findClass('java/lang/reflect/Field');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectField = {
        getName: get('getName', '()Ljava/lang/String;'),
        getType: get('getType', '()Ljava/lang/Class;'),
        getGenericType: get('getGenericType', '()Ljava/lang/reflect/Type;'),
        getModifiers: get('getModifiers', '()I'),
        toString: get('toString', '()Ljava/lang/String;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectField;
};

let javaLangReflectTypeVariable = null;
Env.prototype.javaLangReflectTypeVariable = function () {
  if (javaLangReflectTypeVariable === null) {
    const handle = this.findClass('java/lang/reflect/TypeVariable');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectTypeVariable = {
        handle: register(this.newGlobalRef(handle)),
        getName: get('getName', '()Ljava/lang/String;'),
        getBounds: get('getBounds', '()[Ljava/lang/reflect/Type;'),
        getGenericDeclaration: get('getGenericDeclaration', '()Ljava/lang/reflect/GenericDeclaration;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectTypeVariable;
};

let javaLangReflectWildcardType = null;
Env.prototype.javaLangReflectWildcardType = function () {
  if (javaLangReflectWildcardType === null) {
    const handle = this.findClass('java/lang/reflect/WildcardType');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectWildcardType = {
        handle: register(this.newGlobalRef(handle)),
        getLowerBounds: get('getLowerBounds', '()[Ljava/lang/reflect/Type;'),
        getUpperBounds: get('getUpperBounds', '()[Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectWildcardType;
};

let javaLangReflectGenericArrayType = null;
Env.prototype.javaLangReflectGenericArrayType = function () {
  if (javaLangReflectGenericArrayType === null) {
    const handle = this.findClass('java/lang/reflect/GenericArrayType');
    try {
      javaLangReflectGenericArrayType = {
        handle: register(this.newGlobalRef(handle)),
        getGenericComponentType: this.getMethodId(handle, 'getGenericComponentType', '()Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectGenericArrayType;
};

let javaLangReflectParameterizedType = null;
Env.prototype.javaLangReflectParameterizedType = function () {
  if (javaLangReflectParameterizedType === null) {
    const handle = this.findClass('java/lang/reflect/ParameterizedType');
    try {
      const get = this.getMethodId.bind(this, handle);
      javaLangReflectParameterizedType = {
        handle: register(this.newGlobalRef(handle)),
        getActualTypeArguments: get('getActualTypeArguments', '()[Ljava/lang/reflect/Type;'),
        getRawType: get('getRawType', '()Ljava/lang/reflect/Type;'),
        getOwnerType: get('getOwnerType', '()Ljava/lang/reflect/Type;')
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangReflectParameterizedType;
};

let javaLangString = null;
Env.prototype.javaLangString = function () {
  if (javaLangString === null) {
    const handle = this.findClass('java/lang/String');
    try {
      javaLangString = {
        handle: register(this.newGlobalRef(handle))
      };
    } finally {
      this.deleteLocalRef(handle);
    }
  }
  return javaLangString;
};

Env.prototype.getClassName = function (classHandle) {
  const name = this.vaMethod('pointer', [])(this.handle, classHandle, this.javaLangClass().getName);
  try {
    return this.stringFromJni(name);
  } finally {
    this.deleteLocalRef(name);
  }
};

Env.prototype.getObjectClassName = function (objHandle) {
  const jklass = this.getObjectClass(objHandle);
  try {
    return this.getClassName(jklass);
  } finally {
    this.deleteLocalRef(jklass);
  }
};

Env.prototype.getActualTypeArgument = function (type) {
  const actualTypeArguments = this.vaMethod('pointer', [])(this.handle, type, this.javaLangReflectParameterizedType().getActualTypeArguments);
  this.throwIfExceptionPending();
  if (!actualTypeArguments.isNull()) {
    try {
      return this.getTypeNameFromFirstTypeElement(actualTypeArguments);
    } finally {
      this.deleteLocalRef(actualTypeArguments);
    }
  }
};

Env.prototype.getTypeNameFromFirstTypeElement = function (typeArray) {
  const length = this.getArrayLength(typeArray);
  if (length > 0) {
    const typeArgument0 = this.getObjectArrayElement(typeArray, 0);
    try {
      return this.getTypeName(typeArgument0);
    } finally {
      this.deleteLocalRef(typeArgument0);
    }
  } else {
    // TODO
    return 'java.lang.Object';
  }
};

Env.prototype.getTypeName = function (type, getGenericsInformation) {
  const invokeObjectMethodNoArgs = this.vaMethod('pointer', []);

  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
    return this.getArrayTypeName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectParameterizedType().handle)) {
    const rawType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectParameterizedType().getRawType);
    this.throwIfExceptionPending();
    let result;
    try {
      result = this.getTypeName(rawType);
    } finally {
      this.deleteLocalRef(rawType);
    }

    if (getGenericsInformation) {
      result += '<' + this.getActualTypeArgument(type) + '>';
    }
    return result;
  } else if (this.isInstanceOf(type, this.javaLangReflectTypeVariable().handle)) {
    // TODO
    return 'java.lang.Object';
  } else if (this.isInstanceOf(type, this.javaLangReflectWildcardType().handle)) {
    // TODO
    return 'java.lang.Object';
  } else {
    return 'java.lang.Object';
  }
};

Env.prototype.getArrayTypeName = function (type) {
  const invokeObjectMethodNoArgs = this.vaMethod('pointer', []);

  if (this.isInstanceOf(type, this.javaLangClass().handle)) {
    return this.getClassName(type);
  } else if (this.isInstanceOf(type, this.javaLangReflectGenericArrayType().handle)) {
    const componentType = invokeObjectMethodNoArgs(this.handle, type, this.javaLangReflectGenericArrayType().getGenericComponentType);
    // check for TypeNotPresentException and MalformedParameterizedTypeException
    this.throwIfExceptionPending();
    try {
      return '[L' + this.getTypeName(componentType) + ';';
    } finally {
      this.deleteLocalRef(componentType);
    }
  } else {
    return '[Ljava.lang.Object;';
  }
};

Env.prototype.stringFromJni = function (str) {
  const utf = this.getStringChars(str);
  if (utf.isNull()) {
    throw new Error('Unable to access string');
  }
  try {
    const length = this.getStringLength(str);
    return utf.readUtf16String(length);
  } finally {
    this.releaseStringChars(str, utf);
  }
};

✄
import {
  jvmtiVersion,
  jvmtiCapabilities,
  EnvJvmti
} from './jvmti.js';
import { parseInstructionsAt } from './machine-code.js';
import memoize from './memoize.js';
import { checkJniResult } from './result.js';
import VM from './vm.js';

const jsizeSize = 4;
const { pointerSize } = Process;

const JVM_ACC_NATIVE = 0x0100;
const JVM_ACC_IS_OLD = 0x00010000;
const JVM_ACC_IS_OBSOLETE = 0x00020000;
const JVM_ACC_NOT_C2_COMPILABLE = 0x02000000;
const JVM_ACC_NOT_C1_COMPILABLE = 0x04000000;
const JVM_ACC_NOT_C2_OSR_COMPILABLE = 0x08000000;

const nativeFunctionOptions = {
  exceptions: 'propagate'
};

const getJvmMethodSpec = memoize(_getJvmMethodSpec);
const getJvmInstanceKlassSpec = memoize(_getJvmInstanceKlassSpec);
const getJvmThreadSpec = memoize(_getJvmThreadSpec);

let cachedApi = null;
let manglersScheduled = false;
const replaceManglers = new Map();
const revertManglers = new Map();

export function getApi () {
  if (cachedApi === null) {
    cachedApi = _getApi();
  }
  return cachedApi;
}

function _getApi () {
  const vmModules = Process.enumerateModules()
    .filter(m => /jvm.(dll|dylib|so)$/.test(m.name));
  if (vmModules.length === 0) {
    return null;
  }

  const vmModule = vmModules[0];

  const temporaryApi = {
    flavor: 'jvm'
  };

  const pending = Process.platform === 'windows'
    ? [{
        module: vmModule,
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],
          JVM_Sleep: ['JVM_Sleep', 'void', ['pointer', 'pointer', 'long']],
          'VMThread::execute': ['VMThread::execute', 'void', ['pointer']],
          'Method::size': ['Method::size', 'int', ['int']],
          'Method::set_native_function': ['Method::set_native_function', 'void', ['pointer', 'pointer', 'int']],
          'Method::clear_native_function': ['Method::clear_native_function', 'void', ['pointer']],
          'Method::jmethod_id': ['Method::jmethod_id', 'pointer', ['pointer']],
          'ClassLoaderDataGraph::classes_do': ['ClassLoaderDataGraph::classes_do', 'void', ['pointer']],
          'NMethodSweeper::sweep_code_cache': ['NMethodSweeper::sweep_code_cache', 'void', []],
          'OopMapCache::flush_obsolete_entries': ['OopMapCache::flush_obsolete_entries', 'void', ['pointer']]
        },
        variables: {
          'VM_RedefineClasses::`vftable\'': function (address) {
            this.vtableRedefineClasses = address;
          },
          'VM_RedefineClasses::doit': function (address) {
            this.redefineClassesDoIt = address;
          },
          'VM_RedefineClasses::doit_prologue': function (address) {
            this.redefineClassesDoItPrologue = address;
          },
          'VM_RedefineClasses::doit_epilogue': function (address) {
            this.redefineClassesDoItEpilogue = address;
          },
          'VM_RedefineClasses::allow_nested_vm_operations': function (address) {
            this.redefineClassesAllow = address;
          },
          'NMethodSweeper::_traversals': function (address) {
            this.traversals = address;
          },
          'NMethodSweeper::_should_sweep': function (address) {
            this.shouldSweep = address;
          }
        },
        optionals: [
        ]
      }]
  // If platform is not Windows
    : [{
        module: vmModule,
        functions: {
          JNI_GetCreatedJavaVMs: ['JNI_GetCreatedJavaVMs', 'int', ['pointer', 'int', 'pointer']],

          _ZN6Method4sizeEb: ['Method::size', 'int', ['int']],
          _ZN6Method19set_native_functionEPhb: ['Method::set_native_function', 'void', ['pointer', 'pointer', 'int']],
          _ZN6Method21clear_native_functionEv: ['Method::clear_native_function', 'void', ['pointer']],
          // JDK >= 17
          _ZN6Method24restore_unshareable_infoEP10JavaThread: ['Method::restore_unshareable_info', 'void', ['pointer', 'pointer']],
          // JDK < 17
          _ZN6Method24restore_unshareable_infoEP6Thread: ['Method::restore_unshareable_info', 'void', ['pointer', 'pointer']],
          _ZN6Method11link_methodERK12methodHandleP10JavaThread: ['Method::link_method', 'void', ['pointer', 'pointer', 'pointer']],
          _ZN6Method10jmethod_idEv: ['Method::jmethod_id', 'pointer', ['pointer']],
          _ZN6Method10clear_codeEv: function (address) {
            const clearCode = new NativeFunction(address, 'void', ['pointer'], nativeFunctionOptions);
            this['Method::clear_code'] = function (thisPtr) {
              clearCode(thisPtr);
            };
          },
          _ZN6Method10clear_codeEb: function (address) {
            const clearCode = new NativeFunction(address, 'void', ['pointer', 'int'], nativeFunctionOptions);
            const lock = 0;
            this['Method::clear_code'] = function (thisPtr) {
              clearCode(thisPtr, lock);
            };
          },

          // JDK >= 13
          _ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass: ['VM_RedefineClasses::mark_dependent_code', 'void', ['pointer', 'pointer']],
          _ZN18VM_RedefineClasses20flush_dependent_codeEv: ['VM_RedefineClasses::flush_dependent_code', 'void', []],
          // JDK < 13
          _ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread: ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],
          // JDK < 10
          _ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread: ['VM_RedefineClasses::flush_dependent_code', 'void', ['pointer', 'pointer', 'pointer']],

          _ZN19ResolvedMethodTable21adjust_method_entriesEPb: ['ResolvedMethodTable::adjust_method_entries', 'void', ['pointer']],
          // JDK < 10
          _ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb: ['MemberNameTable::adjust_method_entries', 'void', ['pointer', 'pointer', 'pointer']],

          _ZN17ConstantPoolCache21adjust_method_entriesEPb: function (address) {
            const adjustMethod = new NativeFunction(address, 'void', ['pointer', 'pointer'], nativeFunctionOptions);
            this['ConstantPoolCache::adjust_method_entries'] = function (thisPtr, holderPtr, tracePtr) {
              adjustMethod(thisPtr, tracePtr);
            };
          },
          // JDK < 13
          _ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb: function (address) {
            const adjustMethod = new NativeFunction(address, 'void', ['pointer', 'pointer', 'pointer'], nativeFunctionOptions);
            this['ConstantPoolCache::adjust_method_entries'] = function (thisPtr, holderPtr, tracePtr) {
              adjustMethod(thisPtr, holderPtr, tracePtr);
            };
          },

          _ZN20ClassLoaderDataGraph10classes_doEP12KlassClosure: ['ClassLoaderDataGraph::classes_do', 'void', ['pointer']],
          _ZN20ClassLoaderDataGraph22clean_deallocate_listsEb: ['ClassLoaderDataGraph::clean_deallocate_lists', 'void', ['int']],

          _ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_: ['JavaThread::thread_from_jni_environment', 'pointer', ['pointer']],

          _ZN8VMThread7executeEP12VM_Operation: ['VMThread::execute', 'void', ['pointer']],

          _ZN11OopMapCache22flush_obsolete_entriesEv: ['OopMapCache::flush_obsolete_entries', 'void', ['pointer']],

          _ZN14NMethodSweeper11force_sweepEv: ['NMethodSweeper::force_sweep', 'void', []],
          _ZN14NMethodSweeper16sweep_code_cacheEv: ['NMethodSweeper::sweep_code_cache', 'void', []],
          _ZN14NMethodSweeper17sweep_in_progressEv: ['NMethodSweeper::sweep_in_progress', 'bool', []],

          JVM_Sleep: ['JVM_Sleep', 'void', ['pointer', 'pointer', 'long']]
        },
        variables: {
          // JDK <= 9
          _ZN18VM_RedefineClasses14_the_class_oopE: function (address) {
            this.redefineClass = address;
          },
          // 9 < JDK < 13
          _ZN18VM_RedefineClasses10_the_classE: function (address) {
            this.redefineClass = address;
          },
          // JDK < 13
          _ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass: function (address) {
            this.doKlass = address;
          },
          // JDK >= 13
          _ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass: function (address) {
            this.doKlass = address;
          },
          _ZTV18VM_RedefineClasses: function (address) {
            this.vtableRedefineClasses = address;
          },
          _ZN18VM_RedefineClasses4doitEv: function (address) {
            this.redefineClassesDoIt = address;
          },
          _ZN18VM_RedefineClasses13doit_prologueEv: function (address) {
            this.redefineClassesDoItPrologue = address;
          },
          _ZN18VM_RedefineClasses13doit_epilogueEv: function (address) {
            this.redefineClassesDoItEpilogue = address;
          },
          _ZN18VM_RedefineClassesD0Ev: function (address) {
            this.redefineClassesDispose0 = address;
          },
          _ZN18VM_RedefineClassesD1Ev: function (address) {
            this.redefineClassesDispose1 = address;
          },
          _ZNK18VM_RedefineClasses26allow_nested_vm_operationsEv: function (address) {
            this.redefineClassesAllow = address;
          },
          _ZNK18VM_RedefineClasses14print_on_errorEP12outputStream: function (address) {
            this.redefineClassesOnError = address;
          },

          // JDK >= 17
          _ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread: function (address) {
            this.createNewDefaultVtableIndices = address;
          },
          // JDK < 17
          _ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread: function (address) {
            this.createNewDefaultVtableIndices = address;
          },

          _ZN19Abstract_VM_Version19jre_release_versionEv: function (address) {
            const getVersion = new NativeFunction(address, 'pointer', [], nativeFunctionOptions);
            const versionS = getVersion().readCString();
            this.version = versionS.startsWith('1.8')
              ? 8
              : versionS.startsWith('9.')
                ? 9
                : parseInt(versionS.slice(0, 2), 10);
            this.versionS = versionS;
          },

          _ZN14NMethodSweeper11_traversalsE: function (address) {
            this.traversals = address;
          },
          _ZN14NMethodSweeper21_sweep_fractions_leftE: function (address) {
            this.fractions = address;
          },
          _ZN14NMethodSweeper13_should_sweepE: function (address) {
            this.shouldSweep = address;
          }
        },
        optionals: [
          '_ZN6Method24restore_unshareable_infoEP10JavaThread',
          '_ZN6Method24restore_unshareable_infoEP6Thread',
          '_ZN6Method11link_methodERK12methodHandleP10JavaThread',
          '_ZN6Method10clear_codeEv',
          '_ZN6Method10clear_codeEb',

          '_ZN18VM_RedefineClasses19mark_dependent_codeEP13InstanceKlass',
          '_ZN18VM_RedefineClasses20flush_dependent_codeEv',
          '_ZN18VM_RedefineClasses20flush_dependent_codeEP13InstanceKlassP6Thread',
          '_ZN18VM_RedefineClasses20flush_dependent_codeE19instanceKlassHandleP6Thread',

          '_ZN19ResolvedMethodTable21adjust_method_entriesEPb',
          '_ZN15MemberNameTable21adjust_method_entriesEP13InstanceKlassPb',

          '_ZN17ConstantPoolCache21adjust_method_entriesEPb',
          '_ZN17ConstantPoolCache21adjust_method_entriesEP13InstanceKlassPb',

          '_ZN20ClassLoaderDataGraph22clean_deallocate_listsEb',

          '_ZN10JavaThread27thread_from_jni_environmentEP7JNIEnv_',

          '_ZN14NMethodSweeper11force_sweepEv',
          '_ZN14NMethodSweeper17sweep_in_progressEv',

          '_ZN18VM_RedefineClasses14_the_class_oopE',
          '_ZN18VM_RedefineClasses10_the_classE',
          '_ZN18VM_RedefineClasses25AdjustCpoolCacheAndVtable8do_klassEP5Klass',
          '_ZN18VM_RedefineClasses22AdjustAndCleanMetadata8do_klassEP5Klass',
          '_ZN18VM_RedefineClassesD0Ev',
          '_ZN18VM_RedefineClassesD1Ev',
          '_ZNK18VM_RedefineClasses14print_on_errorEP12outputStream',

          '_ZN13InstanceKlass33create_new_default_vtable_indicesEiP10JavaThread',
          '_ZN13InstanceKlass33create_new_default_vtable_indicesEiP6Thread',

          '_ZN14NMethodSweeper21_sweep_fractions_leftE'
        ]
      }];

  const missing = [];

  pending.forEach(function (api) {
    const module = api.module;
    const functions = api.functions || {};
    const variables = api.variables || {};
    const optionals = new Set(api.optionals || []);

    const tmp = module.enumerateExports()
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, {});

    const exportByName = module.enumerateSymbols()
      .reduce(function (result, exp) {
        result[exp.name] = exp;
        return result;
      }, tmp);

    Object.keys(functions)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined) {
          const signature = functions[name];
          if (typeof signature === 'function') {
            signature.call(temporaryApi, exp.address);
          } else {
            temporaryApi[signature[0]] = new NativeFunction(exp.address, signature[1], signature[2], nativeFunctionOptions);
          }
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });

    Object.keys(variables)
      .forEach(function (name) {
        const exp = exportByName[name];
        if (exp !== undefined) {
          const handler = variables[name];
          handler.call(temporaryApi, exp.address);
        } else {
          if (!optionals.has(name)) {
            missing.push(name);
          }
        }
      });
  });

  if (missing.length > 0) {
    throw new Error('Java API only partially available; please file a bug. Missing: ' + missing.join(', '));
  }

  const vms = Memory.alloc(pointerSize);
  const vmCount = Memory.alloc(jsizeSize);
  checkJniResult('JNI_GetCreatedJavaVMs', temporaryApi.JNI_GetCreatedJavaVMs(vms, 1, vmCount));
  if (vmCount.readInt() === 0) {
    return null;
  }
  temporaryApi.vm = vms.readPointer();

  const allocatorFunctions = Process.platform === 'windows'
    ? {
        $new: ['??2@YAPEAX_K@Z', 'pointer', ['ulong']],
        $delete: ['??3@YAXPEAX@Z', 'void', ['pointer']]
      }
  // If platform is not Windows
    : {
        $new: ['_Znwm', 'pointer', ['ulong']],
        $delete: ['_ZdlPv', 'void', ['pointer']]
      };

  for (const [name, [rawName, retType, argTypes]] of Object.entries(allocatorFunctions)) {
    let address = Module.findGlobalExportByName(rawName);
    if (address === null) {
      address = DebugSymbol.fromName(rawName).address;
      if (address.isNull()) {
        throw new Error(`unable to find C++ allocator API, missing: '${rawName}'`);
      }
    }
    temporaryApi[name] = new NativeFunction(address, retType, argTypes, nativeFunctionOptions);
  }

  temporaryApi.jvmti = getEnvJvmti(temporaryApi);

  if (temporaryApi['JavaThread::thread_from_jni_environment'] === undefined) {
    temporaryApi['JavaThread::thread_from_jni_environment'] = makeThreadFromJniHelper(temporaryApi);
  }

  return temporaryApi;
}

function getEnvJvmti (api) {
  const vm = new VM(api);

  let env;
  vm.perform(() => {
    const handle = vm.tryGetEnvHandle(jvmtiVersion.v1_0);
    if (handle === null) {
      throw new Error('JVMTI not available');
    }
    env = new EnvJvmti(handle, vm);

    const capaBuf = Memory.alloc(8);
    capaBuf.writeU64(jvmtiCapabilities.canTagObjects);
    const result = env.addCapabilities(capaBuf);
    checkJniResult('getEnvJvmti::AddCapabilities', result);
  });

  return env;
}

const threadOffsetParsers = {
  x64: parseX64ThreadOffset
};

function makeThreadFromJniHelper (api) {
  let offset = null;

  const tryParse = threadOffsetParsers[Process.arch];
  if (tryParse !== undefined) {
    const vm = new VM(api);
    const findClassImpl = vm.perform(env => env.handle.readPointer().add(6 * pointerSize).readPointer());
    offset = parseInstructionsAt(findClassImpl, tryParse, { limit: 11 });
  }

  if (offset === null) {
    return () => {
      throw new Error('Unable to make thread_from_jni_environment() helper for the current architecture');
    };
  }

  return env => {
    return env.add(offset);
  };
}

function parseX64ThreadOffset (insn) {
  if (insn.mnemonic !== 'lea') {
    return null;
  }

  const { base, disp } = insn.operands[1].value;
  if (!(base === 'rdi' && disp < 0)) {
    return null;
  }

  return disp;
}

export function ensureClassInitialized (env, classRef) {
}

class JvmMethodMangler {
  constructor (methodId) {
    this.methodId = methodId;
    this.method = methodId.readPointer();
    this.originalMethod = null;
    this.newMethod = null;
    this.resolved = null;
    this.impl = null;
    this.key = methodId.toString(16);
  }

  replace (impl, isInstanceMethod, argTypes, vm, api) {
    const { key } = this;
    const mangler = revertManglers.get(key);
    if (mangler !== undefined) {
      revertManglers.delete(key);
      this.method = mangler.method;
      this.originalMethod = mangler.originalMethod;
      this.newMethod = mangler.newMethod;
      this.resolved = mangler.resolved;
    }
    this.impl = impl;
    replaceManglers.set(key, this);
    ensureManglersScheduled(vm);
  }

  revert (vm) {
    const { key } = this;
    replaceManglers.delete(key);
    revertManglers.set(key, this);
    ensureManglersScheduled(vm);
  }

  resolveTarget (wrapper, isInstanceMethod, env, api) {
    const { resolved, originalMethod, methodId } = this;
    if (resolved !== null) {
      return resolved;
    }

    if (originalMethod === null) {
      return methodId;
    }

    const vip = originalMethod.oldMethod.vtableIndexPtr;

    // Make old method final with nonvirtual_vtable_index = -2
    // so that we don't need a vtable entry when calling old method.
    vip.writeS32(-2);

    const jmethodID = Memory.alloc(pointerSize);
    jmethodID.writePointer(this.method);
    this.resolved = jmethodID;

    return jmethodID;
  }
}

function ensureManglersScheduled (vm) {
  if (!manglersScheduled) {
    manglersScheduled = true;
    Script.nextTick(doManglers, vm);
  }
}

function doManglers (vm) {
  const localReplaceManglers = new Map(replaceManglers);
  const localRevertManglers = new Map(revertManglers);
  replaceManglers.clear();
  revertManglers.clear();
  manglersScheduled = false;

  vm.perform(env => {
    const api = getApi();

    const thread = api['JavaThread::thread_from_jni_environment'](env.handle);

    let force = false;

    withJvmThread(() => {
      localReplaceManglers.forEach(mangler => {
        const { method, originalMethod, impl, methodId, newMethod } = mangler;
        if (originalMethod === null) {
          mangler.originalMethod = fetchJvmMethod(method);
          mangler.newMethod = nativeJvmMethod(method, impl, thread);
          installJvmMethod(mangler.newMethod, methodId, thread);
        } else {
          api['Method::set_native_function'](newMethod.method, impl, 0);
        }
      });

      localRevertManglers.forEach(mangler => {
        const { originalMethod, methodId, newMethod } = mangler;
        if (originalMethod !== null) {
          revertJvmMethod(originalMethod);
          const revert = originalMethod.oldMethod;
          revert.oldMethod = newMethod;
          installJvmMethod(revert, methodId, thread);
          force = true;
        }
      });
    });

    if (force) {
      forceSweep(env.handle);
    }
  });
}

function forceSweep (env) {
  const {
    fractions,
    shouldSweep,
    traversals,
    'NMethodSweeper::sweep_code_cache': sweep,
    'NMethodSweeper::sweep_in_progress': inProgress,
    'NMethodSweeper::force_sweep': force,
    JVM_Sleep: sleep
  } = getApi();

  if (force !== undefined) {
    Thread.sleep(0.05);
    force();
    Thread.sleep(0.05);
    force();
  } else {
    let trav = traversals.readS64();
    const endTrav = trav + 2;

    while (endTrav > trav) {
      // Force a full sweep if already in progress.
      fractions.writeS32(1);
      sleep(env, NULL, 50);

      // Check if current nmethod is set.
      if (!inProgress()) {
        // Force mark_active_nmethods on exit from safepoint.
        withJvmThread(() => {
          Thread.sleep(0.05);
        });
      }

      const sweepNotAlreadyInProgress = shouldSweep.readU8() === 0;
      if (sweepNotAlreadyInProgress) {
        // Sanity check to not divide by 0.
        fractions.writeS32(1);
        sweep();
      }

      trav = traversals.readS64();
    }
  }
}

function withJvmThread (fn, fnPrologue, fnEpilogue) {
  const {
    execute,
    vtable,
    vtableSize,
    doItOffset,
    prologueOffset,
    epilogueOffset
  } = getJvmThreadSpec();

  const vtableDup = Memory.dup(vtable, vtableSize);

  const vmOperation = Memory.alloc(pointerSize * 25);
  vmOperation.writePointer(vtableDup);

  const doIt = new NativeCallback(fn, 'void', ['pointer']);
  vtableDup.add(doItOffset).writePointer(doIt);

  let prologue = null;
  if (fnPrologue !== undefined) {
    prologue = new NativeCallback(fnPrologue, 'int', ['pointer']);
    vtableDup.add(prologueOffset).writePointer(prologue);
  }

  let epilogue = null;
  if (fnEpilogue !== undefined) {
    epilogue = new NativeCallback(fnEpilogue, 'void', ['pointer']);
    vtableDup.add(epilogueOffset).writePointer(epilogue);
  }

  execute(vmOperation);
}

function _getJvmThreadSpec () {
  const {
    vtableRedefineClasses,
    redefineClassesDoIt,
    redefineClassesDoItPrologue,
    redefineClassesDoItEpilogue,
    redefineClassesOnError,
    redefineClassesAllow,
    redefineClassesDispose0,
    redefineClassesDispose1,
    'VMThread::execute': execute
  } = getApi();

  const vtablePtr = vtableRedefineClasses.add(2 * pointerSize);
  const vtableSize = 15 * pointerSize;
  const vtable = Memory.dup(vtablePtr, vtableSize);

  const emptyCallback = new NativeCallback(() => {}, 'void', ['pointer']);

  let doItOffset, prologueOffset, epilogueOffset;
  for (let offset = 0; offset !== vtableSize; offset += pointerSize) {
    const element = vtable.add(offset);
    const value = element.readPointer();
    if ((redefineClassesOnError !== undefined && value.equals(redefineClassesOnError)) ||
        (redefineClassesDispose0 !== undefined && value.equals(redefineClassesDispose0)) ||
        (redefineClassesDispose1 !== undefined && value.equals(redefineClassesDispose1))) {
      element.writePointer(emptyCallback);
    } else if (value.equals(redefineClassesDoIt)) {
      doItOffset = offset;
    } else if (value.equals(redefineClassesDoItPrologue)) {
      prologueOffset = offset;
      element.writePointer(redefineClassesAllow);
    } else if (value.equals(redefineClassesDoItEpilogue)) {
      epilogueOffset = offset;
      element.writePointer(emptyCallback);
    }
  }

  return {
    execute,
    emptyCallback,
    vtable,
    vtableSize,
    doItOffset,
    prologueOffset,
    epilogueOffset
  };
}

export function makeMethodMangler (methodId) {
  return new JvmMethodMangler(methodId);
}

function installJvmMethod (method, methodId, thread) {
  const { method: handle, oldMethod: old } = method;
  const api = getApi();

  // Replace position in methodsArray with new method.
  method.methodsArray.add(method.methodIndex * pointerSize).writePointer(handle);

  // Replace method handle in vtable
  if (method.vtableIndex >= 0) {
    method.vtable.add(method.vtableIndex * pointerSize).writePointer(handle);
  }

  // Replace jmethodID with new method.
  methodId.writePointer(handle);

  old.accessFlagsPtr.writeU32((old.accessFlags | JVM_ACC_IS_OLD | JVM_ACC_IS_OBSOLETE) >>> 0);

  // Deoptimize dependent code.
  const flushObs = api['OopMapCache::flush_obsolete_entries'];
  if (flushObs !== undefined) {
    const { oopMapCache } = method;
    if (!oopMapCache.isNull()) {
      flushObs(oopMapCache);
    }
  }

  const mark = api['VM_RedefineClasses::mark_dependent_code'];
  const flush = api['VM_RedefineClasses::flush_dependent_code'];
  if (mark !== undefined) {
    mark(NULL, method.instanceKlass);
    flush();
  } else {
    flush(NULL, method.instanceKlass, thread);
  }

  const traceNamePrinted = Memory.alloc(1);
  traceNamePrinted.writeU8(1);
  api['ConstantPoolCache::adjust_method_entries'](method.cache, method.instanceKlass, traceNamePrinted);

  const klassClosure = Memory.alloc(3 * pointerSize);
  const doKlassPtr = Memory.alloc(pointerSize);
  doKlassPtr.writePointer(api.doKlass);
  klassClosure.writePointer(doKlassPtr);
  klassClosure.add(pointerSize).writePointer(thread);
  klassClosure.add(2 * pointerSize).writePointer(thread);
  if (api.redefineClass !== undefined) {
    api.redefineClass.writePointer(method.instanceKlass);
  }
  api['ClassLoaderDataGraph::classes_do'](klassClosure);

  const rmtAdjustMethodEntries = api['ResolvedMethodTable::adjust_method_entries'];
  if (rmtAdjustMethodEntries !== undefined) {
    rmtAdjustMethodEntries(traceNamePrinted);
  } else {
    const { memberNames } = method;
    if (!memberNames.isNull()) {
      const mntAdjustMethodEntries = api['MemberNameTable::adjust_method_entries'];
      if (mntAdjustMethodEntries !== undefined) {
        mntAdjustMethodEntries(memberNames, method.instanceKlass, traceNamePrinted);
      }
    }
  }
  const clean = api['ClassLoaderDataGraph::clean_deallocate_lists'];
  if (clean !== undefined) {
    clean(0);
  }
}

function nativeJvmMethod (method, impl, thread) {
  const api = getApi();

  const newMethod = fetchJvmMethod(method);
  newMethod.constPtr.writePointer(newMethod.const);
  const flags = (newMethod.accessFlags | JVM_ACC_NATIVE |
    JVM_ACC_NOT_C2_COMPILABLE | JVM_ACC_NOT_C1_COMPILABLE |
    JVM_ACC_NOT_C2_OSR_COMPILABLE) >>> 0;
  newMethod.accessFlagsPtr.writeU32(flags);
  newMethod.signatureHandler.writePointer(NULL);
  newMethod.adapter.writePointer(NULL);
  newMethod.i2iEntry.writePointer(NULL);
  api['Method::clear_code'](newMethod.method);

  newMethod.dataPtr.writePointer(NULL);
  newMethod.countersPtr.writePointer(NULL);
  newMethod.stackmapPtr.writePointer(NULL);

  api['Method::clear_native_function'](newMethod.method);
  api['Method::set_native_function'](newMethod.method, impl, 0);

  api['Method::restore_unshareable_info'](newMethod.method, thread);

  if (api.version >= 17) {
    // Only certain JDK versions of restore_unshareable_info() call
    // link_method(). Manually call if necessary.
    const methodHandle = Memory.alloc(2 * pointerSize);
    methodHandle.writePointer(newMethod.method);
    methodHandle.add(pointerSize).writePointer(thread);
    api['Method::link_method'](newMethod.method, methodHandle, thread);
  }

  return newMethod;
}

function fetchJvmMethod (method) {
  const spec = getJvmMethodSpec();
  const constMethod = method.add(spec.method.constMethodOffset).readPointer();
  const constMethodSize = constMethod.add(spec.constMethod.sizeOffset).readS32() * pointerSize;

  const newConstMethod = Memory.alloc(constMethodSize + spec.method.size);
  Memory.copy(newConstMethod, constMethod, constMethodSize);

  const newMethod = newConstMethod.add(constMethodSize);
  Memory.copy(newMethod, method, spec.method.size);

  const result = readJvmMethod(newMethod, newConstMethod, constMethodSize);

  const oldMethod = readJvmMethod(method, constMethod, constMethodSize);
  result.oldMethod = oldMethod;

  return result;
}

function readJvmMethod (method, constMethod, constMethodSize) {
  const api = getApi();
  const spec = getJvmMethodSpec();

  const constPtr = method.add(spec.method.constMethodOffset);
  const dataPtr = method.add(spec.method.methodDataOffset);
  const countersPtr = method.add(spec.method.methodCountersOffset);
  const accessFlagsPtr = method.add(spec.method.accessFlagsOffset);
  const accessFlags = accessFlagsPtr.readU32();
  const adapter = spec.getAdapterPointer(method, constMethod);
  const i2iEntry = method.add(spec.method.i2iEntryOffset);
  const signatureHandler = method.add(spec.method.signatureHandlerOffset);

  const constantPool = constMethod.add(spec.constMethod.constantPoolOffset).readPointer();
  const stackmapPtr = constMethod.add(spec.constMethod.stackmapDataOffset);
  const instanceKlass = constantPool.add(spec.constantPool.instanceKlassOffset).readPointer();
  const cache = constantPool.add(spec.constantPool.cacheOffset).readPointer();

  const instanceKlassSpec = getJvmInstanceKlassSpec();

  const methods = instanceKlass.add(instanceKlassSpec.methodsOffset).readPointer();
  const methodsCount = methods.readS32();
  const methodsArray = methods.add(pointerSize);
  const methodIndex = constMethod.add(spec.constMethod.methodIdnumOffset).readU16();
  const vtableIndexPtr = method.add(spec.method.vtableIndexOffset);
  const vtableIndex = vtableIndexPtr.readS32();
  const vtable = instanceKlass.add(instanceKlassSpec.vtableOffset);
  const oopMapCache = instanceKlass.add(instanceKlassSpec.oopMapCacheOffset).readPointer();

  const memberNames = (api.version >= 10)
    ? instanceKlass.add(instanceKlassSpec.memberNamesOffset).readPointer()
    : NULL;

  return {
    method,
    methodSize: spec.method.size,
    const: constMethod,
    constSize: constMethodSize,
    constPtr,
    dataPtr,
    countersPtr,
    stackmapPtr,
    instanceKlass,
    methodsArray,
    methodsCount,
    methodIndex,
    vtableIndex,
    vtableIndexPtr,
    vtable,
    accessFlags,
    accessFlagsPtr,
    adapter,
    i2iEntry,
    signatureHandler,
    memberNames,
    cache,
    oopMapCache
  };
}

function revertJvmMethod (method) {
  const { oldMethod: old } = method;
  old.accessFlagsPtr.writeU32(old.accessFlags);
  old.vtableIndexPtr.writeS32(old.vtableIndex);
}

function _getJvmMethodSpec () {
  const api = getApi();
  const { version } = api;

  let adapterHandlerLocation;
  if (version >= 17) {
    adapterHandlerLocation = 'method:early';
  } else if (version >= 9 && version <= 16) {
    adapterHandlerLocation = 'const-method';
  } else {
    adapterHandlerLocation = 'method:late';
  }

  const isNative = 1;
  const methodSize = api['Method::size'](isNative) * pointerSize;
  const constMethodOffset = pointerSize;
  const methodDataOffset = 2 * pointerSize;
  const methodCountersOffset = 3 * pointerSize;
  const adapterInMethodEarlyOffset = 4 * pointerSize;
  const adapterInMethodEarlySize = (adapterHandlerLocation === 'method:early') ? pointerSize : 0;
  const accessFlagsOffset = adapterInMethodEarlyOffset + adapterInMethodEarlySize;
  const vtableIndexOffset = accessFlagsOffset + 4;
  const i2iEntryOffset = vtableIndexOffset + 4 + 8;
  const adapterInMethodLateOffset = i2iEntryOffset + pointerSize;
  const adapterInMethodOffset = (adapterInMethodEarlySize !== 0) ? adapterInMethodEarlyOffset : adapterInMethodLateOffset;
  const nativeFunctionOffset = methodSize - 2 * pointerSize;
  const signatureHandlerOffset = methodSize - pointerSize;

  const constantPoolOffset = 8;
  const stackmapDataOffset = constantPoolOffset + pointerSize;
  const adapterInConstMethodOffset = stackmapDataOffset + pointerSize;
  const adapterInConstMethodSize = (adapterHandlerLocation === 'const-method') ? pointerSize : 0;
  const constMethodSizeOffset = adapterInConstMethodOffset + adapterInConstMethodSize;
  const methodIdnumOffset = constMethodSizeOffset + 0xe;

  const cacheOffset = 2 * pointerSize;
  const instanceKlassOffset = 3 * pointerSize;

  const getAdapterPointer = (adapterInConstMethodSize !== 0)
    ? function (method, constMethod) {
      return constMethod.add(adapterInConstMethodOffset);
    }
    : function (method, constMethod) {
      return method.add(adapterInMethodOffset);
    };

  return {
    getAdapterPointer,
    method: {
      size: methodSize,
      constMethodOffset,
      methodDataOffset,
      methodCountersOffset,
      accessFlagsOffset,
      vtableIndexOffset,
      i2iEntryOffset,
      nativeFunctionOffset,
      signatureHandlerOffset
    },
    constMethod: {
      constantPoolOffset,
      stackmapDataOffset,
      sizeOffset: constMethodSizeOffset,
      methodIdnumOffset
    },
    constantPool: {
      cacheOffset,
      instanceKlassOffset
    }
  };
}

const vtableOffsetParsers = {
  x64: parseX64VTableOffset
};

function _getJvmInstanceKlassSpec () {
  const { version: jvmVersion, createNewDefaultVtableIndices } = getApi();

  const tryParse = vtableOffsetParsers[Process.arch];
  if (tryParse === undefined) {
    throw new Error(`Missing vtable offset parser for ${Process.arch}`);
  }

  const vtableOffset = parseInstructionsAt(createNewDefaultVtableIndices, tryParse, { limit: 32 });
  if (vtableOffset === null) {
    throw new Error('Unable to deduce vtable offset');
  }

  const oopMultiplier = ((jvmVersion >= 10 && jvmVersion <= 11) || jvmVersion >= 15) ? 17 : 18;

  const methodsOffset = vtableOffset - (7 * pointerSize);
  const memberNamesOffset = vtableOffset - (17 * pointerSize);
  const oopMapCacheOffset = vtableOffset - (oopMultiplier * pointerSize);

  return {
    vtableOffset,
    methodsOffset,
    memberNamesOffset,
    oopMapCacheOffset
  };
}

function parseX64VTableOffset (insn) {
  if (insn.mnemonic !== 'mov') {
    return null;
  }

  const dst = insn.operands[0];
  if (dst.type !== 'mem') {
    return null;
  }

  const { value: dstValue } = dst;
  if (dstValue.scale !== 1) {
    return null;
  }

  const { disp } = dstValue;
  if (disp < 0x100) {
    return null;
  }

  const defaultVtableIndicesOffset = disp;

  return defaultVtableIndicesOffset + 16;
}

export function deoptimizeEverything (vm, env) {
}

✄
import { checkJniResult } from './result.js';

export const jvmtiVersion = {
  v1_0: 0x30010000,
  v1_2: 0x30010200
};

export const jvmtiCapabilities = {
  canTagObjects: 1
};

const { pointerSize } = Process;
const nativeFunctionOptions = {
  exceptions: 'propagate'
};

export function EnvJvmti (handle, vm) {
  this.handle = handle;
  this.vm = vm;
  this.vtable = handle.readPointer();
}

EnvJvmti.prototype.deallocate = proxy(47, 'int32', ['pointer', 'pointer'], function (impl, mem) {
  return impl(this.handle, mem);
});

EnvJvmti.prototype.getLoadedClasses = proxy(78, 'int32', ['pointer', 'pointer', 'pointer'], function (impl, classCountPtr, classesPtr) {
  const result = impl(this.handle, classCountPtr, classesPtr);
  checkJniResult('EnvJvmti::getLoadedClasses', result);
});

EnvJvmti.prototype.iterateOverInstancesOfClass = proxy(112, 'int32', ['pointer', 'pointer', 'int', 'pointer', 'pointer'], function (impl, klass, objectFilter, heapObjectCallback, userData) {
  const result = impl(this.handle, klass, objectFilter, heapObjectCallback, userData);
  checkJniResult('EnvJvmti::iterateOverInstancesOfClass', result);
});

EnvJvmti.prototype.getObjectsWithTags = proxy(114, 'int32', ['pointer', 'int', 'pointer', 'pointer', 'pointer', 'pointer'], function (impl, tagCount, tags, countPtr, objectResultPtr, tagResultPtr) {
  const result = impl(this.handle, tagCount, tags, countPtr, objectResultPtr, tagResultPtr);
  checkJniResult('EnvJvmti::getObjectsWithTags', result);
});

EnvJvmti.prototype.addCapabilities = proxy(142, 'int32', ['pointer', 'pointer'], function (impl, capabilitiesPtr) {
  return impl(this.handle, capabilitiesPtr);
});

function proxy (offset, retType, argTypes, wrapper) {
  let impl = null;
  return function () {
    if (impl === null) {
      impl = new NativeFunction(this.vtable.add((offset - 1) * pointerSize).readPointer(), retType, argTypes, nativeFunctionOptions);
    }
    let args = [impl];
    args = args.concat.apply(args, arguments);
    return wrapper.apply(this, args);
  };
}

✄
// Based on https://stackoverflow.com/a/46432113

export default class LRU {
  constructor (capacity, destroy) {
    this.items = new Map();
    this.capacity = capacity;
    this.destroy = destroy;
  }

  dispose (env) {
    const { items, destroy } = this;
    items.forEach(val => { destroy(val, env); });
    items.clear();
  }

  get (key) {
    const { items } = this;

    const item = items.get(key);
    if (item !== undefined) {
      items.delete(key);
      items.set(key, item);
    }

    return item;
  }

  set (key, val, env) {
    const { items } = this;

    const existingVal = items.get(key);
    if (existingVal !== undefined) {
      items.delete(key);
      this.destroy(existingVal, env);
    } else if (items.size === this.capacity) {
      const oldestKey = items.keys().next().value;
      const oldestVal = items.get(oldestKey);
      items.delete(oldestKey);
      this.destroy(oldestVal, env);
    }

    items.set(key, val);
  }
}

✄
export function parseInstructionsAt (address, tryParse, { limit }) {
  let cursor = address;
  let prevInsn = null;

  for (let i = 0; i !== limit; i++) {
    const insn = Instruction.parse(cursor);

    const value = tryParse(insn, prevInsn);
    if (value !== null) {
      return value;
    }

    cursor = insn.next;
    prevInsn = insn;
  }

  return null;
}

✄
export default function memoize (compute) {
  let value = null;
  let computed = false;

  return function (...args) {
    if (!computed) {
      value = compute(...args);
      computed = true;
    }

    return value;
  };
}

✄
import { Buffer } from 'buffer';

const kAccPublic = 0x0001;
const kAccNative = 0x0100;

const kAccConstructor = 0x00010000;

const kEndianTag = 0x12345678;

const kClassDefSize = 32;
const kProtoIdSize = 12;
const kFieldIdSize = 8;
const kMethodIdSize = 8;
const kTypeIdSize = 4;
const kStringIdSize = 4;
const kMapItemSize = 12;

const TYPE_HEADER_ITEM = 0;
const TYPE_STRING_ID_ITEM = 1;
const TYPE_TYPE_ID_ITEM = 2;
const TYPE_PROTO_ID_ITEM = 3;
const TYPE_FIELD_ID_ITEM = 4;
const TYPE_METHOD_ID_ITEM = 5;
const TYPE_CLASS_DEF_ITEM = 6;
const TYPE_MAP_LIST = 0x1000;
const TYPE_TYPE_LIST = 0x1001;
const TYPE_ANNOTATION_SET_ITEM = 0x1003;
const TYPE_CLASS_DATA_ITEM = 0x2000;
const TYPE_CODE_ITEM = 0x2001;
const TYPE_STRING_DATA_ITEM = 0x2002;
const TYPE_DEBUG_INFO_ITEM = 0x2003;
const TYPE_ANNOTATION_ITEM = 0x2004;
const TYPE_ANNOTATIONS_DIRECTORY_ITEM = 0x2006;

const VALUE_TYPE = 0x18;
const VALUE_ARRAY = 0x1c;

const VISIBILITY_SYSTEM = 2;

const kDefaultConstructorSize = 24;
const kDefaultConstructorDebugInfo = Buffer.from([0x03, 0x00, 0x07, 0x0e, 0x00]);

const kDalvikAnnotationTypeThrows = 'Ldalvik/annotation/Throws;';

const kNullTerminator = Buffer.from([0]);

function mkdex (spec) {
  const builder = new DexBuilder();

  const fullSpec = Object.assign({}, spec);
  builder.addClass(fullSpec);

  return builder.build();
}

class DexBuilder {
  constructor () {
    this.classes = [];
  }

  addClass (spec) {
    this.classes.push(spec);
  }

  build () {
    const model = computeModel(this.classes);

    const {
      classes,
      interfaces,
      fields,
      methods,
      protos,
      parameters,
      annotationDirectories,
      annotationSets,
      throwsAnnotations,
      types,
      strings
    } = model;

    let offset = 0;

    const headerOffset = 0;
    const checksumOffset = 8;
    const signatureOffset = 12;
    const signatureSize = 20;
    const headerSize = 0x70;
    offset += headerSize;

    const stringIdsOffset = offset;
    const stringIdsSize = strings.length * kStringIdSize;
    offset += stringIdsSize;

    const typeIdsOffset = offset;
    const typeIdsSize = types.length * kTypeIdSize;
    offset += typeIdsSize;

    const protoIdsOffset = offset;
    const protoIdsSize = protos.length * kProtoIdSize;
    offset += protoIdsSize;

    const fieldIdsOffset = offset;
    const fieldIdsSize = fields.length * kFieldIdSize;
    offset += fieldIdsSize;

    const methodIdsOffset = offset;
    const methodIdsSize = methods.length * kMethodIdSize;
    offset += methodIdsSize;

    const classDefsOffset = offset;
    const classDefsSize = classes.length * kClassDefSize;
    offset += classDefsSize;

    const dataOffset = offset;

    const annotationSetOffsets = annotationSets.map(set => {
      const setOffset = offset;
      set.offset = setOffset;

      offset += 4 + (set.items.length * 4);

      return setOffset;
    });

    const javaCodeItems = classes.reduce((result, klass) => {
      const constructorMethods = klass.classData.constructorMethods;

      constructorMethods.forEach(method => {
        const [, accessFlags, superConstructor] = method;
        if ((accessFlags & kAccNative) === 0 && superConstructor >= 0) {
          method.push(offset);
          result.push({ offset, superConstructor });
          offset += kDefaultConstructorSize;
        }
      });

      return result;
    }, []);

    annotationDirectories.forEach(dir => {
      dir.offset = offset;

      offset += 16 + (dir.methods.length * 8);
    });

    const interfaceOffsets = interfaces.map(iface => {
      offset = align(offset, 4);

      const ifaceOffset = offset;
      iface.offset = ifaceOffset;

      offset += 4 + (2 * iface.types.length);

      return ifaceOffset;
    });

    const parameterOffsets = parameters.map(param => {
      offset = align(offset, 4);

      const paramOffset = offset;
      param.offset = paramOffset;

      offset += 4 + (2 * param.types.length);

      return paramOffset;
    });

    const stringChunks = [];
    const stringOffsets = strings.map(str => {
      const strOffset = offset;

      const header = Buffer.from(createUleb128(str.length));
      const data = Buffer.from(str, 'utf8');
      const chunk = Buffer.concat([header, data, kNullTerminator]);

      stringChunks.push(chunk);

      offset += chunk.length;

      return strOffset;
    });

    const debugInfoOffsets = javaCodeItems.map(codeItem => {
      const debugOffset = offset;
      offset += kDefaultConstructorDebugInfo.length;
      return debugOffset;
    });

    const throwsAnnotationBlobs = throwsAnnotations.map(annotation => {
      const blob = makeThrowsAnnotation(annotation);

      annotation.offset = offset;

      offset += blob.length;

      return blob;
    });

    const classDataBlobs = classes.map((klass, index) => {
      klass.classData.offset = offset;

      const blob = makeClassData(klass);

      offset += blob.length;

      return blob;
    });

    const linkSize = 0;
    const linkOffset = 0;

    offset = align(offset, 4);
    const mapOffset = offset;
    const typeListLength = interfaces.length + parameters.length;
    const mapNumItems = 4 + ((fields.length > 0) ? 1 : 0) + 2 + annotationSets.length + javaCodeItems.length + annotationDirectories.length +
      ((typeListLength > 0) ? 1 : 0) + 1 + debugInfoOffsets.length + throwsAnnotations.length + classes.length + 1;
    const mapSize = 4 + (mapNumItems * kMapItemSize);
    offset += mapSize;

    const dataSize = offset - dataOffset;

    const fileSize = offset;

    const dex = Buffer.alloc(fileSize);

    dex.write('dex\n035');

    dex.writeUInt32LE(fileSize, 0x20);
    dex.writeUInt32LE(headerSize, 0x24);
    dex.writeUInt32LE(kEndianTag, 0x28);
    dex.writeUInt32LE(linkSize, 0x2c);
    dex.writeUInt32LE(linkOffset, 0x30);
    dex.writeUInt32LE(mapOffset, 0x34);
    dex.writeUInt32LE(strings.length, 0x38);
    dex.writeUInt32LE(stringIdsOffset, 0x3c);
    dex.writeUInt32LE(types.length, 0x40);
    dex.writeUInt32LE(typeIdsOffset, 0x44);
    dex.writeUInt32LE(protos.length, 0x48);
    dex.writeUInt32LE(protoIdsOffset, 0x4c);
    dex.writeUInt32LE(fields.length, 0x50);
    dex.writeUInt32LE(fields.length > 0 ? fieldIdsOffset : 0, 0x54);
    dex.writeUInt32LE(methods.length, 0x58);
    dex.writeUInt32LE(methodIdsOffset, 0x5c);
    dex.writeUInt32LE(classes.length, 0x60);
    dex.writeUInt32LE(classDefsOffset, 0x64);
    dex.writeUInt32LE(dataSize, 0x68);
    dex.writeUInt32LE(dataOffset, 0x6c);

    stringOffsets.forEach((offset, index) => {
      dex.writeUInt32LE(offset, stringIdsOffset + (index * kStringIdSize));
    });

    types.forEach((id, index) => {
      dex.writeUInt32LE(id, typeIdsOffset + (index * kTypeIdSize));
    });

    protos.forEach((proto, index) => {
      const [shortyIndex, returnTypeIndex, params] = proto;

      const protoOffset = protoIdsOffset + (index * kProtoIdSize);
      dex.writeUInt32LE(shortyIndex, protoOffset);
      dex.writeUInt32LE(returnTypeIndex, protoOffset + 4);
      dex.writeUInt32LE((params !== null) ? params.offset : 0, protoOffset + 8);
    });

    fields.forEach((field, index) => {
      const [classIndex, typeIndex, nameIndex] = field;

      const fieldOffset = fieldIdsOffset + (index * kFieldIdSize);
      dex.writeUInt16LE(classIndex, fieldOffset);
      dex.writeUInt16LE(typeIndex, fieldOffset + 2);
      dex.writeUInt32LE(nameIndex, fieldOffset + 4);
    });

    methods.forEach((method, index) => {
      const [classIndex, protoIndex, nameIndex] = method;

      const methodOffset = methodIdsOffset + (index * kMethodIdSize);
      dex.writeUInt16LE(classIndex, methodOffset);
      dex.writeUInt16LE(protoIndex, methodOffset + 2);
      dex.writeUInt32LE(nameIndex, methodOffset + 4);
    });

    classes.forEach((klass, index) => {
      const { interfaces, annotationsDirectory } = klass;
      const interfacesOffset = (interfaces !== null) ? interfaces.offset : 0;
      const annotationsOffset = (annotationsDirectory !== null) ? annotationsDirectory.offset : 0;
      const staticValuesOffset = 0;

      const classOffset = classDefsOffset + (index * kClassDefSize);
      dex.writeUInt32LE(klass.index, classOffset);
      dex.writeUInt32LE(klass.accessFlags, classOffset + 4);
      dex.writeUInt32LE(klass.superClassIndex, classOffset + 8);
      dex.writeUInt32LE(interfacesOffset, classOffset + 12);
      dex.writeUInt32LE(klass.sourceFileIndex, classOffset + 16);
      dex.writeUInt32LE(annotationsOffset, classOffset + 20);
      dex.writeUInt32LE(klass.classData.offset, classOffset + 24);
      dex.writeUInt32LE(staticValuesOffset, classOffset + 28);
    });

    annotationSets.forEach((set, index) => {
      const { items } = set;
      const setOffset = annotationSetOffsets[index];

      dex.writeUInt32LE(items.length, setOffset);
      items.forEach((item, index) => {
        dex.writeUInt32LE(item.offset, setOffset + 4 + (index * 4));
      });
    });

    javaCodeItems.forEach((codeItem, index) => {
      const { offset, superConstructor } = codeItem;

      const registersSize = 1;
      const insSize = 1;
      const outsSize = 1;
      const triesSize = 0;
      const insnsSize = 4;

      dex.writeUInt16LE(registersSize, offset);
      dex.writeUInt16LE(insSize, offset + 2);
      dex.writeUInt16LE(outsSize, offset + 4);
      dex.writeUInt16LE(triesSize, offset + 6);
      dex.writeUInt32LE(debugInfoOffsets[index], offset + 8);
      dex.writeUInt32LE(insnsSize, offset + 12);
      dex.writeUInt16LE(0x1070, offset + 16);
      dex.writeUInt16LE(superConstructor, offset + 18);
      dex.writeUInt16LE(0x0000, offset + 20);
      dex.writeUInt16LE(0x000e, offset + 22);
    });

    annotationDirectories.forEach(dir => {
      const dirOffset = dir.offset;

      const classAnnotationsOffset = 0;
      const fieldsSize = 0;
      const annotatedMethodsSize = dir.methods.length;
      const annotatedParametersSize = 0;

      dex.writeUInt32LE(classAnnotationsOffset, dirOffset);
      dex.writeUInt32LE(fieldsSize, dirOffset + 4);
      dex.writeUInt32LE(annotatedMethodsSize, dirOffset + 8);
      dex.writeUInt32LE(annotatedParametersSize, dirOffset + 12);

      dir.methods.forEach((method, index) => {
        const entryOffset = dirOffset + 16 + (index * 8);

        const [methodIndex, annotationSet] = method;
        dex.writeUInt32LE(methodIndex, entryOffset);
        dex.writeUInt32LE(annotationSet.offset, entryOffset + 4);
      });
    });

    interfaces.forEach((iface, index) => {
      const ifaceOffset = interfaceOffsets[index];

      dex.writeUInt32LE(iface.types.length, ifaceOffset);
      iface.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, ifaceOffset + 4 + (typeIndex * 2));
      });
    });

    parameters.forEach((param, index) => {
      const paramOffset = parameterOffsets[index];

      dex.writeUInt32LE(param.types.length, paramOffset);
      param.types.forEach((type, typeIndex) => {
        dex.writeUInt16LE(type, paramOffset + 4 + (typeIndex * 2));
      });
    });

    stringChunks.forEach((chunk, index) => {
      chunk.copy(dex, stringOffsets[index]);
    });

    debugInfoOffsets.forEach(debugInfoOffset => {
      kDefaultConstructorDebugInfo.copy(dex, debugInfoOffset);
    });

    throwsAnnotationBlobs.forEach((annotationBlob, index) => {
      annotationBlob.copy(dex, throwsAnnotations[index].offset);
    });

    classDataBlobs.forEach((classDataBlob, index) => {
      classDataBlob.copy(dex, classes[index].classData.offset);
    });

    dex.writeUInt32LE(mapNumItems, mapOffset);
    const mapItems = [
      [TYPE_HEADER_ITEM, 1, headerOffset],
      [TYPE_STRING_ID_ITEM, strings.length, stringIdsOffset],
      [TYPE_TYPE_ID_ITEM, types.length, typeIdsOffset],
      [TYPE_PROTO_ID_ITEM, protos.length, protoIdsOffset]
    ];
    if (fields.length > 0) {
      mapItems.push([TYPE_FIELD_ID_ITEM, fields.length, fieldIdsOffset]);
    }
    mapItems.push([TYPE_METHOD_ID_ITEM, methods.length, methodIdsOffset]);
    mapItems.push([TYPE_CLASS_DEF_ITEM, classes.length, classDefsOffset]);
    annotationSets.forEach((set, index) => {
      mapItems.push([TYPE_ANNOTATION_SET_ITEM, set.items.length, annotationSetOffsets[index]]);
    });
    javaCodeItems.forEach(codeItem => {
      mapItems.push([TYPE_CODE_ITEM, 1, codeItem.offset]);
    });
    annotationDirectories.forEach(dir => {
      mapItems.push([TYPE_ANNOTATIONS_DIRECTORY_ITEM, 1, dir.offset]);
    });
    if (typeListLength > 0) {
      mapItems.push([TYPE_TYPE_LIST, typeListLength, interfaceOffsets.concat(parameterOffsets)[0]]);
    }
    mapItems.push([TYPE_STRING_DATA_ITEM, strings.length, stringOffsets[0]]);
    debugInfoOffsets.forEach(debugInfoOffset => {
      mapItems.push([TYPE_DEBUG_INFO_ITEM, 1, debugInfoOffset]);
    });
    throwsAnnotations.forEach(annotation => {
      mapItems.push([TYPE_ANNOTATION_ITEM, 1, annotation.offset]);
    });
    classes.forEach(klass => {
      mapItems.push([TYPE_CLASS_DATA_ITEM, 1, klass.classData.offset]);
    });
    mapItems.push([TYPE_MAP_LIST, 1, mapOffset]);
    mapItems.forEach((item, index) => {
      const [type, size, offset] = item;

      const itemOffset = mapOffset + 4 + (index * kMapItemSize);
      dex.writeUInt16LE(type, itemOffset);
      dex.writeUInt32LE(size, itemOffset + 4);
      dex.writeUInt32LE(offset, itemOffset + 8);
    });

    const hash = new Checksum('sha1');
    hash.update(dex.slice(signatureOffset + signatureSize));
    Buffer.from(hash.getDigest()).copy(dex, signatureOffset);

    dex.writeUInt32LE(adler32(dex, signatureOffset), checksumOffset);

    return dex;
  }
}

function makeClassData (klass) {
  const { instanceFields, constructorMethods, virtualMethods } = klass.classData;

  const staticFieldsSize = 0;

  return Buffer.from([
    staticFieldsSize
  ]
    .concat(createUleb128(instanceFields.length))
    .concat(createUleb128(constructorMethods.length))
    .concat(createUleb128(virtualMethods.length))
    .concat(instanceFields.reduce((result, [indexDiff, accessFlags]) => {
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags));
    }, []))
    .concat(constructorMethods.reduce((result, [indexDiff, accessFlags, , codeOffset]) => {
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags))
        .concat(createUleb128(codeOffset || 0));
    }, []))
    .concat(virtualMethods.reduce((result, [indexDiff, accessFlags]) => {
      const codeOffset = 0;
      return result
        .concat(createUleb128(indexDiff))
        .concat(createUleb128(accessFlags))
        .concat([codeOffset]);
    }, [])));
}

function makeThrowsAnnotation (annotation) {
  const { thrownTypes } = annotation;

  return Buffer.from([
    VISIBILITY_SYSTEM
  ]
    .concat(createUleb128(annotation.type))
    .concat([1])
    .concat(createUleb128(annotation.value))
    .concat([VALUE_ARRAY, thrownTypes.length])
    .concat(thrownTypes.reduce((result, type) => {
      result.push(VALUE_TYPE, type);
      return result;
    }, []))
  );
}

function computeModel (classes) {
  const strings = new Set();
  const types = new Set();
  const protos = {};
  const fields = [];
  const methods = [];
  const throwsAnnotations = {};
  const javaConstructors = new Set();
  const superConstructors = new Set();

  classes.forEach(klass => {
    const { name, superClass, sourceFileName } = klass;

    strings.add('this');

    strings.add(name);
    types.add(name);

    strings.add(superClass);
    types.add(superClass);

    strings.add(sourceFileName);

    klass.interfaces.forEach(iface => {
      strings.add(iface);
      types.add(iface);
    });

    klass.fields.forEach(field => {
      const [fieldName, fieldType] = field;
      strings.add(fieldName);
      strings.add(fieldType);
      types.add(fieldType);
      fields.push([klass.name, fieldType, fieldName]);
    });

    if (!klass.methods.some(([methodName]) => methodName === '<init>')) {
      klass.methods.unshift(['<init>', 'V', []]);
      javaConstructors.add(name);
    }

    klass.methods.forEach(method => {
      const [methodName, retType, argTypes, thrownTypes = [], accessFlags] = method;

      strings.add(methodName);

      const protoId = addProto(retType, argTypes);

      let throwsAnnotationId = null;
      if (thrownTypes.length > 0) {
        const typesNormalized = thrownTypes.slice();
        typesNormalized.sort();

        throwsAnnotationId = typesNormalized.join('|');

        let throwsAnnotation = throwsAnnotations[throwsAnnotationId];
        if (throwsAnnotation === undefined) {
          throwsAnnotation = {
            id: throwsAnnotationId,
            types: typesNormalized
          };
          throwsAnnotations[throwsAnnotationId] = throwsAnnotation;
        }

        strings.add(kDalvikAnnotationTypeThrows);
        types.add(kDalvikAnnotationTypeThrows);

        thrownTypes.forEach(type => {
          strings.add(type);
          types.add(type);
        });

        strings.add('value');
      }

      methods.push([klass.name, protoId, methodName, throwsAnnotationId, accessFlags]);

      if (methodName === '<init>') {
        superConstructors.add(name + '|' + protoId);
        const superConstructorId = superClass + '|' + protoId;
        if (javaConstructors.has(name) && !superConstructors.has(superConstructorId)) {
          methods.push([superClass, protoId, methodName, null, 0]);
          superConstructors.add(superConstructorId);
        }
      }
    });
  });

  function addProto (retType, argTypes) {
    const signature = [retType].concat(argTypes);

    const id = signature.join('|');
    if (protos[id] !== undefined) {
      return id;
    }

    strings.add(retType);
    types.add(retType);
    argTypes.forEach(argType => {
      strings.add(argType);
      types.add(argType);
    });

    const shorty = signature.map(typeToShorty).join('');
    strings.add(shorty);

    protos[id] = [id, shorty, retType, argTypes];

    return id;
  }

  const stringItems = Array.from(strings);
  stringItems.sort();
  const stringToIndex = stringItems.reduce((result, string, index) => {
    result[string] = index;
    return result;
  }, {});

  const typeItems = Array.from(types).map(name => stringToIndex[name]);
  typeItems.sort(compareNumbers);
  const typeToIndex = typeItems.reduce((result, stringIndex, typeIndex) => {
    result[stringItems[stringIndex]] = typeIndex;
    return result;
  }, {});

  const literalProtoItems = Object.keys(protos).map(id => protos[id]);
  literalProtoItems.sort(compareProtoItems);
  const parameters = {};
  const protoItems = literalProtoItems.map(item => {
    const [, shorty, retType, argTypes] = item;

    let params;
    if (argTypes.length > 0) {
      const argTypesSig = argTypes.join('|');
      params = parameters[argTypesSig];
      if (params === undefined) {
        params = {
          types: argTypes.map(type => typeToIndex[type]),
          offset: -1
        };
        parameters[argTypesSig] = params;
      }
    } else {
      params = null;
    }

    return [
      stringToIndex[shorty],
      typeToIndex[retType],
      params
    ];
  });
  const protoToIndex = literalProtoItems.reduce((result, item, index) => {
    const [id] = item;
    result[id] = index;
    return result;
  }, {});
  const parameterItems = Object.keys(parameters).map(id => parameters[id]);

  const fieldItems = fields.map(field => {
    const [klass, fieldType, fieldName] = field;
    return [
      typeToIndex[klass],
      typeToIndex[fieldType],
      stringToIndex[fieldName]
    ];
  });
  fieldItems.sort(compareFieldItems);

  const methodItems = methods.map(method => {
    const [klass, protoId, name, annotationsId, accessFlags] = method;
    return [
      typeToIndex[klass],
      protoToIndex[protoId],
      stringToIndex[name],
      annotationsId,
      accessFlags
    ];
  });
  methodItems.sort(compareMethodItems);

  const throwsAnnotationItems = Object.keys(throwsAnnotations)
    .map(id => throwsAnnotations[id])
    .map(item => {
      return {
        id: item.id,
        type: typeToIndex[kDalvikAnnotationTypeThrows],
        value: stringToIndex.value,
        thrownTypes: item.types.map(type => typeToIndex[type]),
        offset: -1
      };
    });

  const annotationSetItems = throwsAnnotationItems.map(item => {
    return {
      id: item.id,
      items: [item],
      offset: -1
    };
  });
  const annotationSetIdToIndex = annotationSetItems.reduce((result, item, index) => {
    result[item.id] = index;
    return result;
  }, {});

  const interfaceLists = {};
  const annotationDirectories = [];
  const classItems = classes.map(klass => {
    const classIndex = typeToIndex[klass.name];
    const accessFlags = kAccPublic;
    const superClassIndex = typeToIndex[klass.superClass];

    let ifaceList;
    const ifaces = klass.interfaces.map(type => typeToIndex[type]);
    if (ifaces.length > 0) {
      ifaces.sort(compareNumbers);
      const ifacesId = ifaces.join('|');
      ifaceList = interfaceLists[ifacesId];
      if (ifaceList === undefined) {
        ifaceList = {
          types: ifaces,
          offset: -1
        };
        interfaceLists[ifacesId] = ifaceList;
      }
    } else {
      ifaceList = null;
    }

    const sourceFileIndex = stringToIndex[klass.sourceFileName];

    const classMethods = methodItems.reduce((result, method, index) => {
      const [holder, protoIndex, name, annotationsId, accessFlags] = method;
      if (holder === classIndex) {
        result.push([index, name, annotationsId, protoIndex, accessFlags]);
      }
      return result;
    }, []);

    let annotationsDirectory = null;
    const methodAnnotations = classMethods
      .filter(([, , annotationsId]) => {
        return annotationsId !== null;
      })
      .map(([index, , annotationsId]) => {
        return [index, annotationSetItems[annotationSetIdToIndex[annotationsId]]];
      });
    if (methodAnnotations.length > 0) {
      annotationsDirectory = {
        methods: methodAnnotations,
        offset: -1
      };
      annotationDirectories.push(annotationsDirectory);
    }

    const instanceFields = fieldItems.reduce((result, field, index) => {
      const [holder] = field;
      if (holder === classIndex) {
        result.push([index > 0 ? 1 : 0, kAccPublic]);
      }
      return result;
    }, []);

    const constructorNameIndex = stringToIndex['<init>'];
    const constructorMethods = classMethods
      .filter(([, name]) => name === constructorNameIndex)
      .map(([index, , , protoIndex]) => {
        if (javaConstructors.has(klass.name)) {
          let superConstructor = -1;
          const numMethodItems = methodItems.length;
          for (let i = 0; i !== numMethodItems; i++) {
            const [methodClass, methodProto, methodName] = methodItems[i];
            if (methodClass === superClassIndex && methodName === constructorNameIndex && methodProto === protoIndex) {
              superConstructor = i;
              break;
            }
          }
          return [index, kAccPublic | kAccConstructor, superConstructor];
        } else {
          return [index, kAccPublic | kAccConstructor | kAccNative, -1];
        }
      });
    const virtualMethods = compressClassMethodIndexes(classMethods
      .filter(([, name]) => name !== constructorNameIndex)
      .map(([index, , , , accessFlags]) => {
        return [index, accessFlags | kAccPublic | kAccNative];
      }));

    const classData = {
      instanceFields,
      constructorMethods,
      virtualMethods,
      offset: -1
    };

    return {
      index: classIndex,
      accessFlags,
      superClassIndex,
      interfaces: ifaceList,
      sourceFileIndex,
      annotationsDirectory,
      classData
    };
  });
  const interfaceItems = Object.keys(interfaceLists).map(id => interfaceLists[id]);

  return {
    classes: classItems,
    interfaces: interfaceItems,
    fields: fieldItems,
    methods: methodItems,
    protos: protoItems,
    parameters: parameterItems,
    annotationDirectories,
    annotationSets: annotationSetItems,
    throwsAnnotations: throwsAnnotationItems,
    types: typeItems,
    strings: stringItems
  };
}

function compressClassMethodIndexes (items) {
  let previousIndex = 0;
  return items.map(([index, accessFlags], elementIndex) => {
    let result;
    if (elementIndex === 0) {
      result = [index, accessFlags];
    } else {
      result = [index - previousIndex, accessFlags];
    }
    previousIndex = index;
    return result;
  });
}

function compareNumbers (a, b) {
  return a - b;
}

function compareProtoItems (a, b) {
  const [, , aRetType, aArgTypes] = a;
  const [, , bRetType, bArgTypes] = b;

  if (aRetType < bRetType) {
    return -1;
  }
  if (aRetType > bRetType) {
    return 1;
  }

  const aArgTypesSig = aArgTypes.join('|');
  const bArgTypesSig = bArgTypes.join('|');
  if (aArgTypesSig < bArgTypesSig) {
    return -1;
  }
  if (aArgTypesSig > bArgTypesSig) {
    return 1;
  }
  return 0;
}

function compareFieldItems (a, b) {
  const [aClass, aType, aName] = a;
  const [bClass, bType, bName] = b;

  if (aClass !== bClass) {
    return aClass - bClass;
  }

  if (aName !== bName) {
    return aName - bName;
  }

  return aType - bType;
}

function compareMethodItems (a, b) {
  const [aClass, aProto, aName] = a;
  const [bClass, bProto, bName] = b;

  if (aClass !== bClass) {
    return aClass - bClass;
  }

  if (aName !== bName) {
    return aName - bName;
  }

  return aProto - bProto;
}

function typeToShorty (type) {
  const firstCharacter = type[0];
  return (firstCharacter === 'L' || firstCharacter === '[') ? 'L' : type;
}

function createUleb128 (value) {
  if (value <= 0x7f) {
    return [value];
  }

  const result = [];
  let moreSlicesNeeded = false;

  do {
    let slice = value & 0x7f;

    value >>= 7;
    moreSlicesNeeded = value !== 0;

    if (moreSlicesNeeded) {
      slice |= 0x80;
    }

    result.push(slice);
  } while (moreSlicesNeeded);

  return result;
}

function align (value, alignment) {
  const alignmentDelta = value % alignment;
  if (alignmentDelta === 0) {
    return value;
  }
  return value + alignment - alignmentDelta;
}

function adler32 (buffer, offset) {
  let a = 1;
  let b = 0;

  const length = buffer.length;
  for (let i = offset; i < length; i++) {
    a = (a + buffer[i]) % 65521;
    b = (b + a) % 65521;
  }

  return ((b << 16) | a) >>> 0;
}

export default mkdex;

✄
export const JNI_OK = 0;

export function checkJniResult (name, result) {
  if (result !== JNI_OK) {
    throw new Error(name + ' failed: ' + result);
  }
}

✄
import Env from './env.js';

const JNILocalRefType = 1;

let vm = null;

let primitiveArrayHandler = null;

export function initialize (_vm) {
  vm = _vm;
}

/*
 * http://docs.oracle.com/javase/6/docs/technotes/guides/jni/spec/types.html#wp9502
 * http://www.liaohuqiu.net/posts/android-object-size-dalvik/
 */
export function getType (typeName, unbox, factory) {
  let type = getPrimitiveType(typeName);
  if (type === null) {
    if (typeName.indexOf('[') === 0) {
      type = getArrayType(typeName, unbox, factory);
    } else {
      if (typeName[0] === 'L' && typeName[typeName.length - 1] === ';') {
        typeName = typeName.substring(1, typeName.length - 1);
      }
      type = getObjectType(typeName, unbox, factory);
    }
  }

  return Object.assign({ className: typeName }, type);
}

const primitiveTypes = {
  boolean: {
    name: 'Z',
    type: 'uint8',
    size: 1,
    byteSize: 1,
    defaultValue: false,
    isCompatible (v) {
      return typeof v === 'boolean';
    },
    fromJni (v) {
      return !!v;
    },
    toJni (v) {
      return v ? 1 : 0;
    },
    read (address) {
      return address.readU8();
    },
    write (address, value) {
      address.writeU8(value);
    },
    toString () {
      return this.name;
    }
  },
  byte: {
    name: 'B',
    type: 'int8',
    size: 1,
    byteSize: 1,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= -128 && v <= 127;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS8();
    },
    write (address, value) {
      address.writeS8(value);
    },
    toString () {
      return this.name;
    }
  },
  char: {
    name: 'C',
    type: 'uint16',
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible (v) {
      if (typeof v !== 'string' || v.length !== 1) {
        return false;
      }

      const code = v.charCodeAt(0);
      return code >= 0 && code <= 65535;
    },
    fromJni (c) {
      return String.fromCharCode(c);
    },
    toJni (s) {
      return s.charCodeAt(0);
    },
    read (address) {
      return address.readU16();
    },
    write (address, value) {
      address.writeU16(value);
    },
    toString () {
      return this.name;
    }
  },
  short: {
    name: 'S',
    type: 'int16',
    size: 1,
    byteSize: 2,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= -32768 && v <= 32767;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS16();
    },
    write (address, value) {
      address.writeS16(value);
    },
    toString () {
      return this.name;
    }
  },
  int: {
    name: 'I',
    type: 'int32',
    size: 1,
    byteSize: 4,
    defaultValue: 0,
    isCompatible (v) {
      return Number.isInteger(v) && v >= -2147483648 && v <= 2147483647;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS32();
    },
    write (address, value) {
      address.writeS32(value);
    },
    toString () {
      return this.name;
    }
  },
  long: {
    name: 'J',
    type: 'int64',
    size: 2,
    byteSize: 8,
    defaultValue: 0,
    isCompatible (v) {
      return typeof v === 'number' || v instanceof Int64;
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readS64();
    },
    write (address, value) {
      address.writeS64(value);
    },
    toString () {
      return this.name;
    }
  },
  float: {
    name: 'F',
    type: 'float',
    size: 1,
    byteSize: 4,
    defaultValue: 0,
    isCompatible (v) {
      return typeof v === 'number';
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readFloat();
    },
    write (address, value) {
      address.writeFloat(value);
    },
    toString () {
      return this.name;
    }
  },
  double: {
    name: 'D',
    type: 'double',
    size: 2,
    byteSize: 8,
    defaultValue: 0,
    isCompatible (v) {
      return typeof v === 'number';
    },
    fromJni: identity,
    toJni: identity,
    read (address) {
      return address.readDouble();
    },
    write (address, value) {
      address.writeDouble(value);
    },
    toString () {
      return this.name;
    }
  },
  void: {
    name: 'V',
    type: 'void',
    size: 0,
    byteSize: 0,
    defaultValue: undefined,
    isCompatible (v) {
      return v === undefined;
    },
    fromJni () {
      return undefined;
    },
    toJni () {
      return NULL;
    },
    toString () {
      return this.name;
    }
  }
};

const primitiveTypesNames = new Set(Object.values(primitiveTypes).map(t => t.name));

export function getPrimitiveType (name) {
  const result = primitiveTypes[name];
  return (result !== undefined) ? result : null;
}

function getObjectType (typeName, unbox, factory) {
  const cache = factory._types[unbox ? 1 : 0];

  let type = cache[typeName];
  if (type !== undefined) {
    return type;
  }

  if (typeName === 'java.lang.Object') {
    type = getJavaLangObjectType(factory);
  } else {
    type = getAnyObjectType(typeName, unbox, factory);
  }

  cache[typeName] = type;

  return type;
}

function getJavaLangObjectType (factory) {
  return {
    name: 'Ljava/lang/Object;',
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      if (v === null) {
        return true;
      }

      if (v === undefined) {
        return false;
      }

      const isWrapper = v.$h instanceof NativePointer;
      if (isWrapper) {
        return true;
      }

      return typeof v === 'string';
    },
    fromJni (h, env, owned) {
      if (h.isNull()) {
        return null;
      }

      return factory.cast(h, factory.use('java.lang.Object'), owned);
    },
    toJni (o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$h;
    }
  };
}

function getAnyObjectType (typeName, unbox, factory) {
  let cachedClass = null;
  let cachedIsInstance = null;
  let cachedIsDefaultString = null;

  function getClass () {
    if (cachedClass === null) {
      cachedClass = factory.use(typeName).class;
    }
    return cachedClass;
  }

  function isInstance (v) {
    const klass = getClass();

    if (cachedIsInstance === null) {
      cachedIsInstance = klass.isInstance.overload('java.lang.Object');
    }

    return cachedIsInstance.call(klass, v);
  }

  function typeIsDefaultString () {
    if (cachedIsDefaultString === null) {
      const x = getClass();
      cachedIsDefaultString = factory.use('java.lang.String').class.isAssignableFrom(x);
    }
    return cachedIsDefaultString;
  }

  return {
    name: makeJniObjectTypeName(typeName),
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      if (v === null) {
        return true;
      }

      if (v === undefined) {
        return false;
      }

      const isWrapper = v.$h instanceof NativePointer;
      if (isWrapper) {
        return isInstance(v);
      }

      return typeof v === 'string' && typeIsDefaultString();
    },
    fromJni (h, env, owned) {
      if (h.isNull()) {
        return null;
      }

      if (typeIsDefaultString() && unbox) {
        return env.stringFromJni(h);
      }

      return factory.cast(h, factory.use(typeName), owned);
    },
    toJni (o, env) {
      if (o === null) {
        return NULL;
      }

      if (typeof o === 'string') {
        return env.newStringUtf(o);
      }

      return o.$h;
    },
    toString () {
      return this.name;
    }
  };
}

const primitiveArrayTypes = [
  ['Z', 'boolean'],
  ['B', 'byte'],
  ['C', 'char'],
  ['D', 'double'],
  ['F', 'float'],
  ['I', 'int'],
  ['J', 'long'],
  ['S', 'short']
]
  .reduce((result, [shorty, name]) => {
    result['[' + shorty] = makePrimitiveArrayType('[' + shorty, name);
    return result;
  }, {});

function makePrimitiveArrayType (shorty, name) {
  const envProto = Env.prototype;

  const nameTitled = toTitleCase(name);
  const spec = {
    typeName: name,
    newArray: envProto['new' + nameTitled + 'Array'],
    setRegion: envProto['set' + nameTitled + 'ArrayRegion'],
    getElements: envProto['get' + nameTitled + 'ArrayElements'],
    releaseElements: envProto['release' + nameTitled + 'ArrayElements']
  };

  return {
    name: shorty,
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      return isCompatiblePrimitiveArray(v, name);
    },
    fromJni (h, env, owned) {
      return fromJniPrimitiveArray(h, spec, env, owned);
    },
    toJni (arr, env) {
      return toJniPrimitiveArray(arr, spec, env);
    }
  };
}

export function getArrayType (typeName, unbox, factory) {
  const primitiveType = primitiveArrayTypes[typeName];
  if (primitiveType !== undefined) {
    return primitiveType;
  }

  if (typeName.indexOf('[') !== 0) {
    throw new Error('Unsupported type: ' + typeName);
  }

  let elementTypeName = typeName.substring(1);
  const elementType = getType(elementTypeName, unbox, factory);

  let numInternalArrays = 0;
  const end = elementTypeName.length;
  while (numInternalArrays !== end && elementTypeName[numInternalArrays] === '[') {
    numInternalArrays++;
  }
  elementTypeName = elementTypeName.substring(numInternalArrays);

  if (elementTypeName[0] === 'L' && elementTypeName[elementTypeName.length - 1] === ';') {
    elementTypeName = elementTypeName.substring(1, elementTypeName.length - 1);
  }

  // The type name we get is not always the correct representation of the type so we make it so here.
  let internalElementTypeName = elementTypeName.replace(/\./g, '/');
  if (primitiveTypesNames.has(internalElementTypeName)) {
    internalElementTypeName = '['.repeat(numInternalArrays) + internalElementTypeName;
  } else {
    internalElementTypeName = '['.repeat(numInternalArrays) + 'L' + internalElementTypeName + ';';
  }
  const internalTypeName = '[' + internalElementTypeName;
  elementTypeName = '['.repeat(numInternalArrays) + elementTypeName;

  return {
    name: typeName.replace(/\./g, '/'),
    type: 'pointer',
    size: 1,
    defaultValue: NULL,
    isCompatible (v) {
      if (v === null) {
        return true;
      }

      if (typeof v !== 'object' || v.length === undefined) {
        return false;
      }

      return v.every(function (element) {
        return elementType.isCompatible(element);
      });
    },
    fromJni (arr, env, owned) {
      if (arr.isNull()) {
        return null;
      }

      const result = [];

      const n = env.getArrayLength(arr);
      for (let i = 0; i !== n; i++) {
        const element = env.getObjectArrayElement(arr, i);
        try {
          // We'll ignore the owned hint as we might otherwise run out of local references.
          result.push(elementType.fromJni(element, env));
        } finally {
          env.deleteLocalRef(element);
        }
      }

      try {
        result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
      } catch (e) {
        // We need to load the array type before using it.
        factory.use('java.lang.reflect.Array').newInstance(factory.use(elementTypeName).class, 0);
        result.$w = factory.cast(arr, factory.use(internalTypeName), owned);
      }

      result.$dispose = disposeObjectArray;

      return result;
    },
    toJni (elements, env) {
      if (elements === null) {
        return NULL;
      }

      if (!(elements instanceof Array)) {
        throw new Error('Expected an array');
      }

      const wrapper = elements.$w;
      if (wrapper !== undefined) {
        return wrapper.$h;
      }

      const n = elements.length;

      const klassObj = factory.use(elementTypeName);
      const classHandle = klassObj.$borrowClassHandle(env);
      try {
        const result = env.newObjectArray(n, classHandle.value, NULL);
        env.throwIfExceptionPending();

        for (let i = 0; i !== n; i++) {
          const handle = elementType.toJni(elements[i], env);
          try {
            env.setObjectArrayElement(result, i, handle);
          } finally {
            if (elementType.type === 'pointer' && env.getObjectRefType(handle) === JNILocalRefType) {
              env.deleteLocalRef(handle);
            }
          }
          env.throwIfExceptionPending();
        }

        return result;
      } finally {
        classHandle.unref(env);
      }
    }
  };
}

function disposeObjectArray () {
  const n = this.length;

  for (let i = 0; i !== n; i++) {
    const obj = this[i];

    if (obj === null) {
      continue;
    }

    const dispose = obj.$dispose;
    if (dispose === undefined) {
      break;
    }
    dispose.call(obj);
  }

  this.$w.$dispose();
}

function fromJniPrimitiveArray (arr, spec, env, owned) {
  if (arr.isNull()) {
    return null;
  }

  const type = getPrimitiveType(spec.typeName);
  const length = env.getArrayLength(arr);

  return new PrimitiveArray(arr, spec, type, length, env, owned);
}

function toJniPrimitiveArray (arr, spec, env) {
  if (arr === null) {
    return NULL;
  }

  const handle = arr.$h;
  if (handle !== undefined) {
    return handle;
  }

  const length = arr.length;
  const type = getPrimitiveType(spec.typeName);
  const result = spec.newArray.call(env, length);
  if (result.isNull()) {
    throw new Error('Unable to construct array');
  }

  if (length > 0) {
    const elementSize = type.byteSize;
    const writeElement = type.write;
    const unparseElementValue = type.toJni;

    const elements = Memory.alloc(length * type.byteSize);
    for (let index = 0; index !== length; index++) {
      writeElement(elements.add(index * elementSize), unparseElementValue(arr[index]));
    }
    spec.setRegion.call(env, result, 0, length, elements);
    env.throwIfExceptionPending();
  }

  return result;
}

function isCompatiblePrimitiveArray (value, typeName) {
  if (value === null) {
    return true;
  }

  if (value instanceof PrimitiveArray) {
    return value.$s.typeName === typeName;
  }

  const isArrayLike = typeof value === 'object' && value.length !== undefined;
  if (!isArrayLike) {
    return false;
  }

  const elementType = getPrimitiveType(typeName);
  return Array.prototype.every.call(value, element => elementType.isCompatible(element));
}

function PrimitiveArray (handle, spec, type, length, env, owned = true) {
  if (owned) {
    const h = env.newGlobalRef(handle);
    this.$h = h;
    this.$r = Script.bindWeak(this, env.vm.makeHandleDestructor(h));
  } else {
    this.$h = handle;
    this.$r = null;
  }

  this.$s = spec;
  this.$t = type;

  this.length = length;

  return new Proxy(this, primitiveArrayHandler);
}

primitiveArrayHandler = {
  has (target, property) {
    if (property in target) {
      return true;
    }

    return target.tryParseIndex(property) !== null;
  },
  get (target, property, receiver) {
    const index = target.tryParseIndex(property);
    if (index === null) {
      return target[property];
    }

    return target.readElement(index);
  },
  set (target, property, value, receiver) {
    const index = target.tryParseIndex(property);
    if (index === null) {
      target[property] = value;
      return true;
    }

    target.writeElement(index, value);
    return true;
  },
  ownKeys (target) {
    const keys = [];

    const { length } = target;
    for (let i = 0; i !== length; i++) {
      const key = i.toString();
      keys.push(key);
    }

    keys.push('length');

    return keys;
  },
  getOwnPropertyDescriptor (target, property) {
    const index = target.tryParseIndex(property);
    if (index !== null) {
      return {
        writable: true,
        configurable: true,
        enumerable: true
      };
    }

    return Object.getOwnPropertyDescriptor(target, property);
  }
};

Object.defineProperties(PrimitiveArray.prototype, {
  $dispose: {
    enumerable: true,
    value () {
      const ref = this.$r;
      if (ref !== null) {
        this.$r = null;
        Script.unbindWeak(ref);
      }
    }
  },
  $clone: {
    value (env) {
      return new PrimitiveArray(this.$h, this.$s, this.$t, this.length, env);
    }
  },
  tryParseIndex: {
    value (rawIndex) {
      if (typeof rawIndex === 'symbol') {
        return null;
      }

      const index = parseInt(rawIndex);
      if (isNaN(index) || index < 0 || index >= this.length) {
        return null;
      }

      return index;
    }
  },
  readElement: {
    value (index) {
      return this.withElements(elements => {
        const type = this.$t;
        return type.fromJni(type.read(elements.add(index * type.byteSize)));
      });
    }
  },
  writeElement: {
    value (index, value) {
      const { $h: handle, $s: spec, $t: type } = this;
      const env = vm.getEnv();

      const element = Memory.alloc(type.byteSize);
      type.write(element, type.toJni(value));
      spec.setRegion.call(env, handle, index, 1, element);
    }
  },
  withElements: {
    value (perform) {
      const { $h: handle, $s: spec } = this;
      const env = vm.getEnv();

      const elements = spec.getElements.call(env, handle);
      if (elements.isNull()) {
        throw new Error('Unable to get array elements');
      }

      try {
        return perform(elements);
      } finally {
        spec.releaseElements.call(env, handle, elements);
      }
    }
  },
  toJSON: {
    value () {
      const { length, $t: type } = this;
      const { byteSize: elementSize, fromJni, read } = type;

      return this.withElements(elements => {
        const values = [];
        for (let i = 0; i !== length; i++) {
          const value = fromJni(read(elements.add(i * elementSize)));
          values.push(value);
        }
        return values;
      });
    }
  },
  toString: {
    value () {
      return this.toJSON().toString();
    }
  }
});

export function makeJniObjectTypeName (typeName) {
  return 'L' + typeName.replace(/\./g, '/') + ';';
}

function toTitleCase (str) {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function identity (value) {
  return value;
}

✄
import Env from './env.js';
import { JNI_OK, checkJniResult } from './result.js';

const JNI_VERSION_1_6 = 0x00010006;

const pointerSize = Process.pointerSize;

const jsThreadID = Process.getCurrentThreadId();
const attachedThreads = new Map();
const activeEnvs = new Map();

export default function VM (api) {
  const handle = api.vm;
  let attachCurrentThread = null;
  let detachCurrentThread = null;
  let getEnv = null;

  function initialize () {
    const vtable = handle.readPointer();
    const options = {
      exceptions: 'propagate'
    };
    attachCurrentThread = new NativeFunction(vtable.add(4 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'pointer'], options);
    detachCurrentThread = new NativeFunction(vtable.add(5 * pointerSize).readPointer(), 'int32', ['pointer'], options);
    getEnv = new NativeFunction(vtable.add(6 * pointerSize).readPointer(), 'int32', ['pointer', 'pointer', 'int32'], options);
  }

  this.handle = handle;

  this.perform = function (fn) {
    const threadId = Process.getCurrentThreadId();

    const cachedEnv = tryGetCachedEnv(threadId);
    if (cachedEnv !== null) {
      return fn(cachedEnv);
    }

    let env = this._tryGetEnv();
    const alreadyAttached = env !== null;
    if (!alreadyAttached) {
      env = this.attachCurrentThread();
      attachedThreads.set(threadId, true);
    }

    this.link(threadId, env);

    try {
      return fn(env);
    } finally {
      const isJsThread = threadId === jsThreadID;

      if (!isJsThread) {
        this.unlink(threadId);
      }

      if (!alreadyAttached && !isJsThread) {
        const allowedToDetach = attachedThreads.get(threadId);
        attachedThreads.delete(threadId);

        if (allowedToDetach) {
          this.detachCurrentThread();
        }
      }
    }
  };

  this.attachCurrentThread = function () {
    const envBuf = Memory.alloc(pointerSize);
    checkJniResult('VM::AttachCurrentThread', attachCurrentThread(handle, envBuf, NULL));
    return new Env(envBuf.readPointer(), this);
  };

  this.detachCurrentThread = function () {
    checkJniResult('VM::DetachCurrentThread', detachCurrentThread(handle));
  };

  this.preventDetachDueToClassLoader = function () {
    const threadId = Process.getCurrentThreadId();

    if (attachedThreads.has(threadId)) {
      attachedThreads.set(threadId, false);
    }
  };

  this.getEnv = function () {
    const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
    if (cachedEnv !== null) {
      return cachedEnv;
    }

    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, JNI_VERSION_1_6);
    if (result === -2) {
      throw new Error('Current thread is not attached to the Java VM; please move this code inside a Java.perform() callback');
    }
    checkJniResult('VM::GetEnv', result);
    return new Env(envBuf.readPointer(), this);
  };

  this.tryGetEnv = function () {
    const cachedEnv = tryGetCachedEnv(Process.getCurrentThreadId());
    if (cachedEnv !== null) {
      return cachedEnv;
    }

    return this._tryGetEnv();
  };

  this._tryGetEnv = function () {
    const h = this.tryGetEnvHandle(JNI_VERSION_1_6);
    if (h === null) {
      return null;
    }
    return new Env(h, this);
  };

  this.tryGetEnvHandle = function (version) {
    const envBuf = Memory.alloc(pointerSize);
    const result = getEnv(handle, envBuf, version);
    if (result !== JNI_OK) {
      return null;
    }
    return envBuf.readPointer();
  };

  this.makeHandleDestructor = function (handle) {
    return () => {
      this.perform(env => {
        env.deleteGlobalRef(handle);
      });
    };
  };

  this.link = function (tid, env) {
    const entry = activeEnvs.get(tid);
    if (entry === undefined) {
      activeEnvs.set(tid, [env, 1]);
    } else {
      entry[1]++;
    }
  };

  this.unlink = function (tid) {
    const entry = activeEnvs.get(tid);
    if (entry[1] === 1) {
      activeEnvs.delete(tid);
    } else {
      entry[1]--;
    }
  };

  function tryGetCachedEnv (threadId) {
    const entry = activeEnvs.get(threadId);
    if (entry === undefined) {
      return null;
    }
    return entry[0];
  }

  initialize.call(this);
}

VM.dispose = function (vm) {
  if (attachedThreads.get(jsThreadID) === true) {
    attachedThreads.delete(jsThreadID);
    vm.detachCurrentThread();
  }
};

✄
/* jshint esnext: true, evil: true */

import {getApi, defaultInvocationOptions} from './lib/api.js';
import * as fastpaths from './lib/fastpaths.js';

function Runtime() {
    const pointerSize = Process.pointerSize;
    let api = null;
    let apiError = null;
    const realizedClasses = new Set();
    const classRegistry = new ClassRegistry();
    const protocolRegistry = new ProtocolRegistry();
    const replacedMethods = new Map();
    const scheduledWork = new Map();
    let nextId = 1;
    let workCallback = null;
    let NSAutoreleasePool = null;
    const bindings = new Map();
    let readObjectIsa = null;
    const msgSendBySignatureId = new Map();
    const msgSendSuperBySignatureId = new Map();
    let cachedNSString = null;
    let cachedNSStringCtor = null;
    let cachedNSNumber = null;
    let cachedNSNumberCtor = null;
    let singularTypeById = null;
    let modifiers = null;

    try {
        tryInitialize();
    } catch (e) {
    }

    function tryInitialize() {
        if (api !== null)
            return true;

        if (apiError !== null)
            throw apiError;

        try {
            api = getApi();
        } catch (e) {
            apiError = e;
            throw e;
        }

        return api !== null;
    }

    function dispose() {
        for (const [rawMethodHandle, impls] of replacedMethods.entries()) {
            const methodHandle = ptr(rawMethodHandle);
            const [oldImp, newImp] = impls;
            if (api.method_getImplementation(methodHandle).equals(newImp))
                api.method_setImplementation(methodHandle, oldImp);
        }
        replacedMethods.clear();
    }

    Script.bindWeak(this, dispose);

    Object.defineProperty(this, 'available', {
        enumerable: true,
        get() {
            return tryInitialize();
        }
    });

    Object.defineProperty(this, 'api', {
        enumerable: true,
        get() {
          return getApi();
        }
    });

    Object.defineProperty(this, 'classes', {
        enumerable: true,
        value: classRegistry
    });

    Object.defineProperty(this, 'protocols', {
        enumerable: true,
        value: protocolRegistry
    });

    Object.defineProperty(this, 'Object', {
        enumerable: true,
        value: ObjCObject
    });

    Object.defineProperty(this, 'Protocol', {
        enumerable: true,
        value: ObjCProtocol
    });

    Object.defineProperty(this, 'Block', {
        enumerable: true,
        value: Block
    });

    Object.defineProperty(this, 'mainQueue', {
        enumerable: true,
        get() {
            return api?._dispatch_main_q ?? null;
        }
    });

    Object.defineProperty(this, 'registerProxy', {
        enumerable: true,
        value: registerProxy
    });

    Object.defineProperty(this, 'registerClass', {
        enumerable: true,
        value: registerClass
    });

    Object.defineProperty(this, 'registerProtocol', {
        enumerable: true,
        value: registerProtocol
    });

    Object.defineProperty(this, 'bind', {
        enumerable: true,
        value: bind
    });

    Object.defineProperty(this, 'unbind', {
        enumerable: true,
        value: unbind
    });

    Object.defineProperty(this, 'getBoundData', {
        enumerable: true,
        value: getBoundData
    });

    Object.defineProperty(this, 'enumerateLoadedClasses', {
        enumerable: true,
        value: enumerateLoadedClasses
    });

    Object.defineProperty(this, 'enumerateLoadedClassesSync', {
        enumerable: true,
        value: enumerateLoadedClassesSync
    });

    Object.defineProperty(this, 'choose', {
        enumerable: true,
        value: choose
    });

    Object.defineProperty(this, 'chooseSync', {
        enumerable: true,
        value(specifier) {
            const instances = [];
            choose(specifier, {
                onMatch(i) {
                    instances.push(i);
                },
                onComplete() {
                }
            });
            return instances;
        }
    });

    this.schedule = function (queue, work) {
        const id = ptr(nextId++);
        scheduledWork.set(id.toString(), work);

        if (workCallback === null) {
            workCallback = new NativeCallback(performScheduledWorkItem, 'void', ['pointer']);
        }

        Script.pin();
        api.dispatch_async_f(queue, id, workCallback);
    };

    function performScheduledWorkItem(rawId) {
        const id = rawId.toString();
        const work = scheduledWork.get(id);
        scheduledWork.delete(id);

        if (NSAutoreleasePool === null)
            NSAutoreleasePool = classRegistry.NSAutoreleasePool;

        const pool = NSAutoreleasePool.alloc().init();
        let pendingException = null;
        try {
            work();
        } catch (e) {
            pendingException = e;
        }
        pool.release();

        setImmediate(performScheduledWorkCleanup, pendingException);
    }

    function performScheduledWorkCleanup(pendingException) {
        Script.unpin();

        if (pendingException !== null) {
            throw pendingException;
        }
    }

    this.implement = function (method, fn) {
        return new NativeCallback(fn, method.returnType, method.argumentTypes);
    };

    this.selector = selector;

    this.selectorAsString = selectorAsString;

    function selector(name) {
        return api.sel_registerName(Memory.allocUtf8String(name));
    }

    function selectorAsString(sel) {
        return api.sel_getName(sel).readCString();
    }

    const registryBuiltins = new Set([
        "prototype",
        "constructor",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf"
    ]);

    function ClassRegistry() {
        const cachedClasses = new Map();
        let numCachedClasses = 0;

        const registry = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        const klass = findClass(property);
                        return (klass !== null) ? klass : undefined;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                if (api === null)
                    return [];
                let numClasses = api.objc_getClassList(NULL, 0);
                if (numClasses !== numCachedClasses) {
                    // It's impossible to unregister classes in ObjC, so if the number of
                    // classes hasn't changed, we can assume that the list is up to date.
                    const bufferSize = numClasses;
                    const classHandles = Memory.alloc(bufferSize * pointerSize);
                    numClasses = api.objc_getClassList(classHandles, bufferSize);
                    if (numClasses > bufferSize)
                        numClasses = bufferSize;
                    for (let i = 0; i !== numClasses; i++) {
                        const handle = classHandles.add(i * pointerSize).readPointer();
                        const name = api.class_getName(handle).readCString();
                        cachedClasses.set(name, handle);
                    }
                    numCachedClasses = numClasses;
                }
                return Array.from(cachedClasses.keys());
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        function hasProperty(name) {
            if (registryBuiltins.has(name))
                return true;
            return findClass(name) !== null;
        }

        function getClass(name) {
            const cls = findClass(name);
            if (cls === null)
                throw new Error("Unable to find class '" + name + "'");
            return cls;
        }

        function findClass(name) {
            let handle = cachedClasses.get(name);
            if (handle === undefined) {
                handle = api.objc_lookUpClass(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                cachedClasses.set(name, handle);
                numCachedClasses++;
            }

            return new ObjCObject(handle, undefined, true);
        }

        function toJSON() {
            return Object.keys(registry).reduce(function (r, name) {
                r[name] = getClass(name).toJSON();
                return r;
            }, {});
        }

        function toString() {
            return "ClassRegistry";
        }

        function valueOf() {
            return "ClassRegistry";
        }

        return registry;
    }

    function ProtocolRegistry() {
        const cachedProtocols = new Map();
        let numCachedProtocols = 0;

        const registry = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        const proto = findProtocol(property);
                        return (proto !== null) ? proto : undefined;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                if (api === null)
                    return [];
                const numProtocolsBuf = Memory.alloc(pointerSize);
                const protocolHandles = api.objc_copyProtocolList(numProtocolsBuf);
                try {
                    const numProtocols = numProtocolsBuf.readUInt();
                    if (numProtocols !== numCachedProtocols) {
                        cachedProtocols.clear();
                        for (let i = 0; i !== numProtocols; i++) {
                            const handle = protocolHandles.add(i * pointerSize).readPointer();
                            const name = api.protocol_getName(handle).readCString();

                            cachedProtocols.set(name, handle);
                        }
                        numCachedProtocols = numProtocols;
                    }
                } finally {
                    api.free(protocolHandles);
                }
                return Array.from(cachedProtocols.keys());
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        function hasProperty(name) {
            if (registryBuiltins.has(name))
                return true;
            return findProtocol(name) !== null;
        }

        function findProtocol(name) {
            let handle = cachedProtocols.get(name);
            if (handle === undefined) {
                handle = api.objc_getProtocol(Memory.allocUtf8String(name));
                if (handle.isNull())
                    return null;
                cachedProtocols.set(name, handle);
                numCachedProtocols++;
            }

            return new ObjCProtocol(handle);
        }

        function toJSON() {
            return Object.keys(registry).reduce(function (r, name) {
                r[name] = { handle: cachedProtocols.get(name) };
                return r;
            }, {});
        }

        function toString() {
            return "ProtocolRegistry";
        }

        function valueOf() {
            return "ProtocolRegistry";
        }

        return registry;
    }

    const objCObjectBuiltins = new Set([
        "prototype",
        "constructor",
        "handle",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf",
        "equals",
        "$kind",
        "$super",
        "$superClass",
        "$class",
        "$className",
        "$moduleName",
        "$protocols",
        "$methods",
        "$ownMethods",
        "$ivars"
    ]);

    function ObjCObject(handle, protocol, cachedIsClass, superSpecifier) {
        let cachedClassHandle = null;
        let cachedKind = null;
        let cachedSuper = null;
        let cachedSuperClass = null;
        let cachedClass = null;
        let cachedClassName = null;
        let cachedModuleName = null;
        let cachedProtocols = null;
        let cachedMethodNames = null;
        let cachedProtocolMethods = null;
        let respondsToSelector = null;
        const cachedMethods = new Map();
        let cachedNativeMethodNames = null;
        let cachedOwnMethodNames = null;
        let cachedIvars = null;

        handle = getHandle(handle);

        if (cachedIsClass === undefined) {
            // We need to ensure the class is realized, otherwise calling APIs like object_isClass() will crash.
            // The first message delivery will realize the class, but users intercepting calls to objc_msgSend()
            // and inspecting the first argument will run into this situation.
            const klass = api.object_getClass(handle);
            const key = klass.toString();
            if (!realizedClasses.has(key)) {
                api.objc_lookUpClass(api.class_getName(klass));
                realizedClasses.add(key);
            }
        }

        const self = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "handle":
                        return handle;
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                    case "valueOf":
                        const descriptionImpl = receiver.description;
                        if (descriptionImpl !== undefined) {
                            const description = descriptionImpl.call(receiver);
                            if (description !== null)
                                return description.UTF8String.bind(description);
                        }
                        return function () {
                            return receiver.$className;
                        };
                    case "equals":
                        return equals;
                    case "$kind":
                        if (cachedKind === null) {
                            if (isClass())
                                cachedKind = api.class_isMetaClass(handle) ? 'meta-class' : 'class';
                            else
                                cachedKind = 'instance';
                        }
                        return cachedKind;
                    case "$super":
                        if (cachedSuper === null) {
                            const superHandle = api.class_getSuperclass(classHandle());
                            if (!superHandle.isNull()) {
                                const specifier = Memory.alloc(2 * pointerSize);
                                specifier.writePointer(handle);
                                specifier.add(pointerSize).writePointer(superHandle);
                                cachedSuper = [new ObjCObject(handle, undefined, cachedIsClass, specifier)];
                            } else {
                                cachedSuper = [null];
                            }
                        }
                        return cachedSuper[0];
                    case "$superClass":
                        if (cachedSuperClass === null) {
                            const superClassHandle = api.class_getSuperclass(classHandle());
                            if (!superClassHandle.isNull()) {
                                cachedSuperClass = [new ObjCObject(superClassHandle)];
                            } else {
                                cachedSuperClass = [null];
                            }
                        }
                        return cachedSuperClass[0];
                    case "$class":
                        if (cachedClass === null)
                            cachedClass = new ObjCObject(api.object_getClass(handle), undefined, true);
                        return cachedClass;
                    case "$className":
                        if (cachedClassName === null) {
                            if (superSpecifier)
                                cachedClassName = api.class_getName(superSpecifier.add(pointerSize).readPointer()).readCString();
                            else if (isClass())
                                cachedClassName = api.class_getName(handle).readCString();
                            else
                                cachedClassName = api.object_getClassName(handle).readCString();
                        }
                        return cachedClassName;
                    case "$moduleName":
                        if (cachedModuleName === null) {
                            cachedModuleName = api.class_getImageName(classHandle()).readCString();
                        }
                        return cachedModuleName;
                    case "$protocols":
                        if (cachedProtocols === null) {
                            cachedProtocols = {};
                            const numProtocolsBuf = Memory.alloc(pointerSize);
                            const protocolHandles = api.class_copyProtocolList(classHandle(), numProtocolsBuf);
                            if (!protocolHandles.isNull()) {
                                try {
                                    const numProtocols = numProtocolsBuf.readUInt();
                                    for (let i = 0; i !== numProtocols; i++) {
                                        const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                                        const p = new ObjCProtocol(protocolHandle);
                                        cachedProtocols[p.name] = p;
                                    }
                                } finally {
                                    api.free(protocolHandles);
                                }
                            }
                        }
                        return cachedProtocols;
                    case "$methods":
                        if (cachedNativeMethodNames === null) {
                            const klass = superSpecifier ? superSpecifier.add(pointerSize).readPointer() : classHandle();
                            const meta = api.object_getClass(klass);

                            const names = new Set();

                            let cur = meta;
                            do {
                                for (let methodName of collectMethodNames(cur, "+ "))
                                    names.add(methodName);
                                cur = api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cur = klass;
                            do {
                                for (let methodName of collectMethodNames(cur, "- "))
                                    names.add(methodName);
                                cur = api.class_getSuperclass(cur);
                            } while (!cur.isNull());

                            cachedNativeMethodNames = Array.from(names);
                        }
                        return cachedNativeMethodNames;
                    case "$ownMethods":
                        if (cachedOwnMethodNames === null) {
                            const klass = superSpecifier ? superSpecifier.add(pointerSize).readPointer() : classHandle();
                            const meta = api.object_getClass(klass);

                            const classMethods = collectMethodNames(meta, "+ ");
                            const instanceMethods = collectMethodNames(klass, "- ");

                            cachedOwnMethodNames = classMethods.concat(instanceMethods);
                        }
                        return cachedOwnMethodNames;
                    case "$ivars":
                        if (cachedIvars === null) {
                            if (isClass())
                                cachedIvars = {};
                            else
                                cachedIvars = new ObjCIvars(self, classHandle());
                        }
                        return cachedIvars;
                    default:
                        if (typeof property === "symbol") {
                            return target[property];
                        }
                        if (protocol) {
                            const details = findProtocolMethod(property);
                            if (details === null || !details.implemented)
                                return undefined;
                        }
                        const wrapper = findMethodWrapper(property);
                        if (wrapper === null)
                            return undefined;
                        return wrapper;
                }
            },
            set(target, property, value, receiver) {
                return false;
            },
            ownKeys(target) {
                if (cachedMethodNames === null) {
                    if (!protocol) {
                        const jsNames = {};
                        const nativeNames = {};

                        let cur = api.object_getClass(handle);
                        do {
                            const numMethodsBuf = Memory.alloc(pointerSize);
                            const methodHandles = api.class_copyMethodList(cur, numMethodsBuf);
                            const fullNamePrefix = isClass() ? "+ " : "- ";
                            try {
                                const numMethods = numMethodsBuf.readUInt();
                                for (let i = 0; i !== numMethods; i++) {
                                    const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                                    const sel = api.method_getName(methodHandle);
                                    const nativeName = api.sel_getName(sel).readCString();
                                    if (nativeNames[nativeName] !== undefined)
                                        continue;
                                    nativeNames[nativeName] = nativeName;

                                    const jsName = jsMethodName(nativeName);
                                    let serial = 2;
                                    let name = jsName;
                                    while (jsNames[name] !== undefined) {
                                        serial++;
                                        name = jsName + serial;
                                    }
                                    jsNames[name] = true;

                                    const fullName = fullNamePrefix + nativeName;
                                    if (!cachedMethods.has(fullName)) {
                                        const details = {
                                            sel: sel,
                                            handle: methodHandle,
                                            wrapper: null
                                        };
                                        cachedMethods.set(fullName, details);
                                        cachedMethods.set(name, details);
                                    }
                                }
                            } finally {
                                api.free(methodHandles);
                            }
                            cur = api.class_getSuperclass(cur);
                        } while (!cur.isNull());

                        cachedMethodNames = Object.keys(jsNames);
                    } else {
                        const methodNames = [];

                        const protocolMethods = allProtocolMethods();
                        Object.keys(protocolMethods).forEach(function (methodName) {
                            if (methodName[0] !== '+' && methodName[0] !== '-') {
                                const details = protocolMethods[methodName];
                                if (details.implemented) {
                                    methodNames.push(methodName);
                                }
                            }
                        });

                        cachedMethodNames = methodNames;
                    }
                }

                return ['handle'].concat(cachedMethodNames);
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: false,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        if (protocol) {
            respondsToSelector = !isClass() ? findMethodWrapper("- respondsToSelector:") : null;
        }

        return self;

        function hasProperty(name) {
            if (objCObjectBuiltins.has(name))
                return true;
            if (protocol) {
                const details = findProtocolMethod(name);
                return !!(details !== null && details.implemented);
            }
            return findMethod(name) !== null;
        }

        function classHandle() {
            if (cachedClassHandle === null)
                cachedClassHandle = isClass() ? handle : api.object_getClass(handle);
            return cachedClassHandle;
        }

        function isClass() {
            if (cachedIsClass === undefined) {
                if (api.object_isClass)
                    cachedIsClass = !!api.object_isClass(handle);
                else
                    cachedIsClass = !!api.class_isMetaClass(api.object_getClass(handle));
            }
            return cachedIsClass;
        }

        function findMethod(rawName) {
            let method = cachedMethods.get(rawName);
            if (method !== undefined)
                return method;

            const tokens = parseMethodName(rawName);
            const fullName = tokens[2];

            method = cachedMethods.get(fullName);
            if (method !== undefined) {
                cachedMethods.set(rawName, method);
                return method;
            }

            const kind = tokens[0];
            const name = tokens[1];
            const sel = selector(name);
            const defaultKind = isClass() ? '+' : '-';

            if (protocol) {
                const details = findProtocolMethod(fullName);
                if (details !== null) {
                    method = {
                        sel: sel,
                        types: details.types,
                        wrapper: null,
                        kind
                    };
                }
            }

            if (method === undefined) {
                const methodHandle = (kind === '+') ?
                    api.class_getClassMethod(classHandle(), sel) :
                    api.class_getInstanceMethod(classHandle(), sel);
                if (!methodHandle.isNull()) {
                    method = {
                        sel: sel,
                        handle: methodHandle,
                        wrapper: null,
                        kind
                    };
                } else {
                    if (isClass() || kind !== '-' || name === "forwardingTargetForSelector:" || name === "methodSignatureForSelector:") {
                        return null;
                    }

                    let target = self;
                    if ("- forwardingTargetForSelector:" in self) {
                        const forwardingTarget = self.forwardingTargetForSelector_(sel);
                        if (forwardingTarget !== null && forwardingTarget.$kind === 'instance') {
                            target = forwardingTarget;
                        } else {
                            return null;
                        }
                    } else {
                        return null;
                    }

                    const methodHandle = api.class_getInstanceMethod(api.object_getClass(target.handle), sel);
                    if (methodHandle.isNull()) {
                        return null;
                    }
                    let types = api.method_getTypeEncoding(methodHandle).readCString();
                    if (types === null || types === "") {
                        types = stealTypesFromProtocols(target, fullName);
                        if (types === null)
                            types = stealTypesFromProtocols(self, fullName);
                        if (types === null)
                            return null;
                    }
                    method = {
                        sel,
                        types,
                        wrapper: null,
                        kind
                    };
                }
            }

            cachedMethods.set(fullName, method);
            cachedMethods.set(rawName, method);
            if (kind === defaultKind)
                cachedMethods.set(jsMethodName(name), method);

            return method;
        }

        function stealTypesFromProtocols(klass, fullName) {
            const candidates = Object.keys(klass.$protocols)
                .map(protocolName => flatProtocolMethods({}, klass.$protocols[protocolName]))
                .reduce((allMethods, methods) => {
                    Object.assign(allMethods, methods);
                    return allMethods;
                }, {});

            const method = candidates[fullName];
            if (method === undefined) {
                return null;
            }
            return method.types;
        }

        function flatProtocolMethods(result, protocol) {
            if (protocol.methods !== undefined) {
                Object.assign(result, protocol.methods);
            }
            if (protocol.protocol !== undefined) {
                flatProtocolMethods(result, protocol.protocol);
            }
            return result;
        }

        function findProtocolMethod(rawName) {
            const protocolMethods = allProtocolMethods();
            const details = protocolMethods[rawName];
            return (details !== undefined) ? details : null;
        }

        function allProtocolMethods() {
            if (cachedProtocolMethods === null) {
                const methods = {};

                const protocols = collectProtocols(protocol);
                const defaultKind = isClass() ? '+' : '-';
                Object.keys(protocols).forEach(function (name) {
                    const p = protocols[name];
                    const m = p.methods;
                    Object.keys(m).forEach(function (fullMethodName) {
                        const method = m[fullMethodName];
                        const methodName = fullMethodName.substr(2);
                        const kind = fullMethodName[0];

                        let didCheckImplemented = false;
                        let implemented = false;
                        const details = {
                            types: method.types
                        };
                        Object.defineProperty(details, 'implemented', {
                            get() {
                                if (!didCheckImplemented) {
                                    if (method.required) {
                                        implemented = true;
                                    } else {
                                        implemented = (respondsToSelector !== null && respondsToSelector.call(self, selector(methodName)));
                                    }
                                    didCheckImplemented = true;
                                }
                                return implemented;
                            }
                        });

                        methods[fullMethodName] = details;
                        if (kind === defaultKind)
                            methods[jsMethodName(methodName)] = details;
                    });
                });

                cachedProtocolMethods = methods;
            }

            return cachedProtocolMethods;
        }

        function findMethodWrapper(name) {
            const method = findMethod(name);
            if (method === null)
                return null;
            let wrapper = method.wrapper;
            if (wrapper === null) {
                wrapper = makeMethodInvocationWrapper(method, self, superSpecifier, defaultInvocationOptions);
                method.wrapper = wrapper;
            }
            return wrapper;
        }

        function parseMethodName(rawName) {
            const match = /([+\-])\s(\S+)/.exec(rawName);
            let name, kind;
            if (match === null) {
                kind = isClass() ? '+' : '-';
                name = objcMethodName(rawName);
            } else {
                kind = match[1];
                name = match[2];
            }
            const fullName = [kind, name].join(' ');
            return [kind, name, fullName];
        }

        function toJSON() {
            return {
                handle: handle.toString()
            };
        }

        function equals(ptr) {
            return handle.equals(getHandle(ptr));
        }
    }

    function getReplacementMethodImplementation(methodHandle) {
        const existingEntry = replacedMethods.get(methodHandle.toString());
        if (existingEntry === undefined)
            return null;
        const [, newImp] = existingEntry;
        return newImp;
    }

    function replaceMethodImplementation(methodHandle, imp) {
        const key = methodHandle.toString();

        let oldImp;
        const existingEntry = replacedMethods.get(key);
        if (existingEntry !== undefined)
            [oldImp] = existingEntry;
        else
            oldImp = api.method_getImplementation(methodHandle);

        if (!imp.equals(oldImp))
            replacedMethods.set(key, [oldImp, imp]);
        else
            replacedMethods.delete(key);

        api.method_setImplementation(methodHandle, imp);
    }

    function collectMethodNames(klass, prefix) {
        const names = [];

        const numMethodsBuf = Memory.alloc(pointerSize);
        const methodHandles = api.class_copyMethodList(klass, numMethodsBuf);
        try {
            const numMethods = numMethodsBuf.readUInt();
            for (let i = 0; i !== numMethods; i++) {
                const methodHandle = methodHandles.add(i * pointerSize).readPointer();
                const sel = api.method_getName(methodHandle);
                const nativeName = api.sel_getName(sel).readCString();
                names.push(prefix + nativeName);
            }
        } finally {
            api.free(methodHandles);
        }

        return names;
    }

    function ObjCProtocol(handle) {
        let cachedName = null;
        let cachedProtocols = null;
        let cachedProperties = null;
        let cachedMethods = null;

        Object.defineProperty(this, 'handle', {
            value: handle,
            enumerable: true
        });

        Object.defineProperty(this, 'name', {
            get() {
                if (cachedName === null)
                    cachedName = api.protocol_getName(handle).readCString();
                return cachedName;
            },
            enumerable: true
        });

        Object.defineProperty(this, 'protocols', {
            get() {
                if (cachedProtocols === null) {
                    cachedProtocols = {};
                    const numProtocolsBuf = Memory.alloc(pointerSize);
                    const protocolHandles = api.protocol_copyProtocolList(handle, numProtocolsBuf);
                    if (!protocolHandles.isNull()) {
                        try {
                            const numProtocols = numProtocolsBuf.readUInt();
                            for (let i = 0; i !== numProtocols; i++) {
                                const protocolHandle = protocolHandles.add(i * pointerSize).readPointer();
                                const protocol = new ObjCProtocol(protocolHandle);
                                cachedProtocols[protocol.name] = protocol;
                            }
                        } finally {
                            api.free(protocolHandles);
                        }
                    }
                }
                return cachedProtocols;
            },
            enumerable: true
        });

        Object.defineProperty(this, 'properties', {
            get() {
                if (cachedProperties === null) {
                    cachedProperties = {};
                    const numBuf = Memory.alloc(pointerSize);
                    const propertyHandles = api.protocol_copyPropertyList(handle, numBuf);
                    if (!propertyHandles.isNull()) {
                        try {
                            const numProperties = numBuf.readUInt();
                            for (let i = 0; i !== numProperties; i++) {
                                const propertyHandle = propertyHandles.add(i * pointerSize).readPointer();
                                const propName = api.property_getName(propertyHandle).readCString();
                                const attributes = {};
                                const attributeEntries = api.property_copyAttributeList(propertyHandle, numBuf);
                                if (!attributeEntries.isNull()) {
                                    try {
                                        const numAttributeValues = numBuf.readUInt();
                                        for (let j = 0; j !== numAttributeValues; j++) {
                                            const attributeEntry = attributeEntries.add(j * (2 * pointerSize));
                                            const name = attributeEntry.readPointer().readCString();
                                            const value = attributeEntry.add(pointerSize).readPointer().readCString();
                                            attributes[name] = value;
                                        }
                                    } finally {
                                        api.free(attributeEntries);
                                    }
                                }
                                cachedProperties[propName] = attributes;
                            }
                        } finally {
                            api.free(propertyHandles);
                        }
                    }
                }
                return cachedProperties;
            },
            enumerable: true
        });

        Object.defineProperty(this, 'methods', {
            get() {
                if (cachedMethods === null) {
                    cachedMethods = {};
                    const numBuf = Memory.alloc(pointerSize);
                    collectMethods(cachedMethods, numBuf, { required: true, instance: false });
                    collectMethods(cachedMethods, numBuf, { required: false, instance: false });
                    collectMethods(cachedMethods, numBuf, { required: true, instance: true });
                    collectMethods(cachedMethods, numBuf, { required: false, instance: true });
                }
                return cachedMethods;
            },
            enumerable: true
        });

        function collectMethods(methods, numBuf, spec) {
            const methodDescValues = api.protocol_copyMethodDescriptionList(handle, spec.required ? 1 : 0, spec.instance ? 1 : 0, numBuf);
            if (methodDescValues.isNull())
                return;
            try {
                const numMethodDescValues = numBuf.readUInt();
                for (let i = 0; i !== numMethodDescValues; i++) {
                    const methodDesc = methodDescValues.add(i * (2 * pointerSize));
                    const name = (spec.instance ? '- ' : '+ ') + selectorAsString(methodDesc.readPointer());
                    const types = methodDesc.add(pointerSize).readPointer().readCString();
                    methods[name] = {
                        required: spec.required,
                        types: types
                    };
                }
            } finally {
                api.free(methodDescValues);
            }
        }
    }

    const objCIvarsBuiltins = new Set([
        "prototype",
        "constructor",
        "hasOwnProperty",
        "toJSON",
        "toString",
        "valueOf"
    ]);

    function ObjCIvars(instance, classHandle) {
        const ivars = {};
        let cachedIvarNames = null;

        let classHandles = [];

        let currentClassHandle = classHandle;
        do {
            classHandles.unshift(currentClassHandle);
            currentClassHandle = api.class_getSuperclass(currentClassHandle);
        } while (!currentClassHandle.isNull());

        const numIvarsBuf = Memory.alloc(pointerSize);
        classHandles.forEach(c => {
            const ivarHandles = api.class_copyIvarList(c, numIvarsBuf);
            try {
                const numIvars = numIvarsBuf.readUInt();
                for (let i = 0; i !== numIvars; i++) {
                    const handle = ivarHandles.add(i * pointerSize).readPointer();
                    const name = api.ivar_getName(handle).readCString();
                    ivars[name] = [handle, null];
                }
            } finally {
                api.free(ivarHandles);
            }
        });

        const self = new Proxy(this, {
            has(target, property) {
                return hasProperty(property);
            },
            get(target, property, receiver) {
                switch (property) {
                    case "prototype":
                        return target.prototype;
                    case "constructor":
                        return target.constructor;
                    case "hasOwnProperty":
                        return hasProperty;
                    case "toJSON":
                        return toJSON;
                    case "toString":
                        return toString;
                    case "valueOf":
                        return valueOf;
                    default:
                        const ivar = findIvar(property);
                        if (ivar === null)
                            return undefined;
                        return ivar.get();
                }
            },
            set(target, property, value, receiver) {
                const ivar = findIvar(property);
                if (ivar === null)
                    throw new Error("Unknown ivar");
                ivar.set(value);
                return true;
            },
            ownKeys(target) {
                if (cachedIvarNames === null)
                    cachedIvarNames = Object.keys(ivars);
                return cachedIvarNames;
            },
            getOwnPropertyDescriptor(target, property) {
                return {
                    writable: true,
                    configurable: true,
                    enumerable: true
                };
            },
        });

        return self;

        function findIvar(name) {
            const entry = ivars[name];
            if (entry === undefined)
                return null;
            let impl = entry[1];
            if (impl === null) {
                const ivar = entry[0];

                const offset = api.ivar_getOffset(ivar).toInt32();
                const address = instance.handle.add(offset);

                const type = parseType(api.ivar_getTypeEncoding(ivar).readCString());
                const fromNative = type.fromNative || identityTransform;
                const toNative = type.toNative || identityTransform;

                let read, write;
                if (name === 'isa') {
                    read = readObjectIsa;
                    write = function () {
                        throw new Error('Unable to set the isa instance variable');
                    };
                } else {
                    read = type.read;
                    write = type.write;
                }

                impl = {
                    get() {
                        return fromNative.call(instance, read(address));
                    },
                    set(value) {
                        write(address, toNative.call(instance, value));
                    }
                };
                entry[1] = impl;
            }
            return impl;
        }

        function hasProperty(name) {
            if (objCIvarsBuiltins.has(name))
                return true;
            return ivars.hasOwnProperty(name);
        }

        function toJSON() {
            return Object.keys(self).reduce(function (result, name) {
                result[name] = self[name];
                return result;
            }, {});
        }

        function toString() {
            return "ObjCIvars";
        }

        function valueOf() {
            return "ObjCIvars";
        }
    }

    let blockDescriptorAllocSize, blockDescriptorDeclaredSize, blockDescriptorOffsets;
    let blockSize, blockOffsets;
    if (pointerSize === 4) {
        blockDescriptorAllocSize = 16; /* sizeof (BlockDescriptor) == 12 */
        blockDescriptorDeclaredSize = 20;
        blockDescriptorOffsets = {
            reserved: 0,
            size: 4,
            rest: 8
        };

        blockSize = 20;
        blockOffsets = {
            isa: 0,
            flags: 4,
            reserved: 8,
            invoke: 12,
            descriptor: 16
        };
    } else {
        blockDescriptorAllocSize = 32; /* sizeof (BlockDescriptor) == 24 */
        blockDescriptorDeclaredSize = 32;
        blockDescriptorOffsets = {
            reserved: 0,
            size: 8,
            rest: 16
        };

        blockSize = 32;
        blockOffsets = {
            isa: 0,
            flags: 8,
            reserved: 12,
            invoke: 16,
            descriptor: 24
        };
    }

    const BLOCK_HAS_COPY_DISPOSE = (1 << 25);
    const BLOCK_HAS_CTOR =         (1 << 26);
    const BLOCK_IS_GLOBAL =        (1 << 28);
    const BLOCK_HAS_STRET =        (1 << 29);
    const BLOCK_HAS_SIGNATURE =    (1 << 30);

    function Block(target, options = defaultInvocationOptions) {
        this._options = options;

        if (target instanceof NativePointer) {
            const descriptor = target.add(blockOffsets.descriptor).readPointer();

            this.handle = target;

            const flags = target.add(blockOffsets.flags).readU32();
            if ((flags & BLOCK_HAS_SIGNATURE) !== 0) {
                const signatureOffset = ((flags & BLOCK_HAS_COPY_DISPOSE) !== 0) ? 2 : 0;
                this.types = descriptor.add(blockDescriptorOffsets.rest + (signatureOffset * pointerSize)).readPointer().readCString();
                this._signature = parseSignature(this.types);
            } else {
                this._signature = null;
            }
        } else {
            this.declare(target);

            const descriptor = Memory.alloc(blockDescriptorAllocSize + blockSize);
            const block = descriptor.add(blockDescriptorAllocSize);
            const typesStr = Memory.allocUtf8String(this.types);

            descriptor.add(blockDescriptorOffsets.reserved).writeULong(0);
            descriptor.add(blockDescriptorOffsets.size).writeULong(blockDescriptorDeclaredSize);
            descriptor.add(blockDescriptorOffsets.rest).writePointer(typesStr);

            block.add(blockOffsets.isa).writePointer(classRegistry.__NSGlobalBlock__);
            block.add(blockOffsets.flags).writeU32(BLOCK_HAS_SIGNATURE | BLOCK_IS_GLOBAL);
            block.add(blockOffsets.reserved).writeU32(0);
            block.add(blockOffsets.descriptor).writePointer(descriptor);

            this.handle = block;

            this._storage = [descriptor, typesStr];

            this.implementation = target.implementation;
        }
    }

    Object.defineProperties(Block.prototype, {
      implementation: {
        enumerable: true,
        get() {
            const address = this.handle.add(blockOffsets.invoke).readPointer().strip();
            const signature = this._getSignature();
            return makeBlockInvocationWrapper(this, signature, new NativeFunction(
                address.sign(),
                signature.retType.type,
                signature.argTypes.map(function (arg) { return arg.type; }),
                this._options));
        },
        set(func) {
            const signature = this._getSignature();
            const callback = new NativeCallback(
                makeBlockImplementationWrapper(this, signature, func),
                signature.retType.type,
                signature.argTypes.map(function (arg) { return arg.type; }));
            this._callback = callback;
            const location = this.handle.add(blockOffsets.invoke);
            const prot = Memory.queryProtection(location);
            const writable = prot.includes('w');
            if (!writable)
                Memory.protect(location, Process.pointerSize, 'rw-');
            location.writePointer(callback.strip().sign('ia', location));
            if (!writable)
                Memory.protect(location, Process.pointerSize, prot);
        }
      },
      declare: {
        value(signature) {
            let types = signature.types;
            if (types === undefined) {
                types = unparseSignature(signature.retType, ['block'].concat(signature.argTypes));
            }
            this.types = types;
            this._signature = parseSignature(types);
        }
      },
      _getSignature: {
        value() {
            const signature = this._signature;
            if (signature === null)
                throw new Error('block is missing signature; call declare()');
            return signature;
        }
      }
    });

    function collectProtocols(p, acc) {
        acc = acc || {};

        acc[p.name] = p;

        const parentProtocols = p.protocols;
        Object.keys(parentProtocols).forEach(function (name) {
            collectProtocols(parentProtocols[name], acc);
        });

        return acc;
    }

    function registerProxy(properties) {
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};
        const events = properties.events || {};
        const supportedSelectors = new Set(
            Object.keys(methods)
                .filter(m => /([+\-])\s(\S+)/.exec(m) !== null)
                .map(m => m.split(' ')[1])
        );

        const proxyMethods = {
            '- dealloc': function () {
                const target = this.data.target;
                if ('- release' in target)
                    target.release();
                unbind(this.self);
                this.super.dealloc();

                const callback = this.data.events.dealloc;
                if (callback !== undefined)
                    callback.call(this);
            },
            '- respondsToSelector:': function (sel) {
                const selector = selectorAsString(sel);
                if (supportedSelectors.has(selector))
                    return true;

                return this.data.target.respondsToSelector_(sel);
            },
            '- forwardingTargetForSelector:': function (sel) {
                const callback = this.data.events.forward;
                if (callback !== undefined)
                    callback.call(this, selectorAsString(sel));
                return this.data.target;
            },
            '- methodSignatureForSelector:': function (sel) {
                return this.data.target.methodSignatureForSelector_(sel);
            },
            '- forwardInvocation:': function (invocation) {
                invocation.invokeWithTarget_(this.data.target);
            }
        };
        for (var key in methods) {
            if (methods.hasOwnProperty(key)) {
                if (proxyMethods.hasOwnProperty(key))
                    throw new Error("The '" + key + "' method is reserved");
                proxyMethods[key] = methods[key];
            }
        }

        const ProxyClass = registerClass({
            name: properties.name,
            super: classRegistry.NSProxy,
            protocols: protocols,
            methods: proxyMethods
        });

        return function (target, data) {
            target = (target instanceof NativePointer) ? new ObjCObject(target) : target;
            data = data || {};

            const instance = ProxyClass.alloc().autorelease();

            const boundData = getBoundData(instance);
            boundData.target = ('- retain' in target) ? target.retain() : target;
            boundData.events = events;
            for (var key in data) {
                if (data.hasOwnProperty(key)) {
                    if (boundData.hasOwnProperty(key))
                        throw new Error("The '" + key + "' property is reserved");
                    boundData[key] = data[key];
                }
            }

            this.handle = instance.handle;
        };
    }

    function registerClass(properties) {
        let name = properties.name;
        if (name === undefined)
            name = makeClassName();
        const superClass = (properties.super !== undefined) ? properties.super : classRegistry.NSObject;
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};
        const methodCallbacks = [];

        const classHandle = api.objc_allocateClassPair(superClass !== null ? superClass.handle : NULL, Memory.allocUtf8String(name), ptr("0"));
        if (classHandle.isNull())
            throw new Error("Unable to register already registered class '" + name + "'");
        const metaClassHandle = api.object_getClass(classHandle);
        try {
            protocols.forEach(function (protocol) {
                api.class_addProtocol(classHandle, protocol.handle);
            });

            Object.keys(methods).forEach(function (rawMethodName) {
                const match = /([+\-])\s(\S+)/.exec(rawMethodName);
                if (match === null)
                    throw new Error("Invalid method name");
                const kind = match[1];
                const name = match[2];

                let method;
                const value = methods[rawMethodName];
                if (typeof value === 'function') {
                    let types = null;
                    if (rawMethodName in superClass) {
                        types = superClass[rawMethodName].types;
                    } else {
                        for (let protocol of protocols) {
                            const method = protocol.methods[rawMethodName];
                            if (method !== undefined) {
                                types = method.types;
                                break;
                            }
                        }
                    }
                    if (types === null)
                        throw new Error("Unable to find '" + rawMethodName + "' in super-class or any of its protocols");
                    method = {
                        types: types,
                        implementation: value
                    };
                } else {
                    method = value;
                }

                const target = (kind === '+') ? metaClassHandle : classHandle;
                let types = method.types;
                if (types === undefined) {
                    types = unparseSignature(method.retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(method.argTypes));
                }
                const signature = parseSignature(types);
                const implementation = new NativeCallback(
                    makeMethodImplementationWrapper(signature, method.implementation),
                    signature.retType.type,
                    signature.argTypes.map(function (arg) { return arg.type; }));
                methodCallbacks.push(implementation);
                api.class_addMethod(target, selector(name), implementation, Memory.allocUtf8String(types));
            });
        } catch (e) {
            api.objc_disposeClassPair(classHandle);
            throw e;
        }
        api.objc_registerClassPair(classHandle);

        // Keep a reference to the callbacks so they don't get GCed
        classHandle._methodCallbacks = methodCallbacks;

        Script.bindWeak(classHandle, makeClassDestructor(ptr(classHandle)));

        return new ObjCObject(classHandle);
    }

    function makeClassDestructor(classHandle) {
        return function () {
            api.objc_disposeClassPair(classHandle);
        };
    }

    function registerProtocol(properties) {
        let name = properties.name;
        if (name === undefined)
            name = makeProtocolName();
        const protocols = properties.protocols || [];
        const methods = properties.methods || {};

        protocols.forEach(function (protocol) {
            if (!(protocol instanceof ObjCProtocol))
                throw new Error("Expected protocol");
        });

        const methodSpecs = Object.keys(methods).map(function (rawMethodName) {
            const method = methods[rawMethodName];

            const match = /([+\-])\s(\S+)/.exec(rawMethodName);
            if (match === null)
                throw new Error("Invalid method name");
            const kind = match[1];
            const name = match[2];

            let types = method.types;
            if (types === undefined) {
                types = unparseSignature(method.retType, [(kind === '+') ? 'class' : 'object', 'selector'].concat(method.argTypes));
            }

            return {
                kind: kind,
                name: name,
                types: types,
                optional: method.optional
            };
        });

        const handle = api.objc_allocateProtocol(Memory.allocUtf8String(name));
        if (handle.isNull())
            throw new Error("Unable to register already registered protocol '" + name + "'");

        protocols.forEach(function (protocol) {
            api.protocol_addProtocol(handle, protocol.handle);
        });

        methodSpecs.forEach(function (spec) {
            const isRequiredMethod = spec.optional ? 0 : 1;
            const isInstanceMethod = (spec.kind === '-') ? 1 : 0;
            api.protocol_addMethodDescription(handle, selector(spec.name), Memory.allocUtf8String(spec.types), isRequiredMethod, isInstanceMethod);
        });

        api.objc_registerProtocol(handle);

        return new ObjCProtocol(handle);
    }

    function getHandle(obj) {
        if (obj instanceof NativePointer)
            return obj;
        else if (typeof obj === 'object' && obj.hasOwnProperty('handle'))
            return obj.handle;
        else
            throw new Error("Expected NativePointer or ObjC.Object instance");
    }

    function bind(obj, data) {
        const handle = getHandle(obj);
        const self = (obj instanceof ObjCObject) ? obj : new ObjCObject(handle);
        bindings.set(handle.toString(), {
            self: self,
            super: self.$super,
            data: data
        });
    }

    function unbind(obj) {
        const handle = getHandle(obj);
        bindings.delete(handle.toString());
    }

    function getBoundData(obj) {
        return getBinding(obj).data;
    }

    function getBinding(obj) {
        const handle = getHandle(obj);
        const key = handle.toString();
        let binding = bindings.get(key);
        if (binding === undefined) {
            const self = (obj instanceof ObjCObject) ? obj : new ObjCObject(handle);
            binding = {
                self: self,
                super: self.$super,
                data: {}
            };
            bindings.set(key, binding);
        }
        return binding;
    }

    function enumerateLoadedClasses(...args) {
        const allModules = new ModuleMap();
        let unfiltered = false;

        let callbacks;
        let modules;
        if (args.length === 1) {
            callbacks = args[0];
        } else {
            callbacks = args[1];

            const options = args[0];
            modules = options.ownedBy;
        }
        if (modules === undefined) {
            modules = allModules;
            unfiltered = true;
        }

        const classGetName = api.class_getName;
        const onMatch = callbacks.onMatch.bind(callbacks);
        const swiftNominalTypeDescriptorOffset = ((pointerSize === 8) ? 8 : 11) * pointerSize;

        const numClasses = api.objc_getClassList(NULL, 0);
        const classHandles = Memory.alloc(numClasses * pointerSize);
        api.objc_getClassList(classHandles, numClasses);

        for (let i = 0; i !== numClasses; i++) {
            const classHandle = classHandles.add(i * pointerSize).readPointer();

            const rawName = classGetName(classHandle);
            let name = null;

            let modulePath = modules.findPath(rawName);
            const possiblySwift = (modulePath === null) && (unfiltered || allModules.findPath(rawName) === null);
            if (possiblySwift) {
                name = rawName.readCString();
                const probablySwift = name.indexOf('.') !== -1;
                if (probablySwift) {
                    const nominalTypeDescriptor = classHandle.add(swiftNominalTypeDescriptorOffset).readPointer();
                    modulePath = modules.findPath(nominalTypeDescriptor);
                }
            }

            if (modulePath !== null) {
                if (name === null)
                    name = rawName.readCString();
                onMatch(name, modulePath);
            }
        }

        callbacks.onComplete();
    }

    function enumerateLoadedClassesSync(options = {}) {
        const result = {};
        enumerateLoadedClasses(options, {
            onMatch(name, owner) {
                let group = result[owner];
                if (group === undefined) {
                    group = [];
                    result[owner] = group;
                }
                group.push(name);
            },
            onComplete() {
            }
        });
        return result;
    }

    function choose(specifier, callbacks) {
        let cls = specifier;
        let subclasses = true;
        if (!(specifier instanceof ObjCObject) && typeof specifier === 'object') {
            cls = specifier.class;
            if (specifier.hasOwnProperty('subclasses'))
                subclasses = specifier.subclasses;
        }
        if (!(cls instanceof ObjCObject && (cls.$kind === 'class' || cls.$kind === 'meta-class')))
            throw new Error("Expected an ObjC.Object for a class or meta-class");

        const matches = fastpaths.get()
            .choose(cls, subclasses)
            .map(handle => new ObjCObject(handle));
        for (const match of matches) {
            const result = callbacks.onMatch(match);
            if (result === 'stop')
                break;
        }

        callbacks.onComplete();
    }

    function makeMethodInvocationWrapper(method, owner, superSpecifier, invocationOptions) {
        const sel = method.sel;
        let handle = method.handle;
        let types;
        if (handle === undefined) {
            handle = null;
            types = method.types;
        } else {
            types = api.method_getTypeEncoding(handle).readCString();
        }

        const signature = parseSignature(types);
        const retType = signature.retType;
        const argTypes = signature.argTypes.slice(2);

        const objc_msgSend = superSpecifier
            ? getMsgSendSuperImpl(signature, invocationOptions)
            : getMsgSendImpl(signature, invocationOptions);

        const argVariableNames = argTypes.map(function (t, i) {
            return "a" + (i + 1);
        });
        const callArgs = [
            superSpecifier ? "superSpecifier" : "this",
            "sel"
        ].concat(argTypes.map(function (t, i) {
            if (t.toNative) {
                return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
            }
            return argVariableNames[i];
        }));
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.fromNative) {
            returnCaptureLeft = "return retType.fromNative.call(this, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }

        const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " +
            returnCaptureLeft + "objc_msgSend(" + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; m;");

        Object.defineProperty(m, 'handle', {
            enumerable: true,
            get: getMethodHandle
        });

        m.selector = sel;

        Object.defineProperty(m, 'implementation', {
            enumerable: true,
            get() {
                const h = getMethodHandle();

                const impl = new NativeFunction(api.method_getImplementation(h), m.returnType, m.argumentTypes, invocationOptions);

                const newImp = getReplacementMethodImplementation(h);
                if (newImp !== null)
                    impl._callback = newImp;

                return impl;
            },
            set(imp) {
                replaceMethodImplementation(getMethodHandle(), imp);
            }
        });

        m.returnType = retType.type;

        m.argumentTypes = signature.argTypes.map(t => t.type);

        m.types = types;

        Object.defineProperty(m, 'symbol', {
            enumerable: true,
            get() {
                return `${method.kind}[${owner.$className} ${selectorAsString(sel)}]`;
            }
        });

        m.clone = function (options) {
            return makeMethodInvocationWrapper(method, owner, superSpecifier, options);
        };

        function getMethodHandle() {
            if (handle === null) {
                if (owner.$kind === 'instance') {
                    let cur = owner;
                    do {
                        if ("- forwardingTargetForSelector:" in cur) {
                            const target = cur.forwardingTargetForSelector_(sel);
                            if (target === null)
                                break;
                            if (target.$kind !== 'instance')
                                break;
                            const h = api.class_getInstanceMethod(target.$class.handle, sel);
                            if (!h.isNull())
                                handle = h;
                            else
                                cur = target;
                        } else {
                            break;
                        }
                    } while (handle === null);
                }

                if (handle === null)
                    throw new Error("Unable to find method handle of proxied function");
            }

            return handle;
        }

        return m;
    }

    function makeMethodImplementationWrapper(signature, implementation) {
        const retType = signature.retType;
        const argTypes = signature.argTypes;

        const argVariableNames = argTypes.map(function (t, i) {
            if (i === 0)
                return "handle";
            else if (i === 1)
                return "sel";
            else
                return "a" + (i - 1);
        });
        const callArgs = argTypes.slice(2).map(function (t, i) {
            const argVariableName = argVariableNames[2 + i];
            if (t.fromNative) {
                return "argTypes[" + (2 + i) + "].fromNative.call(self, " + argVariableName + ")";
            }
            return argVariableName;
        });
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.toNative) {
            returnCaptureLeft = "return retType.toNative.call(self, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }

        const m = eval("var m = function (" + argVariableNames.join(", ") + ") { " +
            "var binding = getBinding(handle);" +
            "var self = binding.self;" +
            returnCaptureLeft + "implementation.call(binding" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; m;");

        return m;
    }

    function makeBlockInvocationWrapper(block, signature, implementation) {
        const retType = signature.retType;
        const argTypes = signature.argTypes.slice(1);

        const argVariableNames = argTypes.map(function (t, i) {
            return "a" + (i + 1);
        });
        const callArgs = argTypes.map(function (t, i) {
            if (t.toNative) {
                return "argTypes[" + i + "].toNative.call(this, " + argVariableNames[i] + ")";
            }
            return argVariableNames[i];
        });
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.fromNative) {
            returnCaptureLeft = "return retType.fromNative.call(this, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }
        const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " +
            returnCaptureLeft + "implementation(this" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; f;");

        return f.bind(block);
    }

    function makeBlockImplementationWrapper(block, signature, implementation) {
        const retType = signature.retType;
        const argTypes = signature.argTypes;

        const argVariableNames = argTypes.map(function (t, i) {
            if (i === 0)
                return "handle";
            else
                return "a" + i;
        });
        const callArgs = argTypes.slice(1).map(function (t, i) {
            const argVariableName = argVariableNames[1 + i];
            if (t.fromNative) {
                return "argTypes[" + (1 + i) + "].fromNative.call(this, " + argVariableName + ")";
            }
            return argVariableName;
        });
        let returnCaptureLeft;
        let returnCaptureRight;
        if (retType.type === 'void') {
            returnCaptureLeft = "";
            returnCaptureRight = "";
        } else if (retType.toNative) {
            returnCaptureLeft = "return retType.toNative.call(this, ";
            returnCaptureRight = ")";
        } else {
            returnCaptureLeft = "return ";
            returnCaptureRight = "";
        }

        const f = eval("var f = function (" + argVariableNames.join(", ") + ") { " +
            "if (!this.handle.equals(handle))" +
                "this.handle = handle;" +
            returnCaptureLeft + "implementation.call(block" + (callArgs.length > 0 ? ", " : "") + callArgs.join(", ") + ")" + returnCaptureRight + ";" +
        " }; f;");

        return f.bind(block);
    }

    function rawFridaType(t) {
        return (t === 'object') ? 'pointer' : t;
    }

    function makeClassName() {
        for (let i = 1; true; i++) {
            const name = "FridaAnonymousClass" + i;
            if (!(name in classRegistry)) {
                return name;
            }
        }
    }

    function makeProtocolName() {
        for (let i = 1; true; i++) {
            const name = "FridaAnonymousProtocol" + i;
            if (!(name in protocolRegistry)) {
                return name;
            }
        }
    }

    function objcMethodName(name) {
        return name.replace(/_/g, ":");
    }

    function jsMethodName(name) {
        let result = name.replace(/:/g, "_");
        if (objCObjectBuiltins.has(result))
            result += "2";
        return result;
    }

    const isaMasks = {
        x64: '0x7ffffffffff8',
        arm64: '0xffffffff8'
    };

    const rawMask = isaMasks[Process.arch];
    if (rawMask !== undefined) {
        const mask = ptr(rawMask);
        readObjectIsa = function (p) {
            return p.readPointer().and(mask);
        };
    } else {
        readObjectIsa = function (p) {
            return p.readPointer();
        };
    }

    function getMsgSendImpl(signature, invocationOptions) {
        return resolveMsgSendImpl(msgSendBySignatureId, signature, invocationOptions, false);
    }

    function getMsgSendSuperImpl(signature, invocationOptions) {
        return resolveMsgSendImpl(msgSendSuperBySignatureId, signature, invocationOptions, true);
    }

    function resolveMsgSendImpl(cache, signature, invocationOptions, isSuper) {
        if (invocationOptions !== defaultInvocationOptions)
            return makeMsgSendImpl(signature, invocationOptions, isSuper);

        const {id} = signature;

        let impl = cache.get(id);
        if (impl === undefined) {
            impl = makeMsgSendImpl(signature, invocationOptions, isSuper);
            cache.set(id, impl);
        }

        return impl;
    }

    function makeMsgSendImpl(signature, invocationOptions, isSuper) {
        const retType = signature.retType.type;
        const argTypes = signature.argTypes.map(function (t) { return t.type; });

        const components = ['objc_msgSend'];

        if (isSuper)
            components.push('Super');

        const returnsStruct = retType instanceof Array;
        if (returnsStruct && !typeFitsInRegisters(retType))
            components.push('_stret');
        else if (retType === 'float' || retType === 'double')
            components.push('_fpret');

        const name = components.join('');

        return new NativeFunction(api[name], retType, argTypes, invocationOptions);
    }

    function typeFitsInRegisters(type) {
        if (Process.arch !== 'x64')
            return false;

        const size = sizeOfTypeOnX64(type);

        // It's actually way more complex than this, plus, we ignore alignment.
        // But at least we can assume that no SSE types are involved, as we don't yet support them...
        return size <= 16;
    }

    function sizeOfTypeOnX64(type) {
        if (type instanceof Array)
            return type.reduce((total, field) => total + sizeOfTypeOnX64(field), 0);

        switch (type) {
            case 'bool':
            case 'char':
            case 'uchar':
                return 1;
            case 'int16':
            case 'uint16':
                return 2;
            case 'int':
            case 'int32':
            case 'uint':
            case 'uint32':
            case 'float':
                return 4;
            default:
                return 8;
        }
    }

    function unparseSignature(retType, argTypes) {
        const retTypeId = typeIdFromAlias(retType);
        const argTypeIds = argTypes.map(typeIdFromAlias);

        const argSizes = argTypeIds.map(id => singularTypeById[id].size);
        const frameSize = argSizes.reduce((total, size) => total + size, 0);

        let frameOffset = 0;
        return retTypeId + frameSize + argTypeIds.map((id, i) => {
            const result = id + frameOffset;
            frameOffset += argSizes[i];
            return result;
        }).join("");
    }

    function parseSignature(sig) {
        const cursor = [sig, 0];

        parseQualifiers(cursor);
        const retType = readType(cursor);
        readNumber(cursor);

        const argTypes = [];

        let id = JSON.stringify(retType.type);

        while (dataAvailable(cursor)) {
            parseQualifiers(cursor);
            const argType = readType(cursor);
            readNumber(cursor);
            argTypes.push(argType);

            id += JSON.stringify(argType.type);
        }

        return {
            id: id,
            retType: retType,
            argTypes: argTypes
        };
    }

    function parseType(type) {
        const cursor = [type, 0];

        return readType(cursor);
    }

    function readType(cursor) {
        let id = readChar(cursor);
        if (id === '@') {
            let next = peekChar(cursor);
            if (next === '?') {
                id += next;
                skipChar(cursor);
                if (peekChar(cursor) === '<')
                    skipExtendedBlock(cursor);
            } else if (next === '"') {
                skipChar(cursor);
                readUntil('"', cursor);
            }
        } else if (id === '^') {
            let next = peekChar(cursor);
            if (next === '@') {
                id += next;
                skipChar(cursor);
            }
        }

        const type = singularTypeById[id];
        if (type !== undefined) {
            return type;
        } else if (id === '[') {
            const length = readNumber(cursor);
            const elementType = readType(cursor);
            skipChar(cursor); // ']'
            return arrayType(length, elementType);
        } else if (id === '{') {
            if (!tokenExistsAhead('=', '}', cursor)) {
                readUntil('}', cursor);
                return structType([]);
            }
            readUntil('=', cursor);
            const structFields = [];
            let ch;
            while ((ch = peekChar(cursor)) !== '}') {
                if (ch === '"') {
                    skipChar(cursor);
                    readUntil('"', cursor);
                }
                structFields.push(readType(cursor));
            }
            skipChar(cursor); // '}'
            return structType(structFields);
        } else if (id === '(') {
            readUntil('=', cursor);
            const unionFields = [];
            while (peekChar(cursor) !== ')')
                unionFields.push(readType(cursor));
            skipChar(cursor); // ')'
            return unionType(unionFields);
        } else if (id === 'b') {
            readNumber(cursor);
            return singularTypeById.i;
        } else if (id === '^') {
            readType(cursor);
            return singularTypeById['?'];
        } else if (modifiers.has(id)) {
            return readType(cursor);
        } else {
            throw new Error("Unable to handle type " + id);
        }
    }

    function skipExtendedBlock(cursor) {
        let ch;
        skipChar(cursor); // '<'
        while ((ch = peekChar(cursor)) !== '>') {
            if (peekChar(cursor) === '<') {
                skipExtendedBlock(cursor);
            } else {
                skipChar(cursor);
                if (ch === '"')
                    readUntil('"', cursor);
            }
        }
        skipChar(cursor); // '>'
    }

    function readNumber(cursor) {
        let result = "";
        while (dataAvailable(cursor)) {
            const c = peekChar(cursor);
            const v = c.charCodeAt(0);
            const isDigit = v >= 0x30 && v <= 0x39;
            if (isDigit) {
                result += c;
                skipChar(cursor);
            } else {
                break;
            }
        }
        return parseInt(result);
    }

    function readUntil(token, cursor) {
        const buffer = cursor[0];
        const offset = cursor[1];
        const index = buffer.indexOf(token, offset);
        if (index === -1)
            throw new Error("Expected token '" + token + "' not found");
        const result = buffer.substring(offset, index);
        cursor[1] = index + 1;
        return result;
    }

    function readChar(cursor) {
        return cursor[0][cursor[1]++];
    }

    function peekChar(cursor) {
        return cursor[0][cursor[1]];
    }

    function tokenExistsAhead(token, terminator, cursor) {
        const [buffer, offset] = cursor;

        const tokenIndex = buffer.indexOf(token, offset);
        if (tokenIndex === -1)
            return false;

        const terminatorIndex = buffer.indexOf(terminator, offset);
        if (terminatorIndex === -1)
            throw new Error("Expected to find terminator: " + terminator);

        return tokenIndex < terminatorIndex;
    }

    function skipChar(cursor) {
        cursor[1]++;
    }

    function dataAvailable(cursor) {
        return cursor[1] !== cursor[0].length;
    }

    const qualifierById = {
        'r': 'const',
        'n': 'in',
        'N': 'inout',
        'o': 'out',
        'O': 'bycopy',
        'R': 'byref',
        'V': 'oneway'
    };

    function parseQualifiers(cursor) {
        const qualifiers = [];
        while (true) {
            const q = qualifierById[peekChar(cursor)];
            if (q === undefined)
                break;
            qualifiers.push(q);
            skipChar(cursor);
        }
        return qualifiers;
    }

    const idByAlias = {
        'char': 'c',
        'int': 'i',
        'int16': 's',
        'int32': 'i',
        'int64': 'q',
        'uchar': 'C',
        'uint': 'I',
        'uint16': 'S',
        'uint32': 'I',
        'uint64': 'Q',
        'float': 'f',
        'double': 'd',
        'bool': 'B',
        'void': 'v',
        'string': '*',
        'object': '@',
        'block': '@?',
        'class': '#',
        'selector': ':',
        'pointer': '^v'
    };

    function typeIdFromAlias(alias) {
        if (typeof alias === 'object' && alias !== null)
            return `@"${alias.type}"`;

        const id = idByAlias[alias];
        if (id === undefined)
            throw new Error("No known encoding for type " + alias);
        return id;
    }

    const fromNativeId = function (h) {
        if (h.isNull()) {
            return null;
        } else if (h.toString(16) === this.handle.toString(16)) {
            return this;
        } else {
            return new ObjCObject(h);
        }
    };

    const toNativeId = function (v) {
        if (v === null)
            return NULL;

        const type = typeof v;
        if (type === 'string') {
            if (cachedNSStringCtor === null) {
                cachedNSString = classRegistry.NSString;
                cachedNSStringCtor = cachedNSString.stringWithUTF8String_;
            }
            return cachedNSStringCtor.call(cachedNSString, Memory.allocUtf8String(v));
        } else if (type === 'number') {
            if (cachedNSNumberCtor === null) {
                cachedNSNumber = classRegistry.NSNumber;
                cachedNSNumberCtor = cachedNSNumber.numberWithDouble_;
            }
            return cachedNSNumberCtor.call(cachedNSNumber, v);
        }

        return v;
    };

    const fromNativeBlock = function (h) {
        if (h.isNull()) {
            return null;
        } else if (h.toString(16) === this.handle.toString(16)) {
            return this;
        } else {
            return new Block(h);
        }
    };

    const toNativeBlock = function (v) {
        return (v !== null) ? v : NULL;
    };

    const toNativeObjectArray = function (v) {
        if (v instanceof Array) {
            const length = v.length;
            const array = Memory.alloc(length * pointerSize);
            for (let i = 0; i !== length; i++)
                array.add(i * pointerSize).writePointer(toNativeId(v[i]));
            return array;
        }

        return v;
    };

    function arrayType(length, elementType) {
        return {
            type: 'pointer',
            read(address) {
                const result = [];

                const elementSize = elementType.size;
                for (let index = 0; index !== length; index++) {
                    result.push(elementType.read(address.add(index * elementSize)));
                }

                return result;
            },
            write(address, values) {
                const elementSize = elementType.size;
                values.forEach((value, index) => {
                    elementType.write(address.add(index * elementSize), value);
                });
            }
        };
    }

    function structType(fieldTypes) {
        let fromNative, toNative;

        if (fieldTypes.some(function (t) { return !!t.fromNative; })) {
            const fromTransforms = fieldTypes.map(function (t) {
                if (t.fromNative)
                    return t.fromNative;
                else
                    return identityTransform;
            });
            fromNative = function (v) {
                return v.map(function (e, i) {
                    return fromTransforms[i].call(this, e);
                });
            };
        } else {
            fromNative = identityTransform;
        }

        if (fieldTypes.some(function (t) { return !!t.toNative; })) {
            const toTransforms = fieldTypes.map(function (t) {
                if (t.toNative)
                    return t.toNative;
                else
                    return identityTransform;
            });
            toNative = function (v) {
                return v.map(function (e, i) {
                    return toTransforms[i].call(this, e);
                });
            };
        } else {
            toNative = identityTransform;
        }

        const [totalSize, fieldOffsets] = fieldTypes.reduce(function (result, t) {
            const [previousOffset, offsets] = result;

            const {size} = t;
            const offset = align(previousOffset, size);
            offsets.push(offset);

            return [offset + size, offsets];
        }, [0, []]);

        return {
            type: fieldTypes.map(t => t.type),
            size: totalSize,
            read(address) {
                return fieldTypes.map((type, index) => type.read(address.add(fieldOffsets[index])));
            },
            write(address, values) {
                values.forEach((value, index) => {
                    fieldTypes[index].write(address.add(fieldOffsets[index]), value);
                });
            },
            fromNative: fromNative,
            toNative: toNative
        };
    }

    function unionType(fieldTypes) {
        const largestType = fieldTypes.reduce(function (largest, t) {
            if (t.size > largest.size)
                return t;
            else
                return largest;
        }, fieldTypes[0]);

        let fromNative, toNative;

        if (largestType.fromNative) {
            const fromTransform = largestType.fromNative;
            fromNative = function (v) {
                return fromTransform.call(this, v[0]);
            };
        } else {
            fromNative = function (v) {
                return v[0];
            };
        }

        if (largestType.toNative) {
            const toTransform = largestType.toNative;
            toNative = function (v) {
                return [toTransform.call(this, v)];
            };
        } else {
            toNative = function (v) {
                return [v];
            };
        }

        return {
            type: [largestType.type],
            size: largestType.size,
            read: largestType.read,
            write: largestType.write,
            fromNative: fromNative,
            toNative: toNative
        };
    }

    const longBits = (pointerSize == 8 && Process.platform !== 'windows') ? 64 : 32;

    modifiers = new Set([
      'j', // complex
      'A', // atomic
      'r', // const
      'n', // in
      'N', // inout
      'o', // out
      'O', // by copy
      'R', // by ref
      'V', // one way
      '+'  // GNU register
    ]);

    singularTypeById = {
        'c': {
            type: 'char',
            size: 1,
            read: address => address.readS8(),
            write: (address, value) => { address.writeS8(value); },
            toNative(v) {
                if (typeof v === 'boolean') {
                    return v ? 1 : 0;
                }
                return v;
            }
        },
        'i': {
            type: 'int',
            size: 4,
            read: address => address.readInt(),
            write: (address, value) => { address.writeInt(value); }
        },
        's': {
            type: 'int16',
            size: 2,
            read: address => address.readS16(),
            write: (address, value) => { address.writeS16(value); }
        },
        'l': {
            type: 'int32',
            size: 4,
            read: address => address.readS32(),
            write: (address, value) => { address.writeS32(value); }
        },
        'q': {
            type: 'int64',
            size: 8,
            read: address => address.readS64(),
            write: (address, value) => { address.writeS64(value); }
        },
        'C': {
            type: 'uchar',
            size: 1,
            read: address => address.readU8(),
            write: (address, value) => { address.writeU8(value); }
        },
        'I': {
            type: 'uint',
            size: 4,
            read: address => address.readUInt(),
            write: (address, value) => { address.writeUInt(value); }
        },
        'S': {
            type: 'uint16',
            size: 2,
            read: address => address.readU16(),
            write: (address, value) => { address.writeU16(value); }
        },
        'L': {
            type: 'uint' + longBits,
            size: longBits / 8,
            read: address => address.readULong(),
            write: (address, value) => { address.writeULong(value); }
        },
        'Q': {
            type: 'uint64',
            size: 8,
            read: address => address.readU64(),
            write: (address, value) => { address.writeU64(value); }
        },
        'f': {
            type: 'float',
            size: 4,
            read: address => address.readFloat(),
            write: (address, value) => { address.writeFloat(value); }
        },
        'd': {
            type: 'double',
            size: 8,
            read: address => address.readDouble(),
            write: (address, value) => { address.writeDouble(value); }
        },
        'B': {
            type: 'bool',
            size: 1,
            read: address => address.readU8(),
            write: (address, value) => { address.writeU8(value); },
            fromNative(v) {
                return v ? true : false;
            },
            toNative(v) {
                return v ? 1 : 0;
            }
        },
        'v': {
            type: 'void',
            size: 0
        },
        '*': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative(h) {
                return h.readCString();
            }
        },
        '@': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: fromNativeId,
            toNative: toNativeId
        },
        '@?': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: fromNativeBlock,
            toNative: toNativeBlock
        },
        '^@': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            toNative: toNativeObjectArray
        },
        '^v': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
        },
        '#': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); },
            fromNative: fromNativeId,
            toNative: toNativeId
        },
        ':': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); }
        },
        '?': {
            type: 'pointer',
            size: pointerSize,
            read: address => address.readPointer(),
            write: (address, value) => { address.writePointer(value); }
        }
    };

    function identityTransform(v) {
        return v;
    }

    function align(value, boundary) {
        const remainder = value % boundary;
        return (remainder === 0) ? value : value + (boundary - remainder);
    }
}

const runtime = new Runtime();
export default runtime;

✄
let cachedApi = null;

export const defaultInvocationOptions = {
    exceptions: 'propagate'
};

export function getApi() {
    if (cachedApi !== null) {
        return cachedApi;
    }

    const temporaryApi = {};
    const pending = [
        {
            module: "libsystem_malloc.dylib",
            functions: {
                "free": ['void', ['pointer']]
            }
        }, {
            module: "libobjc.A.dylib",
            functions: {
                "objc_msgSend": function (address) {
                    this.objc_msgSend = address;
                },
                "objc_msgSend_stret": function (address) {
                    this.objc_msgSend_stret = address;
                },
                "objc_msgSend_fpret": function (address) {
                    this.objc_msgSend_fpret = address;
                },
                "objc_msgSendSuper": function (address) {
                    this.objc_msgSendSuper = address;
                },
                "objc_msgSendSuper_stret": function (address) {
                    this.objc_msgSendSuper_stret = address;
                },
                "objc_msgSendSuper_fpret": function (address) {
                    this.objc_msgSendSuper_fpret = address;
                },
                "objc_getClassList": ['int', ['pointer', 'int']],
                "objc_lookUpClass": ['pointer', ['pointer']],
                "objc_allocateClassPair": ['pointer', ['pointer', 'pointer', 'pointer']],
                "objc_disposeClassPair": ['void', ['pointer']],
                "objc_registerClassPair": ['void', ['pointer']],
                "class_isMetaClass": ['bool', ['pointer']],
                "class_getName": ['pointer', ['pointer']],
                "class_getImageName": ['pointer', ['pointer']],
                "class_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                "class_copyMethodList": ['pointer', ['pointer', 'pointer']],
                "class_getClassMethod": ['pointer', ['pointer', 'pointer']],
                "class_getInstanceMethod": ['pointer', ['pointer', 'pointer']],
                "class_getSuperclass": ['pointer', ['pointer']],
                "class_addProtocol": ['bool', ['pointer', 'pointer']],
                "class_addMethod": ['bool', ['pointer', 'pointer', 'pointer', 'pointer']],
                "class_copyIvarList": ['pointer', ['pointer', 'pointer']],
                "objc_getProtocol": ['pointer', ['pointer']],
                "objc_copyProtocolList": ['pointer', ['pointer']],
                "objc_allocateProtocol": ['pointer', ['pointer']],
                "objc_registerProtocol": ['void', ['pointer']],
                "protocol_getName": ['pointer', ['pointer']],
                "protocol_copyMethodDescriptionList": ['pointer', ['pointer', 'bool', 'bool', 'pointer']],
                "protocol_copyPropertyList": ['pointer', ['pointer', 'pointer']],
                "protocol_copyProtocolList": ['pointer', ['pointer', 'pointer']],
                "protocol_addProtocol": ['void', ['pointer', 'pointer']],
                "protocol_addMethodDescription": ['void', ['pointer', 'pointer', 'pointer', 'bool', 'bool']],
                "ivar_getName": ['pointer', ['pointer']],
                "ivar_getTypeEncoding": ['pointer', ['pointer']],
                "ivar_getOffset": ['pointer', ['pointer']],
                "object_isClass": ['bool', ['pointer']],
                "object_getClass": ['pointer', ['pointer']],
                "object_getClassName": ['pointer', ['pointer']],
                "method_getName": ['pointer', ['pointer']],
                "method_getTypeEncoding": ['pointer', ['pointer']],
                "method_getImplementation": ['pointer', ['pointer']],
                "method_setImplementation": ['pointer', ['pointer', 'pointer']],
                "property_getName": ['pointer', ['pointer']],
                "property_copyAttributeList": ['pointer', ['pointer', 'pointer']],
                "sel_getName": ['pointer', ['pointer']],
                "sel_registerName": ['pointer', ['pointer']],
                "class_getInstanceSize": ['pointer', ['pointer']]
            },
            optionals: {
                "objc_msgSend_stret": 'ABI',
                "objc_msgSend_fpret": 'ABI',
                "objc_msgSendSuper_stret": 'ABI',
                "objc_msgSendSuper_fpret": 'ABI',
                "object_isClass": 'iOS8'
            }
        }, {
            module: "libdispatch.dylib",
            functions: {
                "dispatch_async_f": ['void', ['pointer', 'pointer', 'pointer']]
            },
            variables: {
                "_dispatch_main_q": function (address) {
                    this._dispatch_main_q = address;
                }
            }
        }
    ];
    let remaining = 0;
    pending.forEach(function (api) {
        const functions = api.functions || {};
        const variables = api.variables || {};
        const optionals = api.optionals || {};

        remaining += Object.keys(functions).length + Object.keys(variables).length;

        const exportByName = (Process.findModuleByName(api.module)?.enumerateExports() ?? [])
        .reduce(function (result, exp) {
            result[exp.name] = exp;
            return result;
        }, {});

        Object.keys(functions)
        .forEach(function (name) {
            const exp = exportByName[name];
            if (exp !== undefined && exp.type === 'function') {
                const signature = functions[name];
                if (typeof signature === 'function') {
                    signature.call(temporaryApi, exp.address);
                } else {
                    temporaryApi[name] = new NativeFunction(exp.address, signature[0], signature[1], defaultInvocationOptions);
                }
                remaining--;
            } else {
                const optional = optionals[name];
                if (optional)
                    remaining--;
            }
        });

        Object.keys(variables)
        .forEach(function (name) {
            const exp = exportByName[name];
            if (exp !== undefined && exp.type === 'variable') {
                const handler = variables[name];
                handler.call(temporaryApi, exp.address);
                remaining--;
            }
        });
    });
    if (remaining === 0) {
        if (!temporaryApi.objc_msgSend_stret)
            temporaryApi.objc_msgSend_stret = temporaryApi.objc_msgSend;
        if (!temporaryApi.objc_msgSend_fpret)
            temporaryApi.objc_msgSend_fpret = temporaryApi.objc_msgSend;
        if (!temporaryApi.objc_msgSendSuper_stret)
            temporaryApi.objc_msgSendSuper_stret = temporaryApi.objc_msgSendSuper;
        if (!temporaryApi.objc_msgSendSuper_fpret)
            temporaryApi.objc_msgSendSuper_fpret = temporaryApi.objc_msgSendSuper;

        cachedApi = temporaryApi;
    }

    return cachedApi;
}

✄
import {getApi} from './api.js';

const code = `#include <glib.h>
#include <ptrauth.h>

#define KERN_SUCCESS 0
#define MALLOC_PTR_IN_USE_RANGE_TYPE 1
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define OBJC_ISA_MASK 0x7ffffffffff8ULL
#elif defined (HAVE_ARM64)
# define OBJC_ISA_MASK 0xffffffff8ULL
#endif

typedef struct _ChooseContext ChooseContext;

typedef struct _malloc_zone_t malloc_zone_t;
typedef struct _malloc_introspection_t malloc_introspection_t;
typedef struct _vm_range_t vm_range_t;

typedef gpointer Class;
typedef int kern_return_t;
typedef guint mach_port_t;
typedef mach_port_t task_t;
typedef guintptr vm_offset_t;
typedef guintptr vm_size_t;
typedef vm_offset_t vm_address_t;

struct _ChooseContext
{
  GHashTable * classes;
  GArray * matches;
};

struct _malloc_zone_t
{
  void * reserved1;
  void * reserved2;
  size_t (* size) (struct _malloc_zone_t * zone, const void * ptr);
  void * (* malloc) (struct _malloc_zone_t * zone, size_t size);
  void * (* calloc) (struct _malloc_zone_t * zone, size_t num_items, size_t size);
  void * (* valloc) (struct _malloc_zone_t * zone, size_t size);
  void (* free) (struct _malloc_zone_t * zone, void * ptr);
  void * (* realloc) (struct _malloc_zone_t * zone, void * ptr, size_t size);
  void (* destroy) (struct _malloc_zone_t * zone);
  const char * zone_name;

  unsigned (* batch_malloc) (struct _malloc_zone_t * zone, size_t size, void ** results, unsigned num_requested);
  void (* batch_free) (struct _malloc_zone_t * zone, void ** to_be_freed, unsigned num_to_be_freed);

  malloc_introspection_t * introspect;
};

typedef kern_return_t (* memory_reader_t) (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);
typedef void (* vm_range_recorder_t) (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
typedef kern_return_t (* enumerator_func) (task_t task, void * user_data, unsigned type_mask, vm_address_t zone_address, memory_reader_t reader,
      vm_range_recorder_t recorder);

struct _malloc_introspection_t
{
  enumerator_func enumerator;
};

struct _vm_range_t
{
  vm_address_t address;
  vm_size_t size;
};

extern int objc_getClassList (Class * buffer, int buffer_count);
extern Class class_getSuperclass (Class cls);
extern size_t class_getInstanceSize (Class cls);
extern kern_return_t malloc_get_all_zones (task_t task, memory_reader_t reader, vm_address_t ** addresses, unsigned * count);

static void collect_subclasses (Class klass, GHashTable * result);
static void collect_matches_in_ranges (task_t task, void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t read_local_memory (task_t remote_task, vm_address_t remote_address, vm_size_t size, void ** local_memory);

extern mach_port_t selfTask;

gpointer *
choose (Class * klass,
        gboolean consider_subclasses,
        guint * count)
{
  ChooseContext ctx;
  GHashTable * classes;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count, i;

  classes = g_hash_table_new_full (NULL, NULL, NULL, NULL);
  ctx.classes = classes;
  ctx.matches = g_array_new (FALSE, FALSE, sizeof (gpointer));
  if (consider_subclasses)
    collect_subclasses (klass, classes);
  else
    g_hash_table_insert (classes, klass, GSIZE_TO_POINTER (class_getInstanceSize (klass)));

  malloc_zone_count = 0;
  malloc_get_all_zones (selfTask, read_local_memory, &malloc_zone_addresses, &malloc_zone_count);

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;
    enumerator_func enumerator;

    if (zone != NULL && zone->introspect != NULL &&
        (enumerator = (ptrauth_strip (zone->introspect, ptrauth_key_asda))->enumerator) != NULL)
    {
      enumerator = ptrauth_sign_unauthenticated (
          ptrauth_strip (enumerator, ptrauth_key_asia),
          ptrauth_key_asia, 0);

      enumerator (selfTask, &ctx, MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address, read_local_memory,
          collect_matches_in_ranges);
    }
  }

  g_hash_table_unref (classes);

  *count = ctx.matches->len;

  return (gpointer *) g_array_free (ctx.matches, FALSE);
}

void
destroy (gpointer mem)
{
  g_free (mem);
}

static void
collect_subclasses (Class klass,
                    GHashTable * result)
{
  Class * classes;
  int buffer_count, count, i;

  buffer_count = objc_getClassList (NULL, 0);
  classes = g_malloc (buffer_count * sizeof (gpointer));
  count = objc_getClassList (classes, buffer_count);
  if (count > buffer_count)
    count = buffer_count;

  for (i = 0; i != count; i++)
  {
    Class candidate = classes[i];
    Class c;

    c = candidate;
    do
    {
      if (c == klass)
      {
        g_hash_table_insert (result, candidate, GSIZE_TO_POINTER (class_getInstanceSize (candidate)));
        break;
      }

      c = class_getSuperclass (c);
    }
    while (c != NULL);
  }

  g_free (classes);
}

static void
collect_matches_in_ranges (task_t task,
                           void * user_data,
                           unsigned type,
                           vm_range_t * ranges,
                           unsigned count)
{
  ChooseContext * ctx = user_data;
  GHashTable * classes = ctx->classes;
  unsigned i;

  for (i = 0; i != count; i++)
  {
    const vm_range_t * range = &ranges[i];
    gconstpointer candidate = GSIZE_TO_POINTER (range->address);
    gconstpointer isa;
    guint instance_size;

    isa = *(gconstpointer *) candidate;
#ifdef OBJC_ISA_MASK
    isa = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (isa) & OBJC_ISA_MASK);
#endif

    instance_size = GPOINTER_TO_UINT (g_hash_table_lookup (classes, isa));
    if (instance_size != 0 && range->size >= instance_size)
    {
      g_array_append_val (ctx->matches, candidate);
    }
  }
}

static kern_return_t
read_local_memory (task_t remote_task,
                   vm_address_t remote_address,
                   vm_size_t size,
                   void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}
`;


const {pointerSize} = Process;

let cachedModule = null;

export function get() {
    if (cachedModule === null)
        cachedModule = compileModule();
    return cachedModule;
}

function compileModule() {
    const {
        objc_getClassList,
        class_getSuperclass,
        class_getInstanceSize,
    } = getApi();

    const selfTask = Memory.alloc(4);
    selfTask.writeU32(Module.getGlobalExportByName('mach_task_self_').readU32());

    const cm = new CModule(code, {
        objc_getClassList,
        class_getSuperclass,
        class_getInstanceSize,
        malloc_get_all_zones: Process.getModuleByName('/usr/lib/system/libsystem_malloc.dylib').getExportByName('malloc_get_all_zones'),
        selfTask,
    });

    const _choose = new NativeFunction(cm.choose, 'pointer', ['pointer', 'bool', 'pointer']);
    const _destroy = new NativeFunction(cm.destroy, 'void', ['pointer']);

    return {
        handle: cm,
        choose(klass, considerSubclasses) {
            const result = [];

            const countPtr = Memory.alloc(4);
            const matches = _choose(klass, considerSubclasses ? 1 : 0, countPtr);
            try {
                const count = countPtr.readU32();
                for (let i = 0; i !== count; i++)
                    result.push(matches.add(i * pointerSize).readPointer());
            } finally {
                _destroy(matches);
            }

            return result;
        },
    };
}

✄
// Ed25519 signature verification for the release-signing chain.
//
// The agent script is signed OFFLINE with a private key that never touches the
// script server (see server/sign_release.py); only the public key is baked into
// the client (RemoteConfig.pubKeyHex). Because the RC4/HMAC master key is baked
// into the shipped client and is therefore effectively public, HMAC alone gives
// freshness and tamper-evidence but NOT authenticity — anyone who extracts the
// key can forge an envelope. The Ed25519 release signature is what actually
// stops a forged or cache-poisoned agent from running: verifying it requires
// only the public key, forging it requires the offline private key.
//
// verify-only: tweetnacl's sign.detached.verify needs no PRNG, so it loads and
// runs in the Gadget's QuickJS runtime without crypto.getRandomValues. It
// carries its own SHA-512 (Ed25519 uses SHA-512 internally), which we do not
// otherwise have.
// Vendored as ESM (src/vendor/tweetnacl.mjs) because frida-compile only bundles
// ES modules and the npm package ships CommonJS. Verify-only: the PRNG setup was
// stripped, so it needs no crypto.getRandomValues in the Gadget runtime.
import nacl from "../vendor/tweetnacl.mjs";
// True only when `signature` (64 bytes) is a valid Ed25519 signature of
// `message` under `publicKey` (32 bytes). Never throws: any malformed input is
// a verification failure, not a crash on the load-blocking path.
export function verifyEd25519(publicKey, message, signature) {
    try {
        if (publicKey.length !== 32 || signature.length !== 64)
            return false;
        return nacl.sign.detached.verify(message, signature, publicKey);
    }
    catch {
        return false;
    }
}

✄
// Where the bootstrap fetches the agent from.
//
// Android uses the loopback: the dev machine is reached through
// `adb reverse tcp:8787 tcp:8787`, and going over the LAN instead does not work
// while a VPN is up on the host — the phone's SYN arrives, the reply leaves
// through the tunnel and never comes back, so the connect just retransmits.
//
// iOS-app-on-macOS is the same trap: the LAN address routes into the VPN
// tunnel and never answers, but the script server on the Mac is reachable on
// 127.0.0.1. So the bootstrap tries loopback FIRST (works for the Mac and for
// any adb/usbmux reverse), then the LAN host for a real untethered device.
import { PROD } from "./env.js";
const DevLoopback = "127.0.0.1";
const LanHost = "192.168.0.100";
export const RemoteConfig = {
    // prod: the public server (TLS on 443); dev: the local script server on the
    // LAN. `./build --prod` flips env.ts to bake the prod endpoint.
    host: PROD ? "script.backtobs.xyz" : (Process.platform === "linux" ? DevLoopback : LanHost),
    hosts: PROD ? ["script.backtobs.xyz"] : [DevLoopback, LanHost],
    port: 8787,
    path: "/v1/script",
    tls: false,
    // Wire protocol the bootstrap speaks. v3 = "sealed channel": the whole
    // response is a crypto_box (X25519+XSalsa20+Poly1305) sealed to a fresh
    // client ephemeral with the server's static key, so a MITM holding the baked
    // master key can no longer forge/freeze responses. The client refuses any
    // response below 3 (downgrade guard).
    protocol: 3,
    // Master key — now used ONLY to obfuscate the on-device cache at rest. It is
    // baked (public), so it never authenticates the wire in v3.
    keyHex: "7f41cce5e1bb987251c190463af646c8d1910b06d5a26a03fd986dd70f64790a",
    // Server static X25519 PUBLIC key of the sealed channel. The private half
    // lives ONLY on the server (~/.btb/channel_x25519_priv.hex / $BTB_CHANNEL_PRIV),
    // never baked — so extracting the app does not let a MITM read or forge the
    // sealed response. Rotate via a new keypair + rebuild if the VPS is exposed.
    channelPubKeyHex: "02135409e2a48c5f00d74fb9669ca67c69d2e2f6120ff3c47455c28d95f08439",
    // Ed25519 public key of the release-signing keypair. The private half is
    // held offline (server/sign_release.py; ~/.btb/release_ed25519_seed.hex) and
    // never reaches the script server. Every agent — freshly downloaded OR
    // loaded from the on-device cache — must carry a valid signature under this
    // key over (version, epoch, content_hash) or it is not run. Empty string
    // disables the check (dev only).
    pubKeyHex: "14c46a10259df2be9baec6300bf83047fc1f0f284615d93cfa2e1d0765b49760",
    // Anti-rollback floor. The client refuses any agent whose epoch is below
    // this, below its persisted high-water mark, or below the cached epoch. Bump
    // this (and sign_release.py's --epoch) whenever an old agent must never run
    // again (e.g. after fixing an agent-side security bug).
    minEpoch: 1,
    // How long a cached agent may be run when the server is unreachable, counted
    // from when the client last saw a fresh, verified reply for it. The server
    // can shorten this per response (max_age); this is the client-side ceiling.
    maxOfflineAgeSec: 86400,
    // Load-blocking budget. connectTimeoutMs bounds a single host connect so a
    // black-holing network cannot stall the launch; networkBudgetMs bounds the
    // whole fetch across hosts; hardDeadlineMs is the internal deadline after
    // which start() gives up and settles (kept below the 10s outer cap in
    // bootstrap.ts so init() can never fire after the cap).
    connectTimeoutMs: 2500,
    networkBudgetMs: 4000,
    hardDeadlineMs: 8000,
    // On-device cache locations, resolved per platform in bootstrap.ts:
    //   cacheDir  — app-private, OS-purgeable (agent.js + agent.meta.json)
    //   stateDir  — app-private, NOT purgeable (epoch high-water mark)
    cacheSubdir: "btb",
    // The body is stored ENCRYPTED at rest (the RC4 ciphertext the server sent,
    // not plaintext JS) so a copy of the file alone is opaque — decrypting it
    // needs the master key baked into the gadget. Hence .enc, not .js.
    cacheFile: "agent.enc",
    metaFile: "agent.meta.json",
    highWaterFile: "epoch.hw"
};

✄
const SHA256_CONSTANTS = Uint32Array.from([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
function rotateRight(value, bits) {
    return value >>> bits | value << 32 - bits;
}
export function sha256(data) {
    const bitLength = data.length * 8;
    const paddedLength = Math.ceil((data.length + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLength);
    padded.set(data);
    padded[data.length] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLength - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(paddedLength - 4, bitLength >>> 0, false);
    const state = Uint32Array.from([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]);
    const words = new Uint32Array(64);
    for (let offset = 0; offset < paddedLength; offset += 64) {
        for (let index = 0; index < 16; index++) {
            words[index] = view.getUint32(offset + index * 4, false);
        }
        for (let index = 16; index < 64; index++) {
            const x = words[index - 15];
            const y = words[index - 2];
            const s0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ x >>> 3;
            const s1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ y >>> 10;
            words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = state;
        for (let index = 0; index < 64; index++) {
            const s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const choice = e & f ^ ~e & g;
            const temp1 = (h + s1 + choice + SHA256_CONSTANTS[index] + words[index]) >>> 0;
            const s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const majority = a & b ^ a & c ^ b & c;
            const temp2 = (s0 + majority) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        state[0] = (state[0] + a) >>> 0;
        state[1] = (state[1] + b) >>> 0;
        state[2] = (state[2] + c) >>> 0;
        state[3] = (state[3] + d) >>> 0;
        state[4] = (state[4] + e) >>> 0;
        state[5] = (state[5] + f) >>> 0;
        state[6] = (state[6] + g) >>> 0;
        state[7] = (state[7] + h) >>> 0;
    }
    const output = new Uint8Array(32);
    const outputView = new DataView(output.buffer);
    for (let index = 0; index < 8; index++)
        outputView.setUint32(index * 4, state[index], false);
    return output;
}
export function utf8Encode(value) {
    const bytes = [];
    for (const character of value) {
        const code = character.codePointAt(0);
        if (code <= 0x7f)
            bytes.push(code);
        else if (code <= 0x7ff)
            bytes.push(0xc0 | code >> 6, 0x80 | code & 0x3f);
        else if (code <= 0xffff) {
            bytes.push(0xe0 | code >> 12, 0x80 | code >> 6 & 0x3f, 0x80 | code & 0x3f);
        }
        else {
            bytes.push(0xf0 | code >> 18, 0x80 | code >> 12 & 0x3f, 0x80 | code >> 6 & 0x3f, 0x80 | code & 0x3f);
        }
    }
    return Uint8Array.from(bytes);
}
export function utf8Decode(bytes) {
    let value = "";
    for (let index = 0; index < bytes.length;) {
        const first = bytes[index++];
        if (first < 0x80)
            value += String.fromCodePoint(first);
        else if (first < 0xe0) {
            value += String.fromCodePoint((first & 0x1f) << 6 | bytes[index++] & 0x3f);
        }
        else if (first < 0xf0) {
            value += String.fromCodePoint((first & 0x0f) << 12 | (bytes[index++] & 0x3f) << 6 | bytes[index++] & 0x3f);
        }
        else {
            value += String.fromCodePoint((first & 7) << 18 | (bytes[index++] & 0x3f) << 12 |
                (bytes[index++] & 0x3f) << 6 | bytes[index++] & 0x3f);
        }
    }
    return value;
}
export function toHex(bytes) {
    let out = "";
    for (let index = 0; index < bytes.length; index++) {
        out += bytes[index].toString(16).padStart(2, "0");
    }
    return out;
}
export function fromHex(value) {
    if (value.length % 2 !== 0)
        throw new Error("invalid hex key");
    const result = new Uint8Array(value.length / 2);
    for (let index = 0; index < result.length; index++) {
        result[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
    }
    return result;
}
export function fromBase64(value) {
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const clean = value.replace(/=+$/, "");
    const output = [];
    let accumulator = 0;
    let bits = 0;
    for (const character of clean) {
        const digit = alphabet.indexOf(character);
        if (digit < 0)
            throw new Error("invalid base64 payload");
        accumulator = accumulator << 6 | digit;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            output.push(accumulator >> bits & 0xff);
            accumulator &= bits === 0 ? 0 : (1 << bits) - 1;
        }
    }
    return Uint8Array.from(output);
}
export function hmacSha256(key, data) {
    let normalized = key.length > 64 ? sha256(key) : key;
    if (normalized.length < 64) {
        const expanded = new Uint8Array(64);
        expanded.set(normalized);
        normalized = expanded;
    }
    const innerPad = new Uint8Array(64);
    const outerPad = new Uint8Array(64);
    for (let index = 0; index < 64; index++) {
        innerPad[index] = normalized[index] ^ 0x36;
        outerPad[index] = normalized[index] ^ 0x5c;
    }
    const inner = new Uint8Array(innerPad.length + data.length);
    inner.set(innerPad);
    inner.set(data, innerPad.length);
    const innerHash = sha256(inner);
    const outer = new Uint8Array(outerPad.length + innerHash.length);
    outer.set(outerPad);
    outer.set(innerHash, outerPad.length);
    return sha256(outer);
}
export function rc4Drop3072(data, key) {
    const state = Uint8Array.from({ length: 256 }, (_, index) => index);
    let j = 0;
    for (let index = 0; index < 256; index++) {
        j = (j + state[index] + key[index % key.length]) & 0xff;
        [state[index], state[j]] = [state[j], state[index]];
    }
    let i = 0;
    j = 0;
    const next = () => {
        i = (i + 1) & 0xff;
        j = (j + state[i]) & 0xff;
        [state[i], state[j]] = [state[j], state[i]];
        return state[(state[i] + state[j]) & 0xff];
    };
    for (let drop = 0; drop < 3072; drop++)
        next();
    return Uint8Array.from(data, byte => byte ^ next());
}
export function equalConstantTime(left, right) {
    if (left.length !== right.length)
        return false;
    let difference = 0;
    for (let index = 0; index < left.length; index++)
        difference |= left[index] ^ right[index];
    return difference === 0;
}

✄
export const PROD = true;

✄
// VENDORED: tweetnacl nacl-fast.js -> ESM via
//   esbuild node_modules/tweetnacl/nacl-fast.js --bundle --format=esm --platform=neutral --external:crypto
// then the PRNG auto-setup require("crypto") was neutralized (verify-only).
var __getOwnPropNames = Object.getOwnPropertyNames;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __commonJS = (cb, mod) => function __require2() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
};

// node_modules/tweetnacl/nacl-fast.js
var require_nacl_fast = __commonJS({
  "node_modules/tweetnacl/nacl-fast.js"(exports, module) {
    (function(nacl) {
      "use strict";
      var gf = function(init) {
        var i, r = new Float64Array(16);
        if (init) for (i = 0; i < init.length; i++) r[i] = init[i];
        return r;
      };
      var randombytes = function() {
        throw new Error("no PRNG");
      };
      var _0 = new Uint8Array(16);
      var _9 = new Uint8Array(32);
      _9[0] = 9;
      var gf0 = gf(), gf1 = gf([1]), _121665 = gf([56129, 1]), D = gf([30883, 4953, 19914, 30187, 55467, 16705, 2637, 112, 59544, 30585, 16505, 36039, 65139, 11119, 27886, 20995]), D2 = gf([61785, 9906, 39828, 60374, 45398, 33411, 5274, 224, 53552, 61171, 33010, 6542, 64743, 22239, 55772, 9222]), X = gf([54554, 36645, 11616, 51542, 42930, 38181, 51040, 26924, 56412, 64982, 57905, 49316, 21502, 52590, 14035, 8553]), Y = gf([26200, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214, 26214]), I = gf([41136, 18958, 6951, 50414, 58488, 44335, 6150, 12099, 55207, 15867, 153, 11085, 57099, 20417, 9344, 11139]);
      function ts64(x, i, h, l) {
        x[i] = h >> 24 & 255;
        x[i + 1] = h >> 16 & 255;
        x[i + 2] = h >> 8 & 255;
        x[i + 3] = h & 255;
        x[i + 4] = l >> 24 & 255;
        x[i + 5] = l >> 16 & 255;
        x[i + 6] = l >> 8 & 255;
        x[i + 7] = l & 255;
      }
      function vn(x, xi, y, yi, n) {
        var i, d = 0;
        for (i = 0; i < n; i++) d |= x[xi + i] ^ y[yi + i];
        return (1 & d - 1 >>> 8) - 1;
      }
      function crypto_verify_16(x, xi, y, yi) {
        return vn(x, xi, y, yi, 16);
      }
      function crypto_verify_32(x, xi, y, yi) {
        return vn(x, xi, y, yi, 32);
      }
      function core_salsa20(o, p, k, c) {
        var j0 = c[0] & 255 | (c[1] & 255) << 8 | (c[2] & 255) << 16 | (c[3] & 255) << 24, j1 = k[0] & 255 | (k[1] & 255) << 8 | (k[2] & 255) << 16 | (k[3] & 255) << 24, j2 = k[4] & 255 | (k[5] & 255) << 8 | (k[6] & 255) << 16 | (k[7] & 255) << 24, j3 = k[8] & 255 | (k[9] & 255) << 8 | (k[10] & 255) << 16 | (k[11] & 255) << 24, j4 = k[12] & 255 | (k[13] & 255) << 8 | (k[14] & 255) << 16 | (k[15] & 255) << 24, j5 = c[4] & 255 | (c[5] & 255) << 8 | (c[6] & 255) << 16 | (c[7] & 255) << 24, j6 = p[0] & 255 | (p[1] & 255) << 8 | (p[2] & 255) << 16 | (p[3] & 255) << 24, j7 = p[4] & 255 | (p[5] & 255) << 8 | (p[6] & 255) << 16 | (p[7] & 255) << 24, j8 = p[8] & 255 | (p[9] & 255) << 8 | (p[10] & 255) << 16 | (p[11] & 255) << 24, j9 = p[12] & 255 | (p[13] & 255) << 8 | (p[14] & 255) << 16 | (p[15] & 255) << 24, j10 = c[8] & 255 | (c[9] & 255) << 8 | (c[10] & 255) << 16 | (c[11] & 255) << 24, j11 = k[16] & 255 | (k[17] & 255) << 8 | (k[18] & 255) << 16 | (k[19] & 255) << 24, j12 = k[20] & 255 | (k[21] & 255) << 8 | (k[22] & 255) << 16 | (k[23] & 255) << 24, j13 = k[24] & 255 | (k[25] & 255) << 8 | (k[26] & 255) << 16 | (k[27] & 255) << 24, j14 = k[28] & 255 | (k[29] & 255) << 8 | (k[30] & 255) << 16 | (k[31] & 255) << 24, j15 = c[12] & 255 | (c[13] & 255) << 8 | (c[14] & 255) << 16 | (c[15] & 255) << 24;
        var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
        for (var i = 0; i < 20; i += 2) {
          u = x0 + x12 | 0;
          x4 ^= u << 7 | u >>> 32 - 7;
          u = x4 + x0 | 0;
          x8 ^= u << 9 | u >>> 32 - 9;
          u = x8 + x4 | 0;
          x12 ^= u << 13 | u >>> 32 - 13;
          u = x12 + x8 | 0;
          x0 ^= u << 18 | u >>> 32 - 18;
          u = x5 + x1 | 0;
          x9 ^= u << 7 | u >>> 32 - 7;
          u = x9 + x5 | 0;
          x13 ^= u << 9 | u >>> 32 - 9;
          u = x13 + x9 | 0;
          x1 ^= u << 13 | u >>> 32 - 13;
          u = x1 + x13 | 0;
          x5 ^= u << 18 | u >>> 32 - 18;
          u = x10 + x6 | 0;
          x14 ^= u << 7 | u >>> 32 - 7;
          u = x14 + x10 | 0;
          x2 ^= u << 9 | u >>> 32 - 9;
          u = x2 + x14 | 0;
          x6 ^= u << 13 | u >>> 32 - 13;
          u = x6 + x2 | 0;
          x10 ^= u << 18 | u >>> 32 - 18;
          u = x15 + x11 | 0;
          x3 ^= u << 7 | u >>> 32 - 7;
          u = x3 + x15 | 0;
          x7 ^= u << 9 | u >>> 32 - 9;
          u = x7 + x3 | 0;
          x11 ^= u << 13 | u >>> 32 - 13;
          u = x11 + x7 | 0;
          x15 ^= u << 18 | u >>> 32 - 18;
          u = x0 + x3 | 0;
          x1 ^= u << 7 | u >>> 32 - 7;
          u = x1 + x0 | 0;
          x2 ^= u << 9 | u >>> 32 - 9;
          u = x2 + x1 | 0;
          x3 ^= u << 13 | u >>> 32 - 13;
          u = x3 + x2 | 0;
          x0 ^= u << 18 | u >>> 32 - 18;
          u = x5 + x4 | 0;
          x6 ^= u << 7 | u >>> 32 - 7;
          u = x6 + x5 | 0;
          x7 ^= u << 9 | u >>> 32 - 9;
          u = x7 + x6 | 0;
          x4 ^= u << 13 | u >>> 32 - 13;
          u = x4 + x7 | 0;
          x5 ^= u << 18 | u >>> 32 - 18;
          u = x10 + x9 | 0;
          x11 ^= u << 7 | u >>> 32 - 7;
          u = x11 + x10 | 0;
          x8 ^= u << 9 | u >>> 32 - 9;
          u = x8 + x11 | 0;
          x9 ^= u << 13 | u >>> 32 - 13;
          u = x9 + x8 | 0;
          x10 ^= u << 18 | u >>> 32 - 18;
          u = x15 + x14 | 0;
          x12 ^= u << 7 | u >>> 32 - 7;
          u = x12 + x15 | 0;
          x13 ^= u << 9 | u >>> 32 - 9;
          u = x13 + x12 | 0;
          x14 ^= u << 13 | u >>> 32 - 13;
          u = x14 + x13 | 0;
          x15 ^= u << 18 | u >>> 32 - 18;
        }
        x0 = x0 + j0 | 0;
        x1 = x1 + j1 | 0;
        x2 = x2 + j2 | 0;
        x3 = x3 + j3 | 0;
        x4 = x4 + j4 | 0;
        x5 = x5 + j5 | 0;
        x6 = x6 + j6 | 0;
        x7 = x7 + j7 | 0;
        x8 = x8 + j8 | 0;
        x9 = x9 + j9 | 0;
        x10 = x10 + j10 | 0;
        x11 = x11 + j11 | 0;
        x12 = x12 + j12 | 0;
        x13 = x13 + j13 | 0;
        x14 = x14 + j14 | 0;
        x15 = x15 + j15 | 0;
        o[0] = x0 >>> 0 & 255;
        o[1] = x0 >>> 8 & 255;
        o[2] = x0 >>> 16 & 255;
        o[3] = x0 >>> 24 & 255;
        o[4] = x1 >>> 0 & 255;
        o[5] = x1 >>> 8 & 255;
        o[6] = x1 >>> 16 & 255;
        o[7] = x1 >>> 24 & 255;
        o[8] = x2 >>> 0 & 255;
        o[9] = x2 >>> 8 & 255;
        o[10] = x2 >>> 16 & 255;
        o[11] = x2 >>> 24 & 255;
        o[12] = x3 >>> 0 & 255;
        o[13] = x3 >>> 8 & 255;
        o[14] = x3 >>> 16 & 255;
        o[15] = x3 >>> 24 & 255;
        o[16] = x4 >>> 0 & 255;
        o[17] = x4 >>> 8 & 255;
        o[18] = x4 >>> 16 & 255;
        o[19] = x4 >>> 24 & 255;
        o[20] = x5 >>> 0 & 255;
        o[21] = x5 >>> 8 & 255;
        o[22] = x5 >>> 16 & 255;
        o[23] = x5 >>> 24 & 255;
        o[24] = x6 >>> 0 & 255;
        o[25] = x6 >>> 8 & 255;
        o[26] = x6 >>> 16 & 255;
        o[27] = x6 >>> 24 & 255;
        o[28] = x7 >>> 0 & 255;
        o[29] = x7 >>> 8 & 255;
        o[30] = x7 >>> 16 & 255;
        o[31] = x7 >>> 24 & 255;
        o[32] = x8 >>> 0 & 255;
        o[33] = x8 >>> 8 & 255;
        o[34] = x8 >>> 16 & 255;
        o[35] = x8 >>> 24 & 255;
        o[36] = x9 >>> 0 & 255;
        o[37] = x9 >>> 8 & 255;
        o[38] = x9 >>> 16 & 255;
        o[39] = x9 >>> 24 & 255;
        o[40] = x10 >>> 0 & 255;
        o[41] = x10 >>> 8 & 255;
        o[42] = x10 >>> 16 & 255;
        o[43] = x10 >>> 24 & 255;
        o[44] = x11 >>> 0 & 255;
        o[45] = x11 >>> 8 & 255;
        o[46] = x11 >>> 16 & 255;
        o[47] = x11 >>> 24 & 255;
        o[48] = x12 >>> 0 & 255;
        o[49] = x12 >>> 8 & 255;
        o[50] = x12 >>> 16 & 255;
        o[51] = x12 >>> 24 & 255;
        o[52] = x13 >>> 0 & 255;
        o[53] = x13 >>> 8 & 255;
        o[54] = x13 >>> 16 & 255;
        o[55] = x13 >>> 24 & 255;
        o[56] = x14 >>> 0 & 255;
        o[57] = x14 >>> 8 & 255;
        o[58] = x14 >>> 16 & 255;
        o[59] = x14 >>> 24 & 255;
        o[60] = x15 >>> 0 & 255;
        o[61] = x15 >>> 8 & 255;
        o[62] = x15 >>> 16 & 255;
        o[63] = x15 >>> 24 & 255;
      }
      function core_hsalsa20(o, p, k, c) {
        var j0 = c[0] & 255 | (c[1] & 255) << 8 | (c[2] & 255) << 16 | (c[3] & 255) << 24, j1 = k[0] & 255 | (k[1] & 255) << 8 | (k[2] & 255) << 16 | (k[3] & 255) << 24, j2 = k[4] & 255 | (k[5] & 255) << 8 | (k[6] & 255) << 16 | (k[7] & 255) << 24, j3 = k[8] & 255 | (k[9] & 255) << 8 | (k[10] & 255) << 16 | (k[11] & 255) << 24, j4 = k[12] & 255 | (k[13] & 255) << 8 | (k[14] & 255) << 16 | (k[15] & 255) << 24, j5 = c[4] & 255 | (c[5] & 255) << 8 | (c[6] & 255) << 16 | (c[7] & 255) << 24, j6 = p[0] & 255 | (p[1] & 255) << 8 | (p[2] & 255) << 16 | (p[3] & 255) << 24, j7 = p[4] & 255 | (p[5] & 255) << 8 | (p[6] & 255) << 16 | (p[7] & 255) << 24, j8 = p[8] & 255 | (p[9] & 255) << 8 | (p[10] & 255) << 16 | (p[11] & 255) << 24, j9 = p[12] & 255 | (p[13] & 255) << 8 | (p[14] & 255) << 16 | (p[15] & 255) << 24, j10 = c[8] & 255 | (c[9] & 255) << 8 | (c[10] & 255) << 16 | (c[11] & 255) << 24, j11 = k[16] & 255 | (k[17] & 255) << 8 | (k[18] & 255) << 16 | (k[19] & 255) << 24, j12 = k[20] & 255 | (k[21] & 255) << 8 | (k[22] & 255) << 16 | (k[23] & 255) << 24, j13 = k[24] & 255 | (k[25] & 255) << 8 | (k[26] & 255) << 16 | (k[27] & 255) << 24, j14 = k[28] & 255 | (k[29] & 255) << 8 | (k[30] & 255) << 16 | (k[31] & 255) << 24, j15 = c[12] & 255 | (c[13] & 255) << 8 | (c[14] & 255) << 16 | (c[15] & 255) << 24;
        var x0 = j0, x1 = j1, x2 = j2, x3 = j3, x4 = j4, x5 = j5, x6 = j6, x7 = j7, x8 = j8, x9 = j9, x10 = j10, x11 = j11, x12 = j12, x13 = j13, x14 = j14, x15 = j15, u;
        for (var i = 0; i < 20; i += 2) {
          u = x0 + x12 | 0;
          x4 ^= u << 7 | u >>> 32 - 7;
          u = x4 + x0 | 0;
          x8 ^= u << 9 | u >>> 32 - 9;
          u = x8 + x4 | 0;
          x12 ^= u << 13 | u >>> 32 - 13;
          u = x12 + x8 | 0;
          x0 ^= u << 18 | u >>> 32 - 18;
          u = x5 + x1 | 0;
          x9 ^= u << 7 | u >>> 32 - 7;
          u = x9 + x5 | 0;
          x13 ^= u << 9 | u >>> 32 - 9;
          u = x13 + x9 | 0;
          x1 ^= u << 13 | u >>> 32 - 13;
          u = x1 + x13 | 0;
          x5 ^= u << 18 | u >>> 32 - 18;
          u = x10 + x6 | 0;
          x14 ^= u << 7 | u >>> 32 - 7;
          u = x14 + x10 | 0;
          x2 ^= u << 9 | u >>> 32 - 9;
          u = x2 + x14 | 0;
          x6 ^= u << 13 | u >>> 32 - 13;
          u = x6 + x2 | 0;
          x10 ^= u << 18 | u >>> 32 - 18;
          u = x15 + x11 | 0;
          x3 ^= u << 7 | u >>> 32 - 7;
          u = x3 + x15 | 0;
          x7 ^= u << 9 | u >>> 32 - 9;
          u = x7 + x3 | 0;
          x11 ^= u << 13 | u >>> 32 - 13;
          u = x11 + x7 | 0;
          x15 ^= u << 18 | u >>> 32 - 18;
          u = x0 + x3 | 0;
          x1 ^= u << 7 | u >>> 32 - 7;
          u = x1 + x0 | 0;
          x2 ^= u << 9 | u >>> 32 - 9;
          u = x2 + x1 | 0;
          x3 ^= u << 13 | u >>> 32 - 13;
          u = x3 + x2 | 0;
          x0 ^= u << 18 | u >>> 32 - 18;
          u = x5 + x4 | 0;
          x6 ^= u << 7 | u >>> 32 - 7;
          u = x6 + x5 | 0;
          x7 ^= u << 9 | u >>> 32 - 9;
          u = x7 + x6 | 0;
          x4 ^= u << 13 | u >>> 32 - 13;
          u = x4 + x7 | 0;
          x5 ^= u << 18 | u >>> 32 - 18;
          u = x10 + x9 | 0;
          x11 ^= u << 7 | u >>> 32 - 7;
          u = x11 + x10 | 0;
          x8 ^= u << 9 | u >>> 32 - 9;
          u = x8 + x11 | 0;
          x9 ^= u << 13 | u >>> 32 - 13;
          u = x9 + x8 | 0;
          x10 ^= u << 18 | u >>> 32 - 18;
          u = x15 + x14 | 0;
          x12 ^= u << 7 | u >>> 32 - 7;
          u = x12 + x15 | 0;
          x13 ^= u << 9 | u >>> 32 - 9;
          u = x13 + x12 | 0;
          x14 ^= u << 13 | u >>> 32 - 13;
          u = x14 + x13 | 0;
          x15 ^= u << 18 | u >>> 32 - 18;
        }
        o[0] = x0 >>> 0 & 255;
        o[1] = x0 >>> 8 & 255;
        o[2] = x0 >>> 16 & 255;
        o[3] = x0 >>> 24 & 255;
        o[4] = x5 >>> 0 & 255;
        o[5] = x5 >>> 8 & 255;
        o[6] = x5 >>> 16 & 255;
        o[7] = x5 >>> 24 & 255;
        o[8] = x10 >>> 0 & 255;
        o[9] = x10 >>> 8 & 255;
        o[10] = x10 >>> 16 & 255;
        o[11] = x10 >>> 24 & 255;
        o[12] = x15 >>> 0 & 255;
        o[13] = x15 >>> 8 & 255;
        o[14] = x15 >>> 16 & 255;
        o[15] = x15 >>> 24 & 255;
        o[16] = x6 >>> 0 & 255;
        o[17] = x6 >>> 8 & 255;
        o[18] = x6 >>> 16 & 255;
        o[19] = x6 >>> 24 & 255;
        o[20] = x7 >>> 0 & 255;
        o[21] = x7 >>> 8 & 255;
        o[22] = x7 >>> 16 & 255;
        o[23] = x7 >>> 24 & 255;
        o[24] = x8 >>> 0 & 255;
        o[25] = x8 >>> 8 & 255;
        o[26] = x8 >>> 16 & 255;
        o[27] = x8 >>> 24 & 255;
        o[28] = x9 >>> 0 & 255;
        o[29] = x9 >>> 8 & 255;
        o[30] = x9 >>> 16 & 255;
        o[31] = x9 >>> 24 & 255;
      }
      function crypto_core_salsa20(out, inp, k, c) {
        core_salsa20(out, inp, k, c);
      }
      function crypto_core_hsalsa20(out, inp, k, c) {
        core_hsalsa20(out, inp, k, c);
      }
      var sigma = new Uint8Array([101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107]);
      function crypto_stream_salsa20_xor(c, cpos, m, mpos, b, n, k) {
        var z = new Uint8Array(16), x = new Uint8Array(64);
        var u, i;
        for (i = 0; i < 16; i++) z[i] = 0;
        for (i = 0; i < 8; i++) z[i] = n[i];
        while (b >= 64) {
          crypto_core_salsa20(x, z, k, sigma);
          for (i = 0; i < 64; i++) c[cpos + i] = m[mpos + i] ^ x[i];
          u = 1;
          for (i = 8; i < 16; i++) {
            u = u + (z[i] & 255) | 0;
            z[i] = u & 255;
            u >>>= 8;
          }
          b -= 64;
          cpos += 64;
          mpos += 64;
        }
        if (b > 0) {
          crypto_core_salsa20(x, z, k, sigma);
          for (i = 0; i < b; i++) c[cpos + i] = m[mpos + i] ^ x[i];
        }
        return 0;
      }
      function crypto_stream_salsa20(c, cpos, b, n, k) {
        var z = new Uint8Array(16), x = new Uint8Array(64);
        var u, i;
        for (i = 0; i < 16; i++) z[i] = 0;
        for (i = 0; i < 8; i++) z[i] = n[i];
        while (b >= 64) {
          crypto_core_salsa20(x, z, k, sigma);
          for (i = 0; i < 64; i++) c[cpos + i] = x[i];
          u = 1;
          for (i = 8; i < 16; i++) {
            u = u + (z[i] & 255) | 0;
            z[i] = u & 255;
            u >>>= 8;
          }
          b -= 64;
          cpos += 64;
        }
        if (b > 0) {
          crypto_core_salsa20(x, z, k, sigma);
          for (i = 0; i < b; i++) c[cpos + i] = x[i];
        }
        return 0;
      }
      function crypto_stream(c, cpos, d, n, k) {
        var s = new Uint8Array(32);
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = new Uint8Array(8);
        for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
        return crypto_stream_salsa20(c, cpos, d, sn, s);
      }
      function crypto_stream_xor(c, cpos, m, mpos, d, n, k) {
        var s = new Uint8Array(32);
        crypto_core_hsalsa20(s, n, k, sigma);
        var sn = new Uint8Array(8);
        for (var i = 0; i < 8; i++) sn[i] = n[i + 16];
        return crypto_stream_salsa20_xor(c, cpos, m, mpos, d, sn, s);
      }
      var poly1305 = function(key) {
        this.buffer = new Uint8Array(16);
        this.r = new Uint16Array(10);
        this.h = new Uint16Array(10);
        this.pad = new Uint16Array(8);
        this.leftover = 0;
        this.fin = 0;
        var t0, t1, t2, t3, t4, t5, t6, t7;
        t0 = key[0] & 255 | (key[1] & 255) << 8;
        this.r[0] = t0 & 8191;
        t1 = key[2] & 255 | (key[3] & 255) << 8;
        this.r[1] = (t0 >>> 13 | t1 << 3) & 8191;
        t2 = key[4] & 255 | (key[5] & 255) << 8;
        this.r[2] = (t1 >>> 10 | t2 << 6) & 7939;
        t3 = key[6] & 255 | (key[7] & 255) << 8;
        this.r[3] = (t2 >>> 7 | t3 << 9) & 8191;
        t4 = key[8] & 255 | (key[9] & 255) << 8;
        this.r[4] = (t3 >>> 4 | t4 << 12) & 255;
        this.r[5] = t4 >>> 1 & 8190;
        t5 = key[10] & 255 | (key[11] & 255) << 8;
        this.r[6] = (t4 >>> 14 | t5 << 2) & 8191;
        t6 = key[12] & 255 | (key[13] & 255) << 8;
        this.r[7] = (t5 >>> 11 | t6 << 5) & 8065;
        t7 = key[14] & 255 | (key[15] & 255) << 8;
        this.r[8] = (t6 >>> 8 | t7 << 8) & 8191;
        this.r[9] = t7 >>> 5 & 127;
        this.pad[0] = key[16] & 255 | (key[17] & 255) << 8;
        this.pad[1] = key[18] & 255 | (key[19] & 255) << 8;
        this.pad[2] = key[20] & 255 | (key[21] & 255) << 8;
        this.pad[3] = key[22] & 255 | (key[23] & 255) << 8;
        this.pad[4] = key[24] & 255 | (key[25] & 255) << 8;
        this.pad[5] = key[26] & 255 | (key[27] & 255) << 8;
        this.pad[6] = key[28] & 255 | (key[29] & 255) << 8;
        this.pad[7] = key[30] & 255 | (key[31] & 255) << 8;
      };
      poly1305.prototype.blocks = function(m, mpos, bytes) {
        var hibit = this.fin ? 0 : 1 << 11;
        var t0, t1, t2, t3, t4, t5, t6, t7, c;
        var d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
        var h0 = this.h[0], h1 = this.h[1], h2 = this.h[2], h3 = this.h[3], h4 = this.h[4], h5 = this.h[5], h6 = this.h[6], h7 = this.h[7], h8 = this.h[8], h9 = this.h[9];
        var r0 = this.r[0], r1 = this.r[1], r2 = this.r[2], r3 = this.r[3], r4 = this.r[4], r5 = this.r[5], r6 = this.r[6], r7 = this.r[7], r8 = this.r[8], r9 = this.r[9];
        while (bytes >= 16) {
          t0 = m[mpos + 0] & 255 | (m[mpos + 1] & 255) << 8;
          h0 += t0 & 8191;
          t1 = m[mpos + 2] & 255 | (m[mpos + 3] & 255) << 8;
          h1 += (t0 >>> 13 | t1 << 3) & 8191;
          t2 = m[mpos + 4] & 255 | (m[mpos + 5] & 255) << 8;
          h2 += (t1 >>> 10 | t2 << 6) & 8191;
          t3 = m[mpos + 6] & 255 | (m[mpos + 7] & 255) << 8;
          h3 += (t2 >>> 7 | t3 << 9) & 8191;
          t4 = m[mpos + 8] & 255 | (m[mpos + 9] & 255) << 8;
          h4 += (t3 >>> 4 | t4 << 12) & 8191;
          h5 += t4 >>> 1 & 8191;
          t5 = m[mpos + 10] & 255 | (m[mpos + 11] & 255) << 8;
          h6 += (t4 >>> 14 | t5 << 2) & 8191;
          t6 = m[mpos + 12] & 255 | (m[mpos + 13] & 255) << 8;
          h7 += (t5 >>> 11 | t6 << 5) & 8191;
          t7 = m[mpos + 14] & 255 | (m[mpos + 15] & 255) << 8;
          h8 += (t6 >>> 8 | t7 << 8) & 8191;
          h9 += t7 >>> 5 | hibit;
          c = 0;
          d0 = c;
          d0 += h0 * r0;
          d0 += h1 * (5 * r9);
          d0 += h2 * (5 * r8);
          d0 += h3 * (5 * r7);
          d0 += h4 * (5 * r6);
          c = d0 >>> 13;
          d0 &= 8191;
          d0 += h5 * (5 * r5);
          d0 += h6 * (5 * r4);
          d0 += h7 * (5 * r3);
          d0 += h8 * (5 * r2);
          d0 += h9 * (5 * r1);
          c += d0 >>> 13;
          d0 &= 8191;
          d1 = c;
          d1 += h0 * r1;
          d1 += h1 * r0;
          d1 += h2 * (5 * r9);
          d1 += h3 * (5 * r8);
          d1 += h4 * (5 * r7);
          c = d1 >>> 13;
          d1 &= 8191;
          d1 += h5 * (5 * r6);
          d1 += h6 * (5 * r5);
          d1 += h7 * (5 * r4);
          d1 += h8 * (5 * r3);
          d1 += h9 * (5 * r2);
          c += d1 >>> 13;
          d1 &= 8191;
          d2 = c;
          d2 += h0 * r2;
          d2 += h1 * r1;
          d2 += h2 * r0;
          d2 += h3 * (5 * r9);
          d2 += h4 * (5 * r8);
          c = d2 >>> 13;
          d2 &= 8191;
          d2 += h5 * (5 * r7);
          d2 += h6 * (5 * r6);
          d2 += h7 * (5 * r5);
          d2 += h8 * (5 * r4);
          d2 += h9 * (5 * r3);
          c += d2 >>> 13;
          d2 &= 8191;
          d3 = c;
          d3 += h0 * r3;
          d3 += h1 * r2;
          d3 += h2 * r1;
          d3 += h3 * r0;
          d3 += h4 * (5 * r9);
          c = d3 >>> 13;
          d3 &= 8191;
          d3 += h5 * (5 * r8);
          d3 += h6 * (5 * r7);
          d3 += h7 * (5 * r6);
          d3 += h8 * (5 * r5);
          d3 += h9 * (5 * r4);
          c += d3 >>> 13;
          d3 &= 8191;
          d4 = c;
          d4 += h0 * r4;
          d4 += h1 * r3;
          d4 += h2 * r2;
          d4 += h3 * r1;
          d4 += h4 * r0;
          c = d4 >>> 13;
          d4 &= 8191;
          d4 += h5 * (5 * r9);
          d4 += h6 * (5 * r8);
          d4 += h7 * (5 * r7);
          d4 += h8 * (5 * r6);
          d4 += h9 * (5 * r5);
          c += d4 >>> 13;
          d4 &= 8191;
          d5 = c;
          d5 += h0 * r5;
          d5 += h1 * r4;
          d5 += h2 * r3;
          d5 += h3 * r2;
          d5 += h4 * r1;
          c = d5 >>> 13;
          d5 &= 8191;
          d5 += h5 * r0;
          d5 += h6 * (5 * r9);
          d5 += h7 * (5 * r8);
          d5 += h8 * (5 * r7);
          d5 += h9 * (5 * r6);
          c += d5 >>> 13;
          d5 &= 8191;
          d6 = c;
          d6 += h0 * r6;
          d6 += h1 * r5;
          d6 += h2 * r4;
          d6 += h3 * r3;
          d6 += h4 * r2;
          c = d6 >>> 13;
          d6 &= 8191;
          d6 += h5 * r1;
          d6 += h6 * r0;
          d6 += h7 * (5 * r9);
          d6 += h8 * (5 * r8);
          d6 += h9 * (5 * r7);
          c += d6 >>> 13;
          d6 &= 8191;
          d7 = c;
          d7 += h0 * r7;
          d7 += h1 * r6;
          d7 += h2 * r5;
          d7 += h3 * r4;
          d7 += h4 * r3;
          c = d7 >>> 13;
          d7 &= 8191;
          d7 += h5 * r2;
          d7 += h6 * r1;
          d7 += h7 * r0;
          d7 += h8 * (5 * r9);
          d7 += h9 * (5 * r8);
          c += d7 >>> 13;
          d7 &= 8191;
          d8 = c;
          d8 += h0 * r8;
          d8 += h1 * r7;
          d8 += h2 * r6;
          d8 += h3 * r5;
          d8 += h4 * r4;
          c = d8 >>> 13;
          d8 &= 8191;
          d8 += h5 * r3;
          d8 += h6 * r2;
          d8 += h7 * r1;
          d8 += h8 * r0;
          d8 += h9 * (5 * r9);
          c += d8 >>> 13;
          d8 &= 8191;
          d9 = c;
          d9 += h0 * r9;
          d9 += h1 * r8;
          d9 += h2 * r7;
          d9 += h3 * r6;
          d9 += h4 * r5;
          c = d9 >>> 13;
          d9 &= 8191;
          d9 += h5 * r4;
          d9 += h6 * r3;
          d9 += h7 * r2;
          d9 += h8 * r1;
          d9 += h9 * r0;
          c += d9 >>> 13;
          d9 &= 8191;
          c = (c << 2) + c | 0;
          c = c + d0 | 0;
          d0 = c & 8191;
          c = c >>> 13;
          d1 += c;
          h0 = d0;
          h1 = d1;
          h2 = d2;
          h3 = d3;
          h4 = d4;
          h5 = d5;
          h6 = d6;
          h7 = d7;
          h8 = d8;
          h9 = d9;
          mpos += 16;
          bytes -= 16;
        }
        this.h[0] = h0;
        this.h[1] = h1;
        this.h[2] = h2;
        this.h[3] = h3;
        this.h[4] = h4;
        this.h[5] = h5;
        this.h[6] = h6;
        this.h[7] = h7;
        this.h[8] = h8;
        this.h[9] = h9;
      };
      poly1305.prototype.finish = function(mac, macpos) {
        var g = new Uint16Array(10);
        var c, mask, f, i;
        if (this.leftover) {
          i = this.leftover;
          this.buffer[i++] = 1;
          for (; i < 16; i++) this.buffer[i] = 0;
          this.fin = 1;
          this.blocks(this.buffer, 0, 16);
        }
        c = this.h[1] >>> 13;
        this.h[1] &= 8191;
        for (i = 2; i < 10; i++) {
          this.h[i] += c;
          c = this.h[i] >>> 13;
          this.h[i] &= 8191;
        }
        this.h[0] += c * 5;
        c = this.h[0] >>> 13;
        this.h[0] &= 8191;
        this.h[1] += c;
        c = this.h[1] >>> 13;
        this.h[1] &= 8191;
        this.h[2] += c;
        g[0] = this.h[0] + 5;
        c = g[0] >>> 13;
        g[0] &= 8191;
        for (i = 1; i < 10; i++) {
          g[i] = this.h[i] + c;
          c = g[i] >>> 13;
          g[i] &= 8191;
        }
        g[9] -= 1 << 13;
        mask = (c ^ 1) - 1;
        for (i = 0; i < 10; i++) g[i] &= mask;
        mask = ~mask;
        for (i = 0; i < 10; i++) this.h[i] = this.h[i] & mask | g[i];
        this.h[0] = (this.h[0] | this.h[1] << 13) & 65535;
        this.h[1] = (this.h[1] >>> 3 | this.h[2] << 10) & 65535;
        this.h[2] = (this.h[2] >>> 6 | this.h[3] << 7) & 65535;
        this.h[3] = (this.h[3] >>> 9 | this.h[4] << 4) & 65535;
        this.h[4] = (this.h[4] >>> 12 | this.h[5] << 1 | this.h[6] << 14) & 65535;
        this.h[5] = (this.h[6] >>> 2 | this.h[7] << 11) & 65535;
        this.h[6] = (this.h[7] >>> 5 | this.h[8] << 8) & 65535;
        this.h[7] = (this.h[8] >>> 8 | this.h[9] << 5) & 65535;
        f = this.h[0] + this.pad[0];
        this.h[0] = f & 65535;
        for (i = 1; i < 8; i++) {
          f = (this.h[i] + this.pad[i] | 0) + (f >>> 16) | 0;
          this.h[i] = f & 65535;
        }
        mac[macpos + 0] = this.h[0] >>> 0 & 255;
        mac[macpos + 1] = this.h[0] >>> 8 & 255;
        mac[macpos + 2] = this.h[1] >>> 0 & 255;
        mac[macpos + 3] = this.h[1] >>> 8 & 255;
        mac[macpos + 4] = this.h[2] >>> 0 & 255;
        mac[macpos + 5] = this.h[2] >>> 8 & 255;
        mac[macpos + 6] = this.h[3] >>> 0 & 255;
        mac[macpos + 7] = this.h[3] >>> 8 & 255;
        mac[macpos + 8] = this.h[4] >>> 0 & 255;
        mac[macpos + 9] = this.h[4] >>> 8 & 255;
        mac[macpos + 10] = this.h[5] >>> 0 & 255;
        mac[macpos + 11] = this.h[5] >>> 8 & 255;
        mac[macpos + 12] = this.h[6] >>> 0 & 255;
        mac[macpos + 13] = this.h[6] >>> 8 & 255;
        mac[macpos + 14] = this.h[7] >>> 0 & 255;
        mac[macpos + 15] = this.h[7] >>> 8 & 255;
      };
      poly1305.prototype.update = function(m, mpos, bytes) {
        var i, want;
        if (this.leftover) {
          want = 16 - this.leftover;
          if (want > bytes)
            want = bytes;
          for (i = 0; i < want; i++)
            this.buffer[this.leftover + i] = m[mpos + i];
          bytes -= want;
          mpos += want;
          this.leftover += want;
          if (this.leftover < 16)
            return;
          this.blocks(this.buffer, 0, 16);
          this.leftover = 0;
        }
        if (bytes >= 16) {
          want = bytes - bytes % 16;
          this.blocks(m, mpos, want);
          mpos += want;
          bytes -= want;
        }
        if (bytes) {
          for (i = 0; i < bytes; i++)
            this.buffer[this.leftover + i] = m[mpos + i];
          this.leftover += bytes;
        }
      };
      function crypto_onetimeauth(out, outpos, m, mpos, n, k) {
        var s = new poly1305(k);
        s.update(m, mpos, n);
        s.finish(out, outpos);
        return 0;
      }
      function crypto_onetimeauth_verify(h, hpos, m, mpos, n, k) {
        var x = new Uint8Array(16);
        crypto_onetimeauth(x, 0, m, mpos, n, k);
        return crypto_verify_16(h, hpos, x, 0);
      }
      function crypto_secretbox(c, m, d, n, k) {
        var i;
        if (d < 32) return -1;
        crypto_stream_xor(c, 0, m, 0, d, n, k);
        crypto_onetimeauth(c, 16, c, 32, d - 32, c);
        for (i = 0; i < 16; i++) c[i] = 0;
        return 0;
      }
      function crypto_secretbox_open(m, c, d, n, k) {
        var i;
        var x = new Uint8Array(32);
        if (d < 32) return -1;
        crypto_stream(x, 0, 32, n, k);
        if (crypto_onetimeauth_verify(c, 16, c, 32, d - 32, x) !== 0) return -1;
        crypto_stream_xor(m, 0, c, 0, d, n, k);
        for (i = 0; i < 32; i++) m[i] = 0;
        return 0;
      }
      function set25519(r, a) {
        var i;
        for (i = 0; i < 16; i++) r[i] = a[i] | 0;
      }
      function car25519(o) {
        var i, v, c = 1;
        for (i = 0; i < 16; i++) {
          v = o[i] + c + 65535;
          c = Math.floor(v / 65536);
          o[i] = v - c * 65536;
        }
        o[0] += c - 1 + 37 * (c - 1);
      }
      function sel25519(p, q, b) {
        var t, c = ~(b - 1);
        for (var i = 0; i < 16; i++) {
          t = c & (p[i] ^ q[i]);
          p[i] ^= t;
          q[i] ^= t;
        }
      }
      function pack25519(o, n) {
        var i, j, b;
        var m = gf(), t = gf();
        for (i = 0; i < 16; i++) t[i] = n[i];
        car25519(t);
        car25519(t);
        car25519(t);
        for (j = 0; j < 2; j++) {
          m[0] = t[0] - 65517;
          for (i = 1; i < 15; i++) {
            m[i] = t[i] - 65535 - (m[i - 1] >> 16 & 1);
            m[i - 1] &= 65535;
          }
          m[15] = t[15] - 32767 - (m[14] >> 16 & 1);
          b = m[15] >> 16 & 1;
          m[14] &= 65535;
          sel25519(t, m, 1 - b);
        }
        for (i = 0; i < 16; i++) {
          o[2 * i] = t[i] & 255;
          o[2 * i + 1] = t[i] >> 8;
        }
      }
      function neq25519(a, b) {
        var c = new Uint8Array(32), d = new Uint8Array(32);
        pack25519(c, a);
        pack25519(d, b);
        return crypto_verify_32(c, 0, d, 0);
      }
      function par25519(a) {
        var d = new Uint8Array(32);
        pack25519(d, a);
        return d[0] & 1;
      }
      function unpack25519(o, n) {
        var i;
        for (i = 0; i < 16; i++) o[i] = n[2 * i] + (n[2 * i + 1] << 8);
        o[15] &= 32767;
      }
      function A(o, a, b) {
        for (var i = 0; i < 16; i++) o[i] = a[i] + b[i];
      }
      function Z(o, a, b) {
        for (var i = 0; i < 16; i++) o[i] = a[i] - b[i];
      }
      function M(o, a, b) {
        var v, c, t0 = 0, t1 = 0, t2 = 0, t3 = 0, t4 = 0, t5 = 0, t6 = 0, t7 = 0, t8 = 0, t9 = 0, t10 = 0, t11 = 0, t12 = 0, t13 = 0, t14 = 0, t15 = 0, t16 = 0, t17 = 0, t18 = 0, t19 = 0, t20 = 0, t21 = 0, t22 = 0, t23 = 0, t24 = 0, t25 = 0, t26 = 0, t27 = 0, t28 = 0, t29 = 0, t30 = 0, b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3], b4 = b[4], b5 = b[5], b6 = b[6], b7 = b[7], b8 = b[8], b9 = b[9], b10 = b[10], b11 = b[11], b12 = b[12], b13 = b[13], b14 = b[14], b15 = b[15];
        v = a[0];
        t0 += v * b0;
        t1 += v * b1;
        t2 += v * b2;
        t3 += v * b3;
        t4 += v * b4;
        t5 += v * b5;
        t6 += v * b6;
        t7 += v * b7;
        t8 += v * b8;
        t9 += v * b9;
        t10 += v * b10;
        t11 += v * b11;
        t12 += v * b12;
        t13 += v * b13;
        t14 += v * b14;
        t15 += v * b15;
        v = a[1];
        t1 += v * b0;
        t2 += v * b1;
        t3 += v * b2;
        t4 += v * b3;
        t5 += v * b4;
        t6 += v * b5;
        t7 += v * b6;
        t8 += v * b7;
        t9 += v * b8;
        t10 += v * b9;
        t11 += v * b10;
        t12 += v * b11;
        t13 += v * b12;
        t14 += v * b13;
        t15 += v * b14;
        t16 += v * b15;
        v = a[2];
        t2 += v * b0;
        t3 += v * b1;
        t4 += v * b2;
        t5 += v * b3;
        t6 += v * b4;
        t7 += v * b5;
        t8 += v * b6;
        t9 += v * b7;
        t10 += v * b8;
        t11 += v * b9;
        t12 += v * b10;
        t13 += v * b11;
        t14 += v * b12;
        t15 += v * b13;
        t16 += v * b14;
        t17 += v * b15;
        v = a[3];
        t3 += v * b0;
        t4 += v * b1;
        t5 += v * b2;
        t6 += v * b3;
        t7 += v * b4;
        t8 += v * b5;
        t9 += v * b6;
        t10 += v * b7;
        t11 += v * b8;
        t12 += v * b9;
        t13 += v * b10;
        t14 += v * b11;
        t15 += v * b12;
        t16 += v * b13;
        t17 += v * b14;
        t18 += v * b15;
        v = a[4];
        t4 += v * b0;
        t5 += v * b1;
        t6 += v * b2;
        t7 += v * b3;
        t8 += v * b4;
        t9 += v * b5;
        t10 += v * b6;
        t11 += v * b7;
        t12 += v * b8;
        t13 += v * b9;
        t14 += v * b10;
        t15 += v * b11;
        t16 += v * b12;
        t17 += v * b13;
        t18 += v * b14;
        t19 += v * b15;
        v = a[5];
        t5 += v * b0;
        t6 += v * b1;
        t7 += v * b2;
        t8 += v * b3;
        t9 += v * b4;
        t10 += v * b5;
        t11 += v * b6;
        t12 += v * b7;
        t13 += v * b8;
        t14 += v * b9;
        t15 += v * b10;
        t16 += v * b11;
        t17 += v * b12;
        t18 += v * b13;
        t19 += v * b14;
        t20 += v * b15;
        v = a[6];
        t6 += v * b0;
        t7 += v * b1;
        t8 += v * b2;
        t9 += v * b3;
        t10 += v * b4;
        t11 += v * b5;
        t12 += v * b6;
        t13 += v * b7;
        t14 += v * b8;
        t15 += v * b9;
        t16 += v * b10;
        t17 += v * b11;
        t18 += v * b12;
        t19 += v * b13;
        t20 += v * b14;
        t21 += v * b15;
        v = a[7];
        t7 += v * b0;
        t8 += v * b1;
        t9 += v * b2;
        t10 += v * b3;
        t11 += v * b4;
        t12 += v * b5;
        t13 += v * b6;
        t14 += v * b7;
        t15 += v * b8;
        t16 += v * b9;
        t17 += v * b10;
        t18 += v * b11;
        t19 += v * b12;
        t20 += v * b13;
        t21 += v * b14;
        t22 += v * b15;
        v = a[8];
        t8 += v * b0;
        t9 += v * b1;
        t10 += v * b2;
        t11 += v * b3;
        t12 += v * b4;
        t13 += v * b5;
        t14 += v * b6;
        t15 += v * b7;
        t16 += v * b8;
        t17 += v * b9;
        t18 += v * b10;
        t19 += v * b11;
        t20 += v * b12;
        t21 += v * b13;
        t22 += v * b14;
        t23 += v * b15;
        v = a[9];
        t9 += v * b0;
        t10 += v * b1;
        t11 += v * b2;
        t12 += v * b3;
        t13 += v * b4;
        t14 += v * b5;
        t15 += v * b6;
        t16 += v * b7;
        t17 += v * b8;
        t18 += v * b9;
        t19 += v * b10;
        t20 += v * b11;
        t21 += v * b12;
        t22 += v * b13;
        t23 += v * b14;
        t24 += v * b15;
        v = a[10];
        t10 += v * b0;
        t11 += v * b1;
        t12 += v * b2;
        t13 += v * b3;
        t14 += v * b4;
        t15 += v * b5;
        t16 += v * b6;
        t17 += v * b7;
        t18 += v * b8;
        t19 += v * b9;
        t20 += v * b10;
        t21 += v * b11;
        t22 += v * b12;
        t23 += v * b13;
        t24 += v * b14;
        t25 += v * b15;
        v = a[11];
        t11 += v * b0;
        t12 += v * b1;
        t13 += v * b2;
        t14 += v * b3;
        t15 += v * b4;
        t16 += v * b5;
        t17 += v * b6;
        t18 += v * b7;
        t19 += v * b8;
        t20 += v * b9;
        t21 += v * b10;
        t22 += v * b11;
        t23 += v * b12;
        t24 += v * b13;
        t25 += v * b14;
        t26 += v * b15;
        v = a[12];
        t12 += v * b0;
        t13 += v * b1;
        t14 += v * b2;
        t15 += v * b3;
        t16 += v * b4;
        t17 += v * b5;
        t18 += v * b6;
        t19 += v * b7;
        t20 += v * b8;
        t21 += v * b9;
        t22 += v * b10;
        t23 += v * b11;
        t24 += v * b12;
        t25 += v * b13;
        t26 += v * b14;
        t27 += v * b15;
        v = a[13];
        t13 += v * b0;
        t14 += v * b1;
        t15 += v * b2;
        t16 += v * b3;
        t17 += v * b4;
        t18 += v * b5;
        t19 += v * b6;
        t20 += v * b7;
        t21 += v * b8;
        t22 += v * b9;
        t23 += v * b10;
        t24 += v * b11;
        t25 += v * b12;
        t26 += v * b13;
        t27 += v * b14;
        t28 += v * b15;
        v = a[14];
        t14 += v * b0;
        t15 += v * b1;
        t16 += v * b2;
        t17 += v * b3;
        t18 += v * b4;
        t19 += v * b5;
        t20 += v * b6;
        t21 += v * b7;
        t22 += v * b8;
        t23 += v * b9;
        t24 += v * b10;
        t25 += v * b11;
        t26 += v * b12;
        t27 += v * b13;
        t28 += v * b14;
        t29 += v * b15;
        v = a[15];
        t15 += v * b0;
        t16 += v * b1;
        t17 += v * b2;
        t18 += v * b3;
        t19 += v * b4;
        t20 += v * b5;
        t21 += v * b6;
        t22 += v * b7;
        t23 += v * b8;
        t24 += v * b9;
        t25 += v * b10;
        t26 += v * b11;
        t27 += v * b12;
        t28 += v * b13;
        t29 += v * b14;
        t30 += v * b15;
        t0 += 38 * t16;
        t1 += 38 * t17;
        t2 += 38 * t18;
        t3 += 38 * t19;
        t4 += 38 * t20;
        t5 += 38 * t21;
        t6 += 38 * t22;
        t7 += 38 * t23;
        t8 += 38 * t24;
        t9 += 38 * t25;
        t10 += 38 * t26;
        t11 += 38 * t27;
        t12 += 38 * t28;
        t13 += 38 * t29;
        t14 += 38 * t30;
        c = 1;
        v = t0 + c + 65535;
        c = Math.floor(v / 65536);
        t0 = v - c * 65536;
        v = t1 + c + 65535;
        c = Math.floor(v / 65536);
        t1 = v - c * 65536;
        v = t2 + c + 65535;
        c = Math.floor(v / 65536);
        t2 = v - c * 65536;
        v = t3 + c + 65535;
        c = Math.floor(v / 65536);
        t3 = v - c * 65536;
        v = t4 + c + 65535;
        c = Math.floor(v / 65536);
        t4 = v - c * 65536;
        v = t5 + c + 65535;
        c = Math.floor(v / 65536);
        t5 = v - c * 65536;
        v = t6 + c + 65535;
        c = Math.floor(v / 65536);
        t6 = v - c * 65536;
        v = t7 + c + 65535;
        c = Math.floor(v / 65536);
        t7 = v - c * 65536;
        v = t8 + c + 65535;
        c = Math.floor(v / 65536);
        t8 = v - c * 65536;
        v = t9 + c + 65535;
        c = Math.floor(v / 65536);
        t9 = v - c * 65536;
        v = t10 + c + 65535;
        c = Math.floor(v / 65536);
        t10 = v - c * 65536;
        v = t11 + c + 65535;
        c = Math.floor(v / 65536);
        t11 = v - c * 65536;
        v = t12 + c + 65535;
        c = Math.floor(v / 65536);
        t12 = v - c * 65536;
        v = t13 + c + 65535;
        c = Math.floor(v / 65536);
        t13 = v - c * 65536;
        v = t14 + c + 65535;
        c = Math.floor(v / 65536);
        t14 = v - c * 65536;
        v = t15 + c + 65535;
        c = Math.floor(v / 65536);
        t15 = v - c * 65536;
        t0 += c - 1 + 37 * (c - 1);
        c = 1;
        v = t0 + c + 65535;
        c = Math.floor(v / 65536);
        t0 = v - c * 65536;
        v = t1 + c + 65535;
        c = Math.floor(v / 65536);
        t1 = v - c * 65536;
        v = t2 + c + 65535;
        c = Math.floor(v / 65536);
        t2 = v - c * 65536;
        v = t3 + c + 65535;
        c = Math.floor(v / 65536);
        t3 = v - c * 65536;
        v = t4 + c + 65535;
        c = Math.floor(v / 65536);
        t4 = v - c * 65536;
        v = t5 + c + 65535;
        c = Math.floor(v / 65536);
        t5 = v - c * 65536;
        v = t6 + c + 65535;
        c = Math.floor(v / 65536);
        t6 = v - c * 65536;
        v = t7 + c + 65535;
        c = Math.floor(v / 65536);
        t7 = v - c * 65536;
        v = t8 + c + 65535;
        c = Math.floor(v / 65536);
        t8 = v - c * 65536;
        v = t9 + c + 65535;
        c = Math.floor(v / 65536);
        t9 = v - c * 65536;
        v = t10 + c + 65535;
        c = Math.floor(v / 65536);
        t10 = v - c * 65536;
        v = t11 + c + 65535;
        c = Math.floor(v / 65536);
        t11 = v - c * 65536;
        v = t12 + c + 65535;
        c = Math.floor(v / 65536);
        t12 = v - c * 65536;
        v = t13 + c + 65535;
        c = Math.floor(v / 65536);
        t13 = v - c * 65536;
        v = t14 + c + 65535;
        c = Math.floor(v / 65536);
        t14 = v - c * 65536;
        v = t15 + c + 65535;
        c = Math.floor(v / 65536);
        t15 = v - c * 65536;
        t0 += c - 1 + 37 * (c - 1);
        o[0] = t0;
        o[1] = t1;
        o[2] = t2;
        o[3] = t3;
        o[4] = t4;
        o[5] = t5;
        o[6] = t6;
        o[7] = t7;
        o[8] = t8;
        o[9] = t9;
        o[10] = t10;
        o[11] = t11;
        o[12] = t12;
        o[13] = t13;
        o[14] = t14;
        o[15] = t15;
      }
      function S(o, a) {
        M(o, a, a);
      }
      function inv25519(o, i) {
        var c = gf();
        var a;
        for (a = 0; a < 16; a++) c[a] = i[a];
        for (a = 253; a >= 0; a--) {
          S(c, c);
          if (a !== 2 && a !== 4) M(c, c, i);
        }
        for (a = 0; a < 16; a++) o[a] = c[a];
      }
      function pow2523(o, i) {
        var c = gf();
        var a;
        for (a = 0; a < 16; a++) c[a] = i[a];
        for (a = 250; a >= 0; a--) {
          S(c, c);
          if (a !== 1) M(c, c, i);
        }
        for (a = 0; a < 16; a++) o[a] = c[a];
      }
      function crypto_scalarmult(q, n, p) {
        var z = new Uint8Array(32);
        var x = new Float64Array(80), r, i;
        var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf();
        for (i = 0; i < 31; i++) z[i] = n[i];
        z[31] = n[31] & 127 | 64;
        z[0] &= 248;
        unpack25519(x, p);
        for (i = 0; i < 16; i++) {
          b[i] = x[i];
          d[i] = a[i] = c[i] = 0;
        }
        a[0] = d[0] = 1;
        for (i = 254; i >= 0; --i) {
          r = z[i >>> 3] >>> (i & 7) & 1;
          sel25519(a, b, r);
          sel25519(c, d, r);
          A(e, a, c);
          Z(a, a, c);
          A(c, b, d);
          Z(b, b, d);
          S(d, e);
          S(f, a);
          M(a, c, a);
          M(c, b, e);
          A(e, a, c);
          Z(a, a, c);
          S(b, a);
          Z(c, d, f);
          M(a, c, _121665);
          A(a, a, d);
          M(c, c, a);
          M(a, d, f);
          M(d, b, x);
          S(b, e);
          sel25519(a, b, r);
          sel25519(c, d, r);
        }
        for (i = 0; i < 16; i++) {
          x[i + 16] = a[i];
          x[i + 32] = c[i];
          x[i + 48] = b[i];
          x[i + 64] = d[i];
        }
        var x32 = x.subarray(32);
        var x16 = x.subarray(16);
        inv25519(x32, x32);
        M(x16, x16, x32);
        pack25519(q, x16);
        return 0;
      }
      function crypto_scalarmult_base(q, n) {
        return crypto_scalarmult(q, n, _9);
      }
      function crypto_box_keypair(y, x) {
        randombytes(x, 32);
        return crypto_scalarmult_base(y, x);
      }
      function crypto_box_beforenm(k, y, x) {
        var s = new Uint8Array(32);
        crypto_scalarmult(s, x, y);
        return crypto_core_hsalsa20(k, _0, s, sigma);
      }
      var crypto_box_afternm = crypto_secretbox;
      var crypto_box_open_afternm = crypto_secretbox_open;
      function crypto_box(c, m, d, n, y, x) {
        var k = new Uint8Array(32);
        crypto_box_beforenm(k, y, x);
        return crypto_box_afternm(c, m, d, n, k);
      }
      function crypto_box_open(m, c, d, n, y, x) {
        var k = new Uint8Array(32);
        crypto_box_beforenm(k, y, x);
        return crypto_box_open_afternm(m, c, d, n, k);
      }
      var K = [
        1116352408,
        3609767458,
        1899447441,
        602891725,
        3049323471,
        3964484399,
        3921009573,
        2173295548,
        961987163,
        4081628472,
        1508970993,
        3053834265,
        2453635748,
        2937671579,
        2870763221,
        3664609560,
        3624381080,
        2734883394,
        310598401,
        1164996542,
        607225278,
        1323610764,
        1426881987,
        3590304994,
        1925078388,
        4068182383,
        2162078206,
        991336113,
        2614888103,
        633803317,
        3248222580,
        3479774868,
        3835390401,
        2666613458,
        4022224774,
        944711139,
        264347078,
        2341262773,
        604807628,
        2007800933,
        770255983,
        1495990901,
        1249150122,
        1856431235,
        1555081692,
        3175218132,
        1996064986,
        2198950837,
        2554220882,
        3999719339,
        2821834349,
        766784016,
        2952996808,
        2566594879,
        3210313671,
        3203337956,
        3336571891,
        1034457026,
        3584528711,
        2466948901,
        113926993,
        3758326383,
        338241895,
        168717936,
        666307205,
        1188179964,
        773529912,
        1546045734,
        1294757372,
        1522805485,
        1396182291,
        2643833823,
        1695183700,
        2343527390,
        1986661051,
        1014477480,
        2177026350,
        1206759142,
        2456956037,
        344077627,
        2730485921,
        1290863460,
        2820302411,
        3158454273,
        3259730800,
        3505952657,
        3345764771,
        106217008,
        3516065817,
        3606008344,
        3600352804,
        1432725776,
        4094571909,
        1467031594,
        275423344,
        851169720,
        430227734,
        3100823752,
        506948616,
        1363258195,
        659060556,
        3750685593,
        883997877,
        3785050280,
        958139571,
        3318307427,
        1322822218,
        3812723403,
        1537002063,
        2003034995,
        1747873779,
        3602036899,
        1955562222,
        1575990012,
        2024104815,
        1125592928,
        2227730452,
        2716904306,
        2361852424,
        442776044,
        2428436474,
        593698344,
        2756734187,
        3733110249,
        3204031479,
        2999351573,
        3329325298,
        3815920427,
        3391569614,
        3928383900,
        3515267271,
        566280711,
        3940187606,
        3454069534,
        4118630271,
        4000239992,
        116418474,
        1914138554,
        174292421,
        2731055270,
        289380356,
        3203993006,
        460393269,
        320620315,
        685471733,
        587496836,
        852142971,
        1086792851,
        1017036298,
        365543100,
        1126000580,
        2618297676,
        1288033470,
        3409855158,
        1501505948,
        4234509866,
        1607167915,
        987167468,
        1816402316,
        1246189591
      ];
      function crypto_hashblocks_hl(hh, hl, m, n) {
        var wh = new Int32Array(16), wl = new Int32Array(16), bh0, bh1, bh2, bh3, bh4, bh5, bh6, bh7, bl0, bl1, bl2, bl3, bl4, bl5, bl6, bl7, th, tl, i, j, h, l, a, b, c, d;
        var ah0 = hh[0], ah1 = hh[1], ah2 = hh[2], ah3 = hh[3], ah4 = hh[4], ah5 = hh[5], ah6 = hh[6], ah7 = hh[7], al0 = hl[0], al1 = hl[1], al2 = hl[2], al3 = hl[3], al4 = hl[4], al5 = hl[5], al6 = hl[6], al7 = hl[7];
        var pos = 0;
        while (n >= 128) {
          for (i = 0; i < 16; i++) {
            j = 8 * i + pos;
            wh[i] = m[j + 0] << 24 | m[j + 1] << 16 | m[j + 2] << 8 | m[j + 3];
            wl[i] = m[j + 4] << 24 | m[j + 5] << 16 | m[j + 6] << 8 | m[j + 7];
          }
          for (i = 0; i < 80; i++) {
            bh0 = ah0;
            bh1 = ah1;
            bh2 = ah2;
            bh3 = ah3;
            bh4 = ah4;
            bh5 = ah5;
            bh6 = ah6;
            bh7 = ah7;
            bl0 = al0;
            bl1 = al1;
            bl2 = al2;
            bl3 = al3;
            bl4 = al4;
            bl5 = al5;
            bl6 = al6;
            bl7 = al7;
            h = ah7;
            l = al7;
            a = l & 65535;
            b = l >>> 16;
            c = h & 65535;
            d = h >>> 16;
            h = (ah4 >>> 14 | al4 << 32 - 14) ^ (ah4 >>> 18 | al4 << 32 - 18) ^ (al4 >>> 41 - 32 | ah4 << 32 - (41 - 32));
            l = (al4 >>> 14 | ah4 << 32 - 14) ^ (al4 >>> 18 | ah4 << 32 - 18) ^ (ah4 >>> 41 - 32 | al4 << 32 - (41 - 32));
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            h = ah4 & ah5 ^ ~ah4 & ah6;
            l = al4 & al5 ^ ~al4 & al6;
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            h = K[i * 2];
            l = K[i * 2 + 1];
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            h = wh[i % 16];
            l = wl[i % 16];
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            th = c & 65535 | d << 16;
            tl = a & 65535 | b << 16;
            h = th;
            l = tl;
            a = l & 65535;
            b = l >>> 16;
            c = h & 65535;
            d = h >>> 16;
            h = (ah0 >>> 28 | al0 << 32 - 28) ^ (al0 >>> 34 - 32 | ah0 << 32 - (34 - 32)) ^ (al0 >>> 39 - 32 | ah0 << 32 - (39 - 32));
            l = (al0 >>> 28 | ah0 << 32 - 28) ^ (ah0 >>> 34 - 32 | al0 << 32 - (34 - 32)) ^ (ah0 >>> 39 - 32 | al0 << 32 - (39 - 32));
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            h = ah0 & ah1 ^ ah0 & ah2 ^ ah1 & ah2;
            l = al0 & al1 ^ al0 & al2 ^ al1 & al2;
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            bh7 = c & 65535 | d << 16;
            bl7 = a & 65535 | b << 16;
            h = bh3;
            l = bl3;
            a = l & 65535;
            b = l >>> 16;
            c = h & 65535;
            d = h >>> 16;
            h = th;
            l = tl;
            a += l & 65535;
            b += l >>> 16;
            c += h & 65535;
            d += h >>> 16;
            b += a >>> 16;
            c += b >>> 16;
            d += c >>> 16;
            bh3 = c & 65535 | d << 16;
            bl3 = a & 65535 | b << 16;
            ah1 = bh0;
            ah2 = bh1;
            ah3 = bh2;
            ah4 = bh3;
            ah5 = bh4;
            ah6 = bh5;
            ah7 = bh6;
            ah0 = bh7;
            al1 = bl0;
            al2 = bl1;
            al3 = bl2;
            al4 = bl3;
            al5 = bl4;
            al6 = bl5;
            al7 = bl6;
            al0 = bl7;
            if (i % 16 === 15) {
              for (j = 0; j < 16; j++) {
                h = wh[j];
                l = wl[j];
                a = l & 65535;
                b = l >>> 16;
                c = h & 65535;
                d = h >>> 16;
                h = wh[(j + 9) % 16];
                l = wl[(j + 9) % 16];
                a += l & 65535;
                b += l >>> 16;
                c += h & 65535;
                d += h >>> 16;
                th = wh[(j + 1) % 16];
                tl = wl[(j + 1) % 16];
                h = (th >>> 1 | tl << 32 - 1) ^ (th >>> 8 | tl << 32 - 8) ^ th >>> 7;
                l = (tl >>> 1 | th << 32 - 1) ^ (tl >>> 8 | th << 32 - 8) ^ (tl >>> 7 | th << 32 - 7);
                a += l & 65535;
                b += l >>> 16;
                c += h & 65535;
                d += h >>> 16;
                th = wh[(j + 14) % 16];
                tl = wl[(j + 14) % 16];
                h = (th >>> 19 | tl << 32 - 19) ^ (tl >>> 61 - 32 | th << 32 - (61 - 32)) ^ th >>> 6;
                l = (tl >>> 19 | th << 32 - 19) ^ (th >>> 61 - 32 | tl << 32 - (61 - 32)) ^ (tl >>> 6 | th << 32 - 6);
                a += l & 65535;
                b += l >>> 16;
                c += h & 65535;
                d += h >>> 16;
                b += a >>> 16;
                c += b >>> 16;
                d += c >>> 16;
                wh[j] = c & 65535 | d << 16;
                wl[j] = a & 65535 | b << 16;
              }
            }
          }
          h = ah0;
          l = al0;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[0];
          l = hl[0];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[0] = ah0 = c & 65535 | d << 16;
          hl[0] = al0 = a & 65535 | b << 16;
          h = ah1;
          l = al1;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[1];
          l = hl[1];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[1] = ah1 = c & 65535 | d << 16;
          hl[1] = al1 = a & 65535 | b << 16;
          h = ah2;
          l = al2;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[2];
          l = hl[2];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[2] = ah2 = c & 65535 | d << 16;
          hl[2] = al2 = a & 65535 | b << 16;
          h = ah3;
          l = al3;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[3];
          l = hl[3];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[3] = ah3 = c & 65535 | d << 16;
          hl[3] = al3 = a & 65535 | b << 16;
          h = ah4;
          l = al4;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[4];
          l = hl[4];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[4] = ah4 = c & 65535 | d << 16;
          hl[4] = al4 = a & 65535 | b << 16;
          h = ah5;
          l = al5;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[5];
          l = hl[5];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[5] = ah5 = c & 65535 | d << 16;
          hl[5] = al5 = a & 65535 | b << 16;
          h = ah6;
          l = al6;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[6];
          l = hl[6];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[6] = ah6 = c & 65535 | d << 16;
          hl[6] = al6 = a & 65535 | b << 16;
          h = ah7;
          l = al7;
          a = l & 65535;
          b = l >>> 16;
          c = h & 65535;
          d = h >>> 16;
          h = hh[7];
          l = hl[7];
          a += l & 65535;
          b += l >>> 16;
          c += h & 65535;
          d += h >>> 16;
          b += a >>> 16;
          c += b >>> 16;
          d += c >>> 16;
          hh[7] = ah7 = c & 65535 | d << 16;
          hl[7] = al7 = a & 65535 | b << 16;
          pos += 128;
          n -= 128;
        }
        return n;
      }
      function crypto_hash(out, m, n) {
        var hh = new Int32Array(8), hl = new Int32Array(8), x = new Uint8Array(256), i, b = n;
        hh[0] = 1779033703;
        hh[1] = 3144134277;
        hh[2] = 1013904242;
        hh[3] = 2773480762;
        hh[4] = 1359893119;
        hh[5] = 2600822924;
        hh[6] = 528734635;
        hh[7] = 1541459225;
        hl[0] = 4089235720;
        hl[1] = 2227873595;
        hl[2] = 4271175723;
        hl[3] = 1595750129;
        hl[4] = 2917565137;
        hl[5] = 725511199;
        hl[6] = 4215389547;
        hl[7] = 327033209;
        crypto_hashblocks_hl(hh, hl, m, n);
        n %= 128;
        for (i = 0; i < n; i++) x[i] = m[b - n + i];
        x[n] = 128;
        n = 256 - 128 * (n < 112 ? 1 : 0);
        x[n - 9] = 0;
        ts64(x, n - 8, b / 536870912 | 0, b << 3);
        crypto_hashblocks_hl(hh, hl, x, n);
        for (i = 0; i < 8; i++) ts64(out, 8 * i, hh[i], hl[i]);
        return 0;
      }
      function add(p, q) {
        var a = gf(), b = gf(), c = gf(), d = gf(), e = gf(), f = gf(), g = gf(), h = gf(), t = gf();
        Z(a, p[1], p[0]);
        Z(t, q[1], q[0]);
        M(a, a, t);
        A(b, p[0], p[1]);
        A(t, q[0], q[1]);
        M(b, b, t);
        M(c, p[3], q[3]);
        M(c, c, D2);
        M(d, p[2], q[2]);
        A(d, d, d);
        Z(e, b, a);
        Z(f, d, c);
        A(g, d, c);
        A(h, b, a);
        M(p[0], e, f);
        M(p[1], h, g);
        M(p[2], g, f);
        M(p[3], e, h);
      }
      function cswap(p, q, b) {
        var i;
        for (i = 0; i < 4; i++) {
          sel25519(p[i], q[i], b);
        }
      }
      function pack(r, p) {
        var tx = gf(), ty = gf(), zi = gf();
        inv25519(zi, p[2]);
        M(tx, p[0], zi);
        M(ty, p[1], zi);
        pack25519(r, ty);
        r[31] ^= par25519(tx) << 7;
      }
      function scalarmult(p, q, s) {
        var b, i;
        set25519(p[0], gf0);
        set25519(p[1], gf1);
        set25519(p[2], gf1);
        set25519(p[3], gf0);
        for (i = 255; i >= 0; --i) {
          b = s[i / 8 | 0] >> (i & 7) & 1;
          cswap(p, q, b);
          add(q, p);
          add(p, p);
          cswap(p, q, b);
        }
      }
      function scalarbase(p, s) {
        var q = [gf(), gf(), gf(), gf()];
        set25519(q[0], X);
        set25519(q[1], Y);
        set25519(q[2], gf1);
        M(q[3], X, Y);
        scalarmult(p, q, s);
      }
      function crypto_sign_keypair(pk, sk, seeded) {
        var d = new Uint8Array(64);
        var p = [gf(), gf(), gf(), gf()];
        var i;
        if (!seeded) randombytes(sk, 32);
        crypto_hash(d, sk, 32);
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;
        scalarbase(p, d);
        pack(pk, p);
        for (i = 0; i < 32; i++) sk[i + 32] = pk[i];
        return 0;
      }
      var L = new Float64Array([237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16]);
      function modL(r, x) {
        var carry, i, j, k;
        for (i = 63; i >= 32; --i) {
          carry = 0;
          for (j = i - 32, k = i - 12; j < k; ++j) {
            x[j] += carry - 16 * x[i] * L[j - (i - 32)];
            carry = Math.floor((x[j] + 128) / 256);
            x[j] -= carry * 256;
          }
          x[j] += carry;
          x[i] = 0;
        }
        carry = 0;
        for (j = 0; j < 32; j++) {
          x[j] += carry - (x[31] >> 4) * L[j];
          carry = x[j] >> 8;
          x[j] &= 255;
        }
        for (j = 0; j < 32; j++) x[j] -= carry * L[j];
        for (i = 0; i < 32; i++) {
          x[i + 1] += x[i] >> 8;
          r[i] = x[i] & 255;
        }
      }
      function reduce(r) {
        var x = new Float64Array(64), i;
        for (i = 0; i < 64; i++) x[i] = r[i];
        for (i = 0; i < 64; i++) r[i] = 0;
        modL(r, x);
      }
      function crypto_sign(sm, m, n, sk) {
        var d = new Uint8Array(64), h = new Uint8Array(64), r = new Uint8Array(64);
        var i, j, x = new Float64Array(64);
        var p = [gf(), gf(), gf(), gf()];
        crypto_hash(d, sk, 32);
        d[0] &= 248;
        d[31] &= 127;
        d[31] |= 64;
        var smlen = n + 64;
        for (i = 0; i < n; i++) sm[64 + i] = m[i];
        for (i = 0; i < 32; i++) sm[32 + i] = d[32 + i];
        crypto_hash(r, sm.subarray(32), n + 32);
        reduce(r);
        scalarbase(p, r);
        pack(sm, p);
        for (i = 32; i < 64; i++) sm[i] = sk[i];
        crypto_hash(h, sm, n + 64);
        reduce(h);
        for (i = 0; i < 64; i++) x[i] = 0;
        for (i = 0; i < 32; i++) x[i] = r[i];
        for (i = 0; i < 32; i++) {
          for (j = 0; j < 32; j++) {
            x[i + j] += h[i] * d[j];
          }
        }
        modL(sm.subarray(32), x);
        return smlen;
      }
      function unpackneg(r, p) {
        var t = gf(), chk = gf(), num = gf(), den = gf(), den2 = gf(), den4 = gf(), den6 = gf();
        set25519(r[2], gf1);
        unpack25519(r[1], p);
        S(num, r[1]);
        M(den, num, D);
        Z(num, num, r[2]);
        A(den, r[2], den);
        S(den2, den);
        S(den4, den2);
        M(den6, den4, den2);
        M(t, den6, num);
        M(t, t, den);
        pow2523(t, t);
        M(t, t, num);
        M(t, t, den);
        M(t, t, den);
        M(r[0], t, den);
        S(chk, r[0]);
        M(chk, chk, den);
        if (neq25519(chk, num)) M(r[0], r[0], I);
        S(chk, r[0]);
        M(chk, chk, den);
        if (neq25519(chk, num)) return -1;
        if (par25519(r[0]) === p[31] >> 7) Z(r[0], gf0, r[0]);
        M(r[3], r[0], r[1]);
        return 0;
      }
      function crypto_sign_open(m, sm, n, pk) {
        var i;
        var t = new Uint8Array(32), h = new Uint8Array(64);
        var p = [gf(), gf(), gf(), gf()], q = [gf(), gf(), gf(), gf()];
        if (n < 64) return -1;
        if (unpackneg(q, pk)) return -1;
        for (i = 0; i < n; i++) m[i] = sm[i];
        for (i = 0; i < 32; i++) m[i + 32] = pk[i];
        crypto_hash(h, m, n);
        reduce(h);
        scalarmult(p, q, h);
        scalarbase(q, sm.subarray(32));
        add(p, q);
        pack(t, p);
        n -= 64;
        if (crypto_verify_32(sm, 0, t, 0)) {
          for (i = 0; i < n; i++) m[i] = 0;
          return -1;
        }
        for (i = 0; i < n; i++) m[i] = sm[i + 64];
        return n;
      }
      var crypto_secretbox_KEYBYTES = 32, crypto_secretbox_NONCEBYTES = 24, crypto_secretbox_ZEROBYTES = 32, crypto_secretbox_BOXZEROBYTES = 16, crypto_scalarmult_BYTES = 32, crypto_scalarmult_SCALARBYTES = 32, crypto_box_PUBLICKEYBYTES = 32, crypto_box_SECRETKEYBYTES = 32, crypto_box_BEFORENMBYTES = 32, crypto_box_NONCEBYTES = crypto_secretbox_NONCEBYTES, crypto_box_ZEROBYTES = crypto_secretbox_ZEROBYTES, crypto_box_BOXZEROBYTES = crypto_secretbox_BOXZEROBYTES, crypto_sign_BYTES = 64, crypto_sign_PUBLICKEYBYTES = 32, crypto_sign_SECRETKEYBYTES = 64, crypto_sign_SEEDBYTES = 32, crypto_hash_BYTES = 64;
      nacl.lowlevel = {
        crypto_core_hsalsa20,
        crypto_stream_xor,
        crypto_stream,
        crypto_stream_salsa20_xor,
        crypto_stream_salsa20,
        crypto_onetimeauth,
        crypto_onetimeauth_verify,
        crypto_verify_16,
        crypto_verify_32,
        crypto_secretbox,
        crypto_secretbox_open,
        crypto_scalarmult,
        crypto_scalarmult_base,
        crypto_box_beforenm,
        crypto_box_afternm,
        crypto_box,
        crypto_box_open,
        crypto_box_keypair,
        crypto_hash,
        crypto_sign,
        crypto_sign_keypair,
        crypto_sign_open,
        crypto_secretbox_KEYBYTES,
        crypto_secretbox_NONCEBYTES,
        crypto_secretbox_ZEROBYTES,
        crypto_secretbox_BOXZEROBYTES,
        crypto_scalarmult_BYTES,
        crypto_scalarmult_SCALARBYTES,
        crypto_box_PUBLICKEYBYTES,
        crypto_box_SECRETKEYBYTES,
        crypto_box_BEFORENMBYTES,
        crypto_box_NONCEBYTES,
        crypto_box_ZEROBYTES,
        crypto_box_BOXZEROBYTES,
        crypto_sign_BYTES,
        crypto_sign_PUBLICKEYBYTES,
        crypto_sign_SECRETKEYBYTES,
        crypto_sign_SEEDBYTES,
        crypto_hash_BYTES,
        gf,
        D,
        L,
        pack25519,
        unpack25519,
        M,
        A,
        S,
        Z,
        pow2523,
        add,
        set25519,
        modL,
        scalarmult,
        scalarbase
      };
      function checkLengths(k, n) {
        if (k.length !== crypto_secretbox_KEYBYTES) throw new Error("bad key size");
        if (n.length !== crypto_secretbox_NONCEBYTES) throw new Error("bad nonce size");
      }
      function checkBoxLengths(pk, sk) {
        if (pk.length !== crypto_box_PUBLICKEYBYTES) throw new Error("bad public key size");
        if (sk.length !== crypto_box_SECRETKEYBYTES) throw new Error("bad secret key size");
      }
      function checkArrayTypes() {
        for (var i = 0; i < arguments.length; i++) {
          if (!(arguments[i] instanceof Uint8Array))
            throw new TypeError("unexpected type, use Uint8Array");
        }
      }
      function cleanup(arr) {
        for (var i = 0; i < arr.length; i++) arr[i] = 0;
      }
      nacl.randomBytes = function(n) {
        var b = new Uint8Array(n);
        randombytes(b, n);
        return b;
      };
      nacl.secretbox = function(msg, nonce, key) {
        checkArrayTypes(msg, nonce, key);
        checkLengths(key, nonce);
        var m = new Uint8Array(crypto_secretbox_ZEROBYTES + msg.length);
        var c = new Uint8Array(m.length);
        for (var i = 0; i < msg.length; i++) m[i + crypto_secretbox_ZEROBYTES] = msg[i];
        crypto_secretbox(c, m, m.length, nonce, key);
        return c.subarray(crypto_secretbox_BOXZEROBYTES);
      };
      nacl.secretbox.open = function(box, nonce, key) {
        checkArrayTypes(box, nonce, key);
        checkLengths(key, nonce);
        var c = new Uint8Array(crypto_secretbox_BOXZEROBYTES + box.length);
        var m = new Uint8Array(c.length);
        for (var i = 0; i < box.length; i++) c[i + crypto_secretbox_BOXZEROBYTES] = box[i];
        if (c.length < 32) return null;
        if (crypto_secretbox_open(m, c, c.length, nonce, key) !== 0) return null;
        return m.subarray(crypto_secretbox_ZEROBYTES);
      };
      nacl.secretbox.keyLength = crypto_secretbox_KEYBYTES;
      nacl.secretbox.nonceLength = crypto_secretbox_NONCEBYTES;
      nacl.secretbox.overheadLength = crypto_secretbox_BOXZEROBYTES;
      nacl.scalarMult = function(n, p) {
        checkArrayTypes(n, p);
        if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error("bad n size");
        if (p.length !== crypto_scalarmult_BYTES) throw new Error("bad p size");
        var q = new Uint8Array(crypto_scalarmult_BYTES);
        crypto_scalarmult(q, n, p);
        return q;
      };
      nacl.scalarMult.base = function(n) {
        checkArrayTypes(n);
        if (n.length !== crypto_scalarmult_SCALARBYTES) throw new Error("bad n size");
        var q = new Uint8Array(crypto_scalarmult_BYTES);
        crypto_scalarmult_base(q, n);
        return q;
      };
      nacl.scalarMult.scalarLength = crypto_scalarmult_SCALARBYTES;
      nacl.scalarMult.groupElementLength = crypto_scalarmult_BYTES;
      nacl.box = function(msg, nonce, publicKey, secretKey) {
        var k = nacl.box.before(publicKey, secretKey);
        return nacl.secretbox(msg, nonce, k);
      };
      nacl.box.before = function(publicKey, secretKey) {
        checkArrayTypes(publicKey, secretKey);
        checkBoxLengths(publicKey, secretKey);
        var k = new Uint8Array(crypto_box_BEFORENMBYTES);
        crypto_box_beforenm(k, publicKey, secretKey);
        return k;
      };
      nacl.box.after = nacl.secretbox;
      nacl.box.open = function(msg, nonce, publicKey, secretKey) {
        var k = nacl.box.before(publicKey, secretKey);
        return nacl.secretbox.open(msg, nonce, k);
      };
      nacl.box.open.after = nacl.secretbox.open;
      nacl.box.keyPair = function() {
        var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
        var sk = new Uint8Array(crypto_box_SECRETKEYBYTES);
        crypto_box_keypair(pk, sk);
        return { publicKey: pk, secretKey: sk };
      };
      nacl.box.keyPair.fromSecretKey = function(secretKey) {
        checkArrayTypes(secretKey);
        if (secretKey.length !== crypto_box_SECRETKEYBYTES)
          throw new Error("bad secret key size");
        var pk = new Uint8Array(crypto_box_PUBLICKEYBYTES);
        crypto_scalarmult_base(pk, secretKey);
        return { publicKey: pk, secretKey: new Uint8Array(secretKey) };
      };
      nacl.box.publicKeyLength = crypto_box_PUBLICKEYBYTES;
      nacl.box.secretKeyLength = crypto_box_SECRETKEYBYTES;
      nacl.box.sharedKeyLength = crypto_box_BEFORENMBYTES;
      nacl.box.nonceLength = crypto_box_NONCEBYTES;
      nacl.box.overheadLength = nacl.secretbox.overheadLength;
      nacl.sign = function(msg, secretKey) {
        checkArrayTypes(msg, secretKey);
        if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
          throw new Error("bad secret key size");
        var signedMsg = new Uint8Array(crypto_sign_BYTES + msg.length);
        crypto_sign(signedMsg, msg, msg.length, secretKey);
        return signedMsg;
      };
      nacl.sign.open = function(signedMsg, publicKey) {
        checkArrayTypes(signedMsg, publicKey);
        if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
          throw new Error("bad public key size");
        var tmp = new Uint8Array(signedMsg.length);
        var mlen = crypto_sign_open(tmp, signedMsg, signedMsg.length, publicKey);
        if (mlen < 0) return null;
        var m = new Uint8Array(mlen);
        for (var i = 0; i < m.length; i++) m[i] = tmp[i];
        return m;
      };
      nacl.sign.detached = function(msg, secretKey) {
        var signedMsg = nacl.sign(msg, secretKey);
        var sig = new Uint8Array(crypto_sign_BYTES);
        for (var i = 0; i < sig.length; i++) sig[i] = signedMsg[i];
        return sig;
      };
      nacl.sign.detached.verify = function(msg, sig, publicKey) {
        checkArrayTypes(msg, sig, publicKey);
        if (sig.length !== crypto_sign_BYTES)
          throw new Error("bad signature size");
        if (publicKey.length !== crypto_sign_PUBLICKEYBYTES)
          throw new Error("bad public key size");
        var sm = new Uint8Array(crypto_sign_BYTES + msg.length);
        var m = new Uint8Array(crypto_sign_BYTES + msg.length);
        var i;
        for (i = 0; i < crypto_sign_BYTES; i++) sm[i] = sig[i];
        for (i = 0; i < msg.length; i++) sm[i + crypto_sign_BYTES] = msg[i];
        return crypto_sign_open(m, sm, sm.length, publicKey) >= 0;
      };
      nacl.sign.keyPair = function() {
        var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
        var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
        crypto_sign_keypair(pk, sk);
        return { publicKey: pk, secretKey: sk };
      };
      nacl.sign.keyPair.fromSecretKey = function(secretKey) {
        checkArrayTypes(secretKey);
        if (secretKey.length !== crypto_sign_SECRETKEYBYTES)
          throw new Error("bad secret key size");
        var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
        for (var i = 0; i < pk.length; i++) pk[i] = secretKey[32 + i];
        return { publicKey: pk, secretKey: new Uint8Array(secretKey) };
      };
      nacl.sign.keyPair.fromSeed = function(seed) {
        checkArrayTypes(seed);
        if (seed.length !== crypto_sign_SEEDBYTES)
          throw new Error("bad seed size");
        var pk = new Uint8Array(crypto_sign_PUBLICKEYBYTES);
        var sk = new Uint8Array(crypto_sign_SECRETKEYBYTES);
        for (var i = 0; i < 32; i++) sk[i] = seed[i];
        crypto_sign_keypair(pk, sk, true);
        return { publicKey: pk, secretKey: sk };
      };
      nacl.sign.publicKeyLength = crypto_sign_PUBLICKEYBYTES;
      nacl.sign.secretKeyLength = crypto_sign_SECRETKEYBYTES;
      nacl.sign.seedLength = crypto_sign_SEEDBYTES;
      nacl.sign.signatureLength = crypto_sign_BYTES;
      nacl.hash = function(msg) {
        checkArrayTypes(msg);
        var h = new Uint8Array(crypto_hash_BYTES);
        crypto_hash(h, msg, msg.length);
        return h;
      };
      nacl.hash.hashLength = crypto_hash_BYTES;
      nacl.verify = function(x, y) {
        checkArrayTypes(x, y);
        if (x.length === 0 || y.length === 0) return false;
        if (x.length !== y.length) return false;
        return vn(x, 0, y, 0, x.length) === 0 ? true : false;
      };
      nacl.setPRNG = function(fn) {
        randombytes = fn;
      };
      (function() {
        var crypto = typeof self !== "undefined" ? self.crypto || self.msCrypto : null;
        if (crypto && crypto.getRandomValues) {
          var QUOTA = 65536;
          nacl.setPRNG(function(x, n) {
            var i, v = new Uint8Array(n);
            for (i = 0; i < n; i += QUOTA) {
              crypto.getRandomValues(v.subarray(i, i + Math.min(n - i, QUOTA)));
            }
            for (i = 0; i < n; i++) x[i] = v[i];
            cleanup(v);
          });
        } else if (typeof __require !== "undefined") {
          crypto = null; /* require("crypto") stripped: verify-only, no PRNG in QuickJS */
          if (crypto && crypto.randomBytes) {
            nacl.setPRNG(function(x, n) {
              var i, v = crypto.randomBytes(n);
              for (i = 0; i < n; i++) x[i] = v[i];
              cleanup(v);
            });
          }
        }
      })();
    })(typeof module !== "undefined" && module.exports ? module.exports : self.nacl = self.nacl || {});
  }
});
export default require_nacl_fast();
