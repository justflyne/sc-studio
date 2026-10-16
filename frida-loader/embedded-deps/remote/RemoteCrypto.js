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
