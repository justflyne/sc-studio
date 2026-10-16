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
