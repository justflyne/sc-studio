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
