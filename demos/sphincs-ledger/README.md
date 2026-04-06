# sphincs-ledger

Browser-based cryptographic demo for **SLH-DSA (SPHINCS+)** — the hash-based signature scheme standardized as [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

Part of the [crypto-compare](https://github.com/systemslibrarian/crypto-compare) portfolio.

## What This Demo Shows

1. **Hash-only security** — SPHINCS+ security reduces entirely to SHA-256 collision resistance. No algebraic assumptions (factoring, discrete log, lattice problems).
2. **Merkle tree mechanics** — Real SHA-256 Merkle trees built and verified in the browser, with authentication path visualization and step-by-step root recomputation.
3. **WOTS+ one-time property** — Simplified Winternitz hash-chain demonstration showing why keys must only be used once, with a reuse warning when a second distinct message is signed.
4. **Ledger signing** — Append-only ledger of SPHINCS+ signed entries with tamper detection. Each entry generates a fresh keypair — no shared keys or PKI required.
5. **Parameter set comparison** — All four SHA-2 parameter sets (128f, 128s, 256f, 256s) with measured signing times and size comparisons against RSA, Ed25519, and ML-DSA.

## Run Locally

```bash
cd demos/sphincs-ledger
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

## Build

```bash
npm run build
```

Output goes to `dist/`. The demo runs fully offline — no external CDN dependencies at runtime.

## SPHINCS+ Implementation

- **Package:** [`@noble/post-quantum`](https://www.npmjs.com/package/@noble/post-quantum) v0.6.0 by Paul Miller
- **Import:** `@noble/post-quantum/slh-dsa.js`
- **Functions:** `keygen()`, `sign(msg, secretKey)`, `verify(sig, msg, publicKey)`

## Parameter Set Reference (NIST FIPS 205 Table 1)

| Parameter Set | Public Key | Private Key | Signature | Security Level |
|---|---|---|---|---|
| SLH-DSA-SHA2-128f | 32 B | 64 B | 17,088 B | 128-bit |
| SLH-DSA-SHA2-128s | 32 B | 64 B | 7,856 B | 128-bit |
| SLH-DSA-SHA2-256f | 64 B | 128 B | 49,856 B | 256-bit |
| SLH-DSA-SHA2-256s | 64 B | 128 B | 29,792 B | 256-bit |

- **f (fast):** Larger signatures, faster signing
- **s (small):** Smaller signatures, slower signing

## What Is Illustrative vs Production

| Component | Status |
|---|---|
| SPHINCS+ sign/verify (`@noble/post-quantum`) | **Production** — audited library implementing FIPS 205 |
| SHA-256 hashing (Web Crypto API) | **Production** — browser-native implementation |
| Merkle tree visualization | **Illustrative** — real SHA-256, simplified structure (up to 16 leaves) |
| WOTS+ chain demonstration | **Illustrative** — shows hash-chain concept, not full WOTS+ spec |
| Ledger | **Demo** — sessionStorage persistence, no consensus or networking |

## Stack

| Layer | Choice |
|---|---|
| Frontend | Vite + TypeScript |
| SPHINCS+ | `@noble/post-quantum` (FIPS 205) |
| Hash function | SHA-256 via Web Crypto API |
| Visualization | SVG — vanilla TypeScript |
| UI | Vanilla TypeScript — no framework |

## Specification References

- [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) — SLH-DSA standard
- [SPHINCS+ specification v3.1](https://sphincs.org/data/sphincs+-r3.1-specification.pdf)
- [sphincs.org](https://sphincs.org)

## Cross-References

- **[ratchet-wire](https://github.com/systemslibrarian/crypto-compare):** SPHINCS+ could sign the initial X3DH pre-keys for a fully post-quantum messaging handshake.
- **[quantum-vault-kpqc](https://github.com/systemslibrarian/crypto-compare):** Korean KpqC (HAETAE) is a lattice-based alternative occupying a similar role to ML-DSA, while SPHINCS+ occupies a distinct hash-only niche.
