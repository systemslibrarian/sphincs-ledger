# sphincs-ledger

**SLH-DSA (SPHINCS+)** — Browser-based cryptographic demo showcasing hash-based digital signatures standardized as [NIST FIPS 205](https://csrc.nist.gov/pubs/fips/205/final).

Part of the [crypto-compare](https://github.com/systemslibrarian/crypto-compare) portfolio.

**[Live Demo →](https://systemslibrarian.github.io/sphincs-ledger/)**

## Post-Quantum Signatures

| Field | Value |
|---|---|
| Scheme | SLH-DSA (SPHINCS+) |
| Standard | NIST FIPS 205 |
| Hash function | SHA-256 / SHA-512 |
| Security assumption | Hash function collision resistance only |
| Quantum resistance | Yes — Grover reduces to 128-bit minimum |
| Signature sizes | 7,856 – 49,856 bytes depending on parameter set |
| Authors | Bernstein, Hülsing, Kölbl, Niederhagen, Rijneveld, Schwabe |
| Year standardized | 2024 |
| Key property | No algebraic structure — most conservative PQC assumption |

## Quick Start

```bash
cd demos/sphincs-ledger
npm install
npm run dev
```

## Cross-References

- **[ratchet-wire](https://github.com/systemslibrarian/crypto-compare):** SPHINCS+ could sign the initial X3DH pre-keys for a fully post-quantum messaging handshake.
- **[quantum-vault-kpqc](https://github.com/systemslibrarian/crypto-compare):** Korean KpqC (HAETAE) is a lattice-based alternative occupying a similar role to ML-DSA, while SPHINCS+ occupies a distinct hash-only niche.

## Demo Details

See [demos/sphincs-ledger/README.md](demos/sphincs-ledger/README.md) for full documentation.