# crypto-lab-sphincs-ledger

## What It Is

This project is a browser demo of SLH-DSA (SPHINCS+), with supporting SHA-256 Merkle tree and WOTS+ visualizations that make the signing flow easier to inspect. SLH-DSA solves the digital-signature problem: a signer produces a public verifiable proof that a message came from the holder of the private key and was not modified. The scheme is an asymmetric, hash-based, post-quantum signature system standardized in NIST FIPS 205. In this demo, the security story is presented honestly: the production signing path is SLH-DSA, while the Merkle tree and WOTS+ tabs are educational views of the primitives beneath it.

## When to Use It

- Use it for long-lived software releases or archive signatures when conservative post-quantum assurances matter more than compact signatures.
- Use it for offline or low-frequency signing workflows because SLH-DSA trades very large signatures for a hash-only security foundation.
- Use it for teaching or internal reviews when you need to show how SHA-256 Merkle trees, WOTS+, and SLH-DSA fit together in one place.
- Do not use it for bandwidth-sensitive or latency-sensitive protocols because the signature sizes in the implemented parameter sets are much larger than RSA, Ed25519, or ML-DSA.

## Live Demo

Live demo: [https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/](https://systemslibrarian.github.io/crypto-lab-sphincs-ledger/)

The demo lets you generate keys, sign messages, verify signatures, inspect a SHA-256 Merkle tree authentication path, experiment with a WOTS+ chain reveal, and append signed entries to a browser-side ledger. The main controls are the Parameter set selector, Message to sign textarea, Number of leaves selector, Message nibble input, and Chain index input.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-sphincs-ledger.git
cd crypto-lab-sphincs-ledger/demos/sphincs-ledger
npm install
npm run dev
```

No environment variables are required.

## Part of the Crypto-Lab Suite

This demo is one part of the broader Crypto-Lab suite at [https://systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).

Whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31