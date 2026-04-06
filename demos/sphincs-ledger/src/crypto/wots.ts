// WOTS+ (Winternitz One-Time Signature) — Simplified Demonstration
// This is an ILLUSTRATIVE implementation showing the hash-chain concept,
// NOT a production WOTS+ implementation.
// Reference: NIST FIPS 205, Section 4 — WOTS+ one-time signatures
// https://csrc.nist.gov/pubs/fips/205/final

import { sha256, sha256Hex } from './hash';

// Winternitz parameter w=16 for illustration
export const W = 16;

export interface WotsChain {
  privateKey: Uint8Array;     // random 32-byte seed
  publicKey: Uint8Array;      // SHA-256^W(privateKey)
  chainLength: number;        // W iterations
  chainValues: Uint8Array[];  // all intermediate values for visualization
}

export interface WotsKeyPair {
  chains: WotsChain[];
  signedMessages: string[];   // track messages signed with this key
}

export async function buildChain(seed: Uint8Array, steps: number): Promise<Uint8Array[]> {
  const chain: Uint8Array[] = [seed];
  let current = seed;
  for (let i = 0; i < steps; i++) {
    current = await sha256(current);
    chain.push(current);
  }
  return chain;
}

export async function generateWotsKeyPair(numChains: number = 4): Promise<WotsKeyPair> {
  const chains: WotsChain[] = [];
  for (let i = 0; i < numChains; i++) {
    const privateKey = crypto.getRandomValues(new Uint8Array(32));
    const chainValues = await buildChain(privateKey, W);
    chains.push({
      privateKey,
      publicKey: chainValues[chainValues.length - 1],
      chainLength: W,
      chainValues,
    });
  }
  return { chains, signedMessages: [] };
}

export interface WotsSignatureResult {
  chainIndex: number;
  revealedStep: number;
  revealedValue: Uint8Array;
  stepsToPublicKey: number;
}

export function wotsSign(
  keyPair: WotsKeyPair,
  messageNibble: number,
  chainIndex: number
): WotsSignatureResult {
  // In real WOTS+, each nibble of the message hash determines how far
  // up the chain to reveal. For illustration, we use the nibble directly.
  const step = messageNibble % W;
  const chain = keyPair.chains[chainIndex];
  return {
    chainIndex,
    revealedStep: step,
    revealedValue: chain.chainValues[step],
    stepsToPublicKey: W - step,
  };
}

export async function wotsVerify(
  publicKey: Uint8Array,
  sigResult: WotsSignatureResult
): Promise<boolean> {
  // Hash forward from the revealed value to see if we reach the public key
  let current = sigResult.revealedValue;
  for (let i = 0; i < sigResult.stepsToPublicKey; i++) {
    current = await sha256(current);
  }
  // Compare
  if (current.length !== publicKey.length) return false;
  for (let i = 0; i < current.length; i++) {
    if (current[i] !== publicKey[i]) return false;
  }
  return true;
}

export function checkReuseWarning(
  keyPair: WotsKeyPair,
  newMessage: string
): { isReuse: boolean; warning: string; exposedChains: number[] } {
  if (keyPair.signedMessages.length === 0) {
    return { isReuse: false, warning: '', exposedChains: [] };
  }
  if (keyPair.signedMessages.includes(newMessage)) {
    return { isReuse: false, warning: '', exposedChains: [] }; // Same message is safe
  }
  // Different message with same key = reuse!
  const exposedChains = keyPair.chains.map((_, i) => i);
  return {
    isReuse: true,
    warning: `WOTS+ KEY REUSE DETECTED: Signing a second distinct message with the same one-time key exposes private key material. Each signature reveals a point on the hash chain — two different messages reveal two different points, allowing an attacker to forge signatures for other messages. In SPHINCS+, the hypertree structure prevents this by using each WOTS+ key exactly once.`,
    exposedChains,
  };
}

export async function getChainHexValues(chain: WotsChain): Promise<string[]> {
  return Promise.all(chain.chainValues.map((v) => sha256Hex(v).then(() =>
    Array.from(v).map((b) => b.toString(16).padStart(2, '0')).join('')
  )));
}
