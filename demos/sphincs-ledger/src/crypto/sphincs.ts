// SPHINCS+ / SLH-DSA wrapper using @noble/post-quantum v0.6.0
// Specification: NIST FIPS 205 — https://csrc.nist.gov/pubs/fips/205/final
// SPHINCS+ submission: https://sphincs.org/data/sphincs+-r3.1-specification.pdf
// Package: https://www.npmjs.com/package/@noble/post-quantum

import {
  slh_dsa_sha2_128f,
  slh_dsa_sha2_128s,
  slh_dsa_sha2_256f,
  slh_dsa_sha2_256s,
} from '@noble/post-quantum/slh-dsa.js';

export type SphincsParamSet = 'sha2-128f' | 'sha2-128s' | 'sha2-256f' | 'sha2-256s';

export interface SphincsKeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  paramSet: SphincsParamSet;
}

export interface SphincsSignature {
  signature: Uint8Array;
  message: Uint8Array;
  paramSet: SphincsParamSet;
}

export const PARAM_SIZES: Record<SphincsParamSet, {
  publicKey: number;
  privateKey: number;
  signature: number;
  security: number;
}> = {
  'sha2-128f': { publicKey: 32, privateKey: 64, signature: 17088, security: 128 },
  'sha2-128s': { publicKey: 32, privateKey: 64, signature: 7856, security: 128 },
  'sha2-256f': { publicKey: 64, privateKey: 128, signature: 49856, security: 256 },
  'sha2-256s': { publicKey: 64, privateKey: 128, signature: 29792, security: 256 },
};

function getImpl(params: SphincsParamSet) {
  switch (params) {
    case 'sha2-128f': return slh_dsa_sha2_128f;
    case 'sha2-128s': return slh_dsa_sha2_128s;
    case 'sha2-256f': return slh_dsa_sha2_256f;
    case 'sha2-256s': return slh_dsa_sha2_256s;
  }
}

export async function generateKeyPair(params: SphincsParamSet): Promise<SphincsKeyPair> {
  const impl = getImpl(params);
  const keys = impl.keygen();
  return {
    publicKey: keys.publicKey,
    privateKey: keys.secretKey,
    paramSet: params,
  };
}

export async function sign(
  privateKey: Uint8Array,
  message: Uint8Array,
  params: SphincsParamSet
): Promise<Uint8Array> {
  const impl = getImpl(params);
  return impl.sign(message, privateKey);
}

export async function verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
  params: SphincsParamSet
): Promise<boolean> {
  const impl = getImpl(params);
  try {
    return impl.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}
