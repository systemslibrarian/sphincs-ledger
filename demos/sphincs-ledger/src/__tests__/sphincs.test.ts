// SPHINCS+ / SLH-DSA test suite
// Tests: keygen → sign → verify round-trip, single-byte tamper detection
// Run via: npx tsx src/__tests__/sphincs.test.ts (or import in a test runner)

import {
  generateKeyPair,
  sign,
  verify,
  PARAM_SIZES,
  type SphincsParamSet,
} from '../crypto/sphincs.js';

const PARAM_SETS: SphincsParamSet[] = ['sha2-128f', 'sha2-128s', 'sha2-256f', 'sha2-256s'];

async function test(name: string, fn: () => Promise<void>) {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    console.error(`  ✗ ${name}: ${msg}`);
    process.exitCode = 1;
  }
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

async function runTests() {
  // Test only sha2-128f by default for speed; pass --all for all param sets
  const paramSets = process.argv.includes('--all') ? PARAM_SETS : (['sha2-128f'] as SphincsParamSet[]);

  for (const params of paramSets) {
    console.log(`\nParameter set: ${params}`);
    const sizes = PARAM_SIZES[params];

    await test('generate keypair with correct sizes', async () => {
      const kp = await generateKeyPair(params);
      assert(kp.publicKey.length === sizes.publicKey,
        `public key: expected ${sizes.publicKey}, got ${kp.publicKey.length}`);
      assert(kp.privateKey.length === sizes.privateKey,
        `private key: expected ${sizes.privateKey}, got ${kp.privateKey.length}`);
      assert(kp.paramSet === params, 'paramSet mismatch');
    });

    await test('sign → verify → true', async () => {
      const kp = await generateKeyPair(params);
      const msg = new TextEncoder().encode('test message');
      const sig = await sign(kp.privateKey, msg, params);
      assert(sig.length === sizes.signature,
        `signature: expected ${sizes.signature}, got ${sig.length}`);
      const valid = await verify(kp.publicKey, msg, sig, params);
      assert(valid === true, 'expected verify to return true');
    });

    await test('flip byte in signature → verify → false', async () => {
      const kp = await generateKeyPair(params);
      const msg = new TextEncoder().encode('test message');
      const sig = await sign(kp.privateKey, msg, params);
      const tampered = new Uint8Array(sig);
      tampered[0] ^= 0x01;
      const valid = await verify(kp.publicKey, msg, tampered, params);
      assert(valid === false, 'expected verify to return false after signature tamper');
    });

    await test('flip byte in message → verify → false', async () => {
      const kp = await generateKeyPair(params);
      const msg = new TextEncoder().encode('test message');
      const sig = await sign(kp.privateKey, msg, params);
      const tamperedMsg = new TextEncoder().encode('Test message'); // capital T
      const valid = await verify(kp.publicKey, tamperedMsg, sig, params);
      assert(valid === false, 'expected verify to return false after message tamper');
    });
  }

  console.log('\nAll tests passed.');
}

runTests();
