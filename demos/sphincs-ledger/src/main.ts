import './styles.css';
import {
  generateKeyPair,
  sign,
  verify,
  PARAM_SIZES,
  type SphincsParamSet,
  type SphincsKeyPair,
} from './crypto/sphincs';
import { bytesToHex, sha256Hex } from './crypto/hash';
import { buildMerkleTree, getAuthPath, verifyAuthPath } from './crypto/merkle';
import { renderMerkleTree, animateAuthPath } from './visualization/tree';
import {
  generateWotsKeyPair,
  wotsSign,
  wotsVerify,
  checkReuseWarning,
  type WotsKeyPair,
  type WotsSignatureResult,
} from './crypto/wots';
import { renderWotsChain } from './visualization/wots-chain';
import { Ledger } from './ledger/ledger';

// ─── Speed tracking ───
const speedRecords: Record<string, number[]> = {};

function recordSpeed(paramSet: string, ms: number) {
  if (!speedRecords[paramSet]) speedRecords[paramSet] = [];
  speedRecords[paramSet].push(ms);
  renderSpeedChart();
}

// ─── Tab switching ───
document.querySelectorAll<HTMLButtonElement>('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => {
      t.classList.remove('active');
      t.setAttribute('aria-selected', 'false');
    });
    document.querySelectorAll('.tab-panel').forEach((p) => {
      p.classList.remove('active');
      p.classList.add('hidden');
    });
    btn.classList.add('active');
    btn.setAttribute('aria-selected', 'true');
    const panel = document.getElementById(`tab-${btn.dataset.tab}`);
    if (panel) {
      panel.classList.add('active');
      panel.classList.remove('hidden');
    }
  });
});

// ─── TAB 1: Sign & Verify ───
const paramSelect = document.getElementById('param-select') as HTMLSelectElement;
const paramInfo = document.getElementById('param-info')!;
const messageInput = document.getElementById('message-input') as HTMLTextAreaElement;
const btnGenerate = document.getElementById('btn-generate') as HTMLButtonElement;
const signSpinner = document.getElementById('sign-spinner')!;
const signOutput = document.getElementById('sign-output')!;
const btnVerify = document.getElementById('btn-verify') as HTMLButtonElement;
const verifyOutput = document.getElementById('verify-output')!;
const btnTamperSig = document.getElementById('btn-tamper-sig') as HTMLButtonElement;
const btnTamperMsg = document.getElementById('btn-tamper-msg') as HTMLButtonElement;
const tamperOutput = document.getElementById('tamper-output')!;

let currentKeyPair: SphincsKeyPair | null = null;
let currentSignature: Uint8Array | null = null;
let currentMessage: Uint8Array | null = null;
let currentParamSet: SphincsParamSet = 'sha2-128f';

function updateParamInfo() {
  currentParamSet = paramSelect.value as SphincsParamSet;
  const p = PARAM_SIZES[currentParamSet];
  paramInfo.innerHTML = `
    <span class="label">Public key</span><span class="value">${p.publicKey} bytes</span>
    <span class="label">Private key</span><span class="value">${p.privateKey} bytes</span>
    <span class="label">Signature</span><span class="value">${p.signature.toLocaleString()} bytes</span>
    <span class="label">Security level</span><span class="value">${p.security}-bit</span>
  `;
}
paramSelect.addEventListener('change', updateParamInfo);
updateParamInfo();

btnGenerate.addEventListener('click', async () => {
  const params = paramSelect.value as SphincsParamSet;
  currentParamSet = params;
  const msg = new TextEncoder().encode(messageInput.value);

  signSpinner.classList.remove('hidden');
  signOutput.classList.add('hidden');
  btnGenerate.disabled = true;

  try {
    const t0 = performance.now();
    const keyPair = await generateKeyPair(params);
    const tKeygen = performance.now() - t0;

    const t1 = performance.now();
    const sig = await sign(keyPair.privateKey, msg, params);
    const tSign = performance.now() - t1;

    currentKeyPair = keyPair;
    currentSignature = sig;
    currentMessage = msg;

    recordSpeed(params, tSign);

    signOutput.innerHTML =
      `<strong>Keygen:</strong> ${tKeygen.toFixed(1)} ms\n` +
      `<strong>Signing:</strong> ${tSign.toFixed(1)} ms\n\n` +
      `<strong>Public key (${keyPair.publicKey.length} B):</strong>\n${bytesToHex(keyPair.publicKey).substring(0, 64)}…\n\n` +
      `<strong>Private key (${keyPair.privateKey.length} B):</strong> <span style="color:#fca5a5">[never transmitted]</span>\n${bytesToHex(keyPair.privateKey).substring(0, 64)}…\n\n` +
      `<strong>Signature (${sig.length.toLocaleString()} B):</strong>\n${bytesToHex(sig).substring(0, 80)}…`;
    signOutput.classList.remove('hidden');

    btnVerify.disabled = false;
    btnTamperSig.disabled = false;
    btnTamperMsg.disabled = false;
    verifyOutput.classList.add('hidden');
    tamperOutput.classList.add('hidden');
  } catch (e: unknown) {
    const msg2 = e instanceof Error ? e.message : String(e);
    signOutput.innerHTML = `<span style="color:#fca5a5">Error: ${msg2}</span>`;
    signOutput.classList.remove('hidden');
  } finally {
    signSpinner.classList.add('hidden');
    btnGenerate.disabled = false;
  }
});

btnVerify.addEventListener('click', async () => {
  if (!currentKeyPair || !currentSignature || !currentMessage) return;
  const t0 = performance.now();
  const valid = await verify(currentKeyPair.publicKey, currentMessage, currentSignature, currentParamSet);
  const elapsed = performance.now() - t0;
  verifyOutput.innerHTML = valid
    ? `<span class="badge badge-valid">VERIFIED</span> in ${elapsed.toFixed(1)} ms — the signature is authentic.`
    : `<span class="badge badge-invalid">FAILED</span> in ${elapsed.toFixed(1)} ms — verification rejected.`;
  verifyOutput.classList.remove('hidden');
});

btnTamperSig.addEventListener('click', async () => {
  if (!currentKeyPair || !currentSignature || !currentMessage) return;
  const tampered = new Uint8Array(currentSignature);
  tampered[0] ^= 0x01; // flip one bit of the first byte
  const valid = await verify(currentKeyPair.publicKey, currentMessage, tampered, currentParamSet);
  tamperOutput.innerHTML = valid
    ? `<span class="badge badge-valid">VERIFIED</span> — unexpected!`
    : `<span class="badge badge-invalid">REJECTED</span> — flipped 1 byte in signature (byte[0] XOR 0x01). SHA-256 digest mismatch causes SPHINCS+ verification to fail.`;
  tamperOutput.classList.remove('hidden');
});

btnTamperMsg.addEventListener('click', async () => {
  if (!currentKeyPair || !currentSignature || !currentMessage) return;
  const tampered = new Uint8Array(currentMessage);
  tampered[0] ^= 0x01;
  const valid = await verify(currentKeyPair.publicKey, tampered, currentSignature!, currentParamSet);
  tamperOutput.innerHTML = valid
    ? `<span class="badge badge-valid">VERIFIED</span> — unexpected!`
    : `<span class="badge badge-invalid">REJECTED</span> — flipped 1 byte in message (byte[0] XOR 0x01). The modified message hashes to a different SHA-256 digest, which does not match the signed digest.`;
  tamperOutput.classList.remove('hidden');
});

// ─── TAB 2: Merkle Tree ───
const treeLeavesSelect = document.getElementById('tree-leaves') as HTMLSelectElement;
const btnBuildTree = document.getElementById('btn-build-tree') as HTMLButtonElement;
const leafSelect = document.getElementById('leaf-select') as HTMLSelectElement;
const btnVerifyLeaf = document.getElementById('btn-verify-leaf') as HTMLButtonElement;
const treeContainer = document.getElementById('tree-container')!;
const treeVerifyOutput = document.getElementById('tree-verify-output')!;

let treeLeaves: Uint8Array[] = [];
let treeRoot: Awaited<ReturnType<typeof buildMerkleTree>> | null = null;

btnBuildTree.addEventListener('click', async () => {
  const count = parseInt(treeLeavesSelect.value);
  treeLeaves = [];
  for (let i = 0; i < count; i++) {
    treeLeaves.push(crypto.getRandomValues(new Uint8Array(32)));
  }
  treeRoot = await buildMerkleTree(treeLeaves);
  renderMerkleTree(treeContainer, treeRoot);

  // Populate leaf selector
  leafSelect.innerHTML = '';
  for (let i = 0; i < count; i++) {
    const opt = document.createElement('option');
    opt.value = String(i);
    opt.textContent = `Leaf ${i}`;
    leafSelect.appendChild(opt);
  }
  btnVerifyLeaf.disabled = false;
  treeVerifyOutput.classList.add('hidden');
});

btnVerifyLeaf.addEventListener('click', async () => {
  if (!treeRoot || treeLeaves.length === 0) return;
  const leafIdx = parseInt(leafSelect.value);
  const authPath = await getAuthPath(treeLeaves, leafIdx);
  const leafHash = await sha256Hex(treeLeaves[leafIdx]);
  const { valid, intermediates } = await verifyAuthPath(leafHash, leafIdx, authPath, treeRoot.hash);

  await animateAuthPath(treeContainer, treeRoot, authPath, leafHash, intermediates);

  let html = `<strong>Leaf ${leafIdx} verification: </strong>`;
  html += valid
    ? `<span class="badge badge-valid">ROOT MATCHES</span>`
    : `<span class="badge badge-invalid">MISMATCH</span>`;
  html += `\n\n<strong>Authentication path (sibling hashes):</strong>\n`;
  authPath.forEach((h, i) => { html += `  Level ${i}: ${h.substring(0, 16)}…\n`; });
  html += `\n<strong>Intermediate computations:</strong>\n`;
  intermediates.forEach((h, i) => { html += `  Step ${i}: ${h.substring(0, 16)}…\n`; });
  html += `\n<strong>Computed root:</strong> ${intermediates[intermediates.length - 1].substring(0, 32)}…`;
  html += `\n<strong>Expected root:</strong> ${treeRoot.hash.substring(0, 32)}…`;

  treeVerifyOutput.innerHTML = html;
  treeVerifyOutput.classList.remove('hidden');
});

// ─── TAB 3: WOTS+ ───
const btnGenWots = document.getElementById('btn-gen-wots') as HTMLButtonElement;
const wotsChainContainer = document.getElementById('wots-chains')!;
const wotsSignControls = document.getElementById('wots-sign-controls')!;
const wotsNibble = document.getElementById('wots-nibble') as HTMLInputElement;
const wotsChainIdx = document.getElementById('wots-chain-idx') as HTMLInputElement;
const btnWotsSign = document.getElementById('btn-wots-sign') as HTMLButtonElement;
const btnWotsVerify = document.getElementById('btn-wots-verify') as HTMLButtonElement;
const wotsReuseWarning = document.getElementById('wots-reuse-warning')!;
const wotsOutput = document.getElementById('wots-output')!;

let wotsKeyPair: WotsKeyPair | null = null;
let wotsLastSig: WotsSignatureResult | null = null;
let wotsSignCount = 0;

btnGenWots.addEventListener('click', async () => {
  wotsKeyPair = await generateWotsKeyPair(4);
  wotsSignCount = 0;
  wotsLastSig = null;
  wotsReuseWarning.classList.add('hidden');
  wotsOutput.classList.add('hidden');

  wotsChainContainer.innerHTML = '';
  for (let i = 0; i < wotsKeyPair.chains.length; i++) {
    const div = document.createElement('div');
    div.id = `wots-chain-${i}`;
    const label = document.createElement('div');
    label.style.cssText = 'font-size:0.8rem; color:#94a3b8; margin-top:8px;';
    label.textContent = `Chain ${i}`;
    wotsChainContainer.appendChild(label);
    wotsChainContainer.appendChild(div);
    renderWotsChain(div, wotsKeyPair.chains[i]);
  }

  wotsSignControls.style.display = 'flex';
  btnWotsVerify.disabled = true;
});

btnWotsSign.addEventListener('click', () => {
  if (!wotsKeyPair) return;
  const nibble = parseInt(wotsNibble.value);
  const chainIdx = parseInt(wotsChainIdx.value);

  // Check reuse
  const msgStr = `nibble-${nibble}-chain-${chainIdx}`;
  const reuse = checkReuseWarning(wotsKeyPair, msgStr);

  if (reuse.isReuse) {
    wotsReuseWarning.textContent = reuse.warning;
    wotsReuseWarning.classList.remove('hidden');
  } else {
    wotsReuseWarning.classList.add('hidden');
  }

  wotsKeyPair.signedMessages.push(msgStr);
  wotsSignCount++;

  wotsLastSig = wotsSign(wotsKeyPair, nibble, chainIdx);

  // Re-render the relevant chain with highlight
  const div = document.getElementById(`wots-chain-${chainIdx}`)!;
  renderWotsChain(div, wotsKeyPair.chains[chainIdx], wotsLastSig);

  wotsOutput.innerHTML =
    `<strong>Signed:</strong> nibble=${nibble}, chain=${chainIdx}\n` +
    `<strong>Revealed step:</strong> ${wotsLastSig.revealedStep} of ${wotsKeyPair.chains[chainIdx].chainLength}\n` +
    `<strong>Steps to public key:</strong> ${wotsLastSig.stepsToPublicKey}\n` +
    `<strong>Revealed value:</strong> ${bytesToHex(wotsLastSig.revealedValue).substring(0, 32)}…`;
  wotsOutput.classList.remove('hidden');
  btnWotsVerify.disabled = false;
});

btnWotsVerify.addEventListener('click', async () => {
  if (!wotsKeyPair || !wotsLastSig) return;
  const chainIdx = wotsLastSig.chainIndex;
  const valid = await wotsVerify(wotsKeyPair.chains[chainIdx].publicKey, wotsLastSig);
  wotsOutput.innerHTML +=
    `\n\n<strong>Verification:</strong> ` +
    (valid
      ? `<span class="badge badge-valid">VALID</span> — hashed forward ${wotsLastSig.stepsToPublicKey} times from revealed value and reached the public key.`
      : `<span class="badge badge-invalid">FAILED</span>`);
});

// ─── TAB 4: Ledger ───
const ledger = new Ledger();
const btnLedgerAdd = document.getElementById('btn-ledger-add') as HTMLButtonElement;
const btnLedgerVerify = document.getElementById('btn-ledger-verify') as HTMLButtonElement;
const btnLedgerTamper = document.getElementById('btn-ledger-tamper') as HTMLButtonElement;
const btnLedgerClear = document.getElementById('btn-ledger-clear') as HTMLButtonElement;
const ledgerSpinner = document.getElementById('ledger-spinner')!;
const ledgerEntries = document.getElementById('ledger-entries')!;
const ledgerTamperExpl = document.getElementById('ledger-tamper-explanation')!;

function renderLedger() {
  ledgerEntries.innerHTML = '';
  if (ledger.entries.length === 0) {
    ledgerEntries.innerHTML = '<p class="muted">No entries yet. Add one above.</p>';
    btnLedgerTamper.disabled = true;
    return;
  }
  btnLedgerTamper.disabled = false;

  for (const entry of ledger.entries) {
    const div = document.createElement('div');
    div.className = `ledger-entry${entry.valid ? '' : ' invalid'}`;
    div.innerHTML = `
      <div class="entry-header">
        <span class="entry-author">#${entry.id} — ${escapeHtml(entry.author)}</span>
        <span class="badge ${entry.valid ? 'badge-valid' : 'badge-invalid'}">${entry.valid ? 'VALID' : 'INVALID'}</span>
      </div>
      <div class="entry-message">${escapeHtml(entry.message)}</div>
      <div class="entry-meta">
        ${entry.timestamp} · ${entry.paramSet} · sig: ${entry.signature.length.toLocaleString()} B · ${bytesToHex(entry.signature).substring(0, 24)}…
      </div>
    `;
    ledgerEntries.appendChild(div);
  }
}

function escapeHtml(s: string): string {
  const div = document.createElement('div');
  div.textContent = s;
  return div.innerHTML;
}

renderLedger();

btnLedgerAdd.addEventListener('click', async () => {
  const author = (document.getElementById('ledger-author') as HTMLInputElement).value || 'Anonymous';
  const message = (document.getElementById('ledger-message') as HTMLInputElement).value || '(empty)';
  const params = (document.getElementById('ledger-param') as HTMLSelectElement).value as SphincsParamSet;

  ledgerSpinner.classList.remove('hidden');
  btnLedgerAdd.disabled = true;

  try {
    await ledger.addEntry(author, message, params);
    ledgerTamperExpl.classList.add('hidden');
    renderLedger();
  } finally {
    ledgerSpinner.classList.add('hidden');
    btnLedgerAdd.disabled = false;
  }
});

btnLedgerVerify.addEventListener('click', async () => {
  const result = await ledger.verifyAll();
  renderLedger();
  const summary = document.createElement('div');
  summary.className = 'output';
  summary.innerHTML = `<strong>Verification complete:</strong> ${result.valid} valid, ${result.invalid} invalid out of ${result.entries.length} entries.`;
  ledgerEntries.insertBefore(summary, ledgerEntries.firstChild);
});

btnLedgerTamper.addEventListener('click', () => {
  const latest = ledger.entries[ledger.entries.length - 1];
  if (!latest) return;
  ledger.tamperEntry(latest.id, latest.message + ' [TAMPERED]');
  ledgerTamperExpl.textContent =
    'The message content changed after signing. SHA-256 of the new message does not match the digest that was signed. SPHINCS+ verification rejects it.';
  ledgerTamperExpl.classList.remove('hidden');
  renderLedger();
});

btnLedgerClear.addEventListener('click', () => {
  ledger.clearAll();
  ledgerTamperExpl.classList.add('hidden');
  renderLedger();
});

// ─── TAB 5: Security Basis ───
document.getElementById('security-content')!.innerHTML = `
  <div class="security-section">
    <h3>The Hash-Only Security Argument</h3>
    <div class="highlight-box">
      <strong>"If SHA-256 is secure, SPHINCS+ is secure."</strong><br>
      SLH-DSA's security reduces entirely to the collision resistance, second-preimage resistance,
      and PRF properties of its underlying hash function. There are no number-theoretic assumptions
      (factoring, discrete log, lattice problems) that could be independently broken.
    </div>
  </div>

  <div class="security-section">
    <h3>Quantum Impact</h3>
    <table>
      <thead>
        <tr><th>Scheme</th><th>Assumption</th><th>Quantum Attack</th><th>Status</th></tr>
      </thead>
      <tbody>
        <tr><td>RSA</td><td>Integer factoring</td><td>Shor's algorithm</td><td style="color:#fca5a5">Broken</td></tr>
        <tr><td>ECDSA / Ed25519</td><td>Elliptic curve DLP</td><td>Shor's algorithm</td><td style="color:#fca5a5">Broken</td></tr>
        <tr><td>ML-DSA (Dilithium)</td><td>Module-LWE (lattice)</td><td>No known efficient attack</td><td style="color:#86efac">Survives</td></tr>
        <tr><td>SLH-DSA (SPHINCS+)</td><td>Hash function only</td><td>Grover reduces to 128-bit</td><td style="color:#86efac">Survives</td></tr>
      </tbody>
    </table>
  </div>

  <div class="security-section">
    <h3>Grover's Algorithm Impact</h3>
    <p>Grover's algorithm provides a quadratic speedup for unstructured search, effectively halving
    the security level of symmetric primitives. SHA-256 retains <strong>128-bit post-quantum security</strong>
    under Grover — still computationally infeasible.</p>
  </div>

  <div class="security-section">
    <h3>Assumption Maturity</h3>
    <table>
      <thead>
        <tr><th>Assumption</th><th>Years Studied</th><th>Used By</th></tr>
      </thead>
      <tbody>
        <tr><td>Integer factoring</td><td>~50 years</td><td>RSA</td></tr>
        <tr><td>Elliptic curve DLP</td><td>~35 years</td><td>ECDSA, Ed25519</td></tr>
        <tr><td>SHA-256 (hash functions)</td><td>~25 years</td><td>SLH-DSA (SPHINCS+)</td></tr>
        <tr><td>LWE (lattices)</td><td>~20 years</td><td>ML-DSA (Dilithium), ML-KEM</td></tr>
      </tbody>
    </table>
  </div>

  <div class="security-section">
    <h3>When to Use SPHINCS+</h3>
    <table>
      <thead>
        <tr><th>Use Case</th><th>Recommended?</th><th>Rationale</th></tr>
      </thead>
      <tbody>
        <tr><td>Long-lived archives</td><td style="color:#86efac">Yes</td><td>Most conservative PQC assumption; signatures remain valid for decades</td></tr>
        <tr><td>Legal documents</td><td style="color:#86efac">Yes</td><td>Minimal attack surface; hash-only foundation is well-understood</td></tr>
        <tr><td>Software signing (offline)</td><td style="color:#86efac">Yes</td><td>Large signatures acceptable; signing speed less critical</td></tr>
        <tr><td>High-frequency TLS handshakes</td><td style="color:#fca5a5">No</td><td>Large signatures (7–50 KB) add latency; ML-DSA preferred</td></tr>
        <tr><td>Bandwidth-constrained IoT</td><td style="color:#fca5a5">No</td><td>Signature sizes too large for constrained links</td></tr>
      </tbody>
    </table>
  </div>
`;

// ─── TAB 6: Comparison ───
document.getElementById('compare-content')!.innerHTML = `
  <table>
    <thead>
      <tr>
        <th>Scheme</th>
        <th>Public Key</th>
        <th>Signature</th>
        <th>Quantum Safe</th>
        <th>Assumption</th>
      </tr>
    </thead>
    <tbody>
      <tr><td>RSA-2048</td><td>256 B</td><td>256 B</td><td style="color:#fca5a5">No</td><td>Factoring</td></tr>
      <tr><td>Ed25519</td><td>32 B</td><td>64 B</td><td style="color:#fca5a5">No</td><td>ECDLP</td></tr>
      <tr><td>ML-DSA-44</td><td>1,312 B</td><td>2,420 B</td><td style="color:#86efac">Yes</td><td>LWE (lattice)</td></tr>
      <tr><td>SLH-DSA-128s</td><td>32 B</td><td>7,856 B</td><td style="color:#86efac">Yes</td><td>Hash only</td></tr>
      <tr><td>SLH-DSA-128f</td><td>32 B</td><td>17,088 B</td><td style="color:#86efac">Yes</td><td>Hash only</td></tr>
      <tr><td>SLH-DSA-256s</td><td>64 B</td><td>29,792 B</td><td style="color:#86efac">Yes</td><td>Hash only</td></tr>
      <tr><td>SLH-DSA-256f</td><td>64 B</td><td>49,856 B</td><td style="color:#86efac">Yes</td><td>Hash only</td></tr>
    </tbody>
  </table>
`;

// ─── Speed chart ───
function renderSpeedChart() {
  const container = document.getElementById('speed-chart');
  if (!container) return;
  container.innerHTML = '';

  const allTimes = Object.values(speedRecords).flat();
  if (allTimes.length === 0) {
    container.innerHTML = '<p class="muted">No signing operations recorded yet. Sign a message in Tab 1 to populate this chart.</p>';
    return;
  }
  const maxTime = Math.max(...allTimes, 1);

  for (const [paramSet, times] of Object.entries(speedRecords)) {
    const avg = times.reduce((a, b) => a + b, 0) / times.length;
    const pct = Math.max((avg / maxTime) * 100, 3);
    const div = document.createElement('div');
    div.className = 'speed-bar-container';
    div.innerHTML = `
      <div class="speed-bar-label">SLH-DSA-${paramSet} (${times.length} run${times.length > 1 ? 's' : ''})</div>
      <div class="speed-bar-track">
        <div class="speed-bar-fill" style="width:${pct}%">${avg.toFixed(0)} ms</div>
      </div>`;
    container.appendChild(div);
  }
}
