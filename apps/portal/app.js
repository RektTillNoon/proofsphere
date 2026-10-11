'use strict';

const MAX_PROOF = 8 * 1024 * 1024 + 16;
const CLAIM = 'Unauthorized withdrawal demonstrated';
const byId = id => document.getElementById(id);
const elements = {
  options: [...document.querySelectorAll('.scenario-option')],
  steps: [...document.querySelectorAll('.process-step')],
  newRequest: byId('new-request'),
  newRequestLabel: byId('new-request-label'),
  requestTitle: byId('request-title'),
  requestIntro: document.querySelector('.request-intro'),
  download: byId('download-request'),
  proofFile: byId('proof-file'),
  fileZone: byId('file-zone'),
  fileTitle: byId('file-title'),
  fileDescription: byId('file-description'),
  verify: byId('verify-button'),
  result: byId('result'),
  resultTitle: byId('result-title'),
  resultDescription: byId('result-description'),
};
const state = {
  scenarios: [], selectedId: 'vault-vulnerable-v1', active: null,
  file: null, verifying: false, mutating: false, revision: 0,
  controller: null, phase: 'idle',
};

const explanations = {
  setup: {
    label: '01 / PUBLIC SETUP',
    body: 'The owner pins the compiled contract, three accounts, the EVM environment, and the precise claim. Their hashes identify the scenario the proof must use.',
    boundary: 'VISIBLE TO BOTH SIDES',
  },
  witness: {
    label: '02 / PRIVATE INPUT',
    body: 'The researcher provides raw transaction calldata to a local RISC Zero guest. The guest executes the registered vault and checks the claim. This portal never receives those bytes.',
    boundary: 'STAYS WITH RESEARCHER',
  },
  receipt: {
    label: '03 / PROOF ARTIFACT',
    body: 'The guest commits only a scenario digest, the owner’s nonce, and a true claim flag. The succinct receipt authenticates that computation.',
    boundary: 'SHARED ARTIFACT',
  },
  verify: {
    label: '04 / VERIFICATION',
    body: 'The owner checks the receipt against the registered guest image and their own active request. The result comes from the verifier, not from this visualization.',
    boundary: 'OWNER CHECKS LOCALLY',
  },
};
const rejectionMessages = {
  UNSUPPORTED_FORMAT: 'This file is not a supported ProofSphere proof artifact.',
  TOO_LARGE: 'The proof file exceeds the 8 MiB limit.',
  RECEIPT_REJECTED: 'The cryptographic proof could not be verified.',
  SCENARIO_MISMATCH: 'This proof refers to another registered contract scenario.',
  CHALLENGE_MISMATCH: 'This proof belongs to a different owner request.',
  CLAIM_INVALID: 'The verified receipt does not contain the required claim journal.',
  REQUEST_REPLACED: 'The owner request changed before verification finished. Choose the current challenge.',
  VERIFIER_BUSY: 'The verifier is working on another proof. Try again after it finishes.',
  NO_ACTIVE_CHALLENGE: 'Create a current owner request before verifying a proof.',
};

function status(phase, title, description) {
  state.phase = phase;
  elements.result.dataset.status = phase;
  elements.resultTitle.textContent = title;
  elements.resultDescription.textContent = description;
  document.body.dataset.phase = phase;
}
function activeForSelection() {
  return state.active && state.active.scenario_id === state.selectedId ? state.active : null;
}
function sameRequest(snapshot, revision) {
  const active = activeForSelection();
  return revision === state.revision && active && active.scenario_id === snapshot.scenario_id
    && active.nonce === snapshot.nonce && active.generation === snapshot.generation;
}
function clearFile() {
  state.file = null;
  elements.proofFile.value = '';
}
function invalidate() {
  state.revision += 1;
  state.controller?.abort();
  state.controller = null;
  state.verifying = false;
  state.active = null;
  clearFile();
}
function shorten(value) {
  return value ? `${value.slice(0, 9)}…${value.slice(-7)}` : 'No active challenge';
}
function render() {
  const active = activeForSelection();
  const scenario = state.scenarios.find(item => item.id === state.selectedId);
  elements.options.forEach(button => {
    const chosen = button.dataset.scenarioId === state.selectedId;
    button.classList.toggle('is-selected', chosen);
    button.setAttribute('aria-pressed', String(chosen));
    button.disabled = state.mutating || !scenario;
  });
  elements.newRequest.disabled = state.mutating || !scenario;
  elements.newRequestLabel.textContent = state.mutating ? 'Creating request…' : active ? 'Create another request' : 'Create owner request';
  elements.requestTitle.textContent = active ? 'Owner request ready.' : 'Create the owner request.';
  elements.requestIntro.textContent = active?.mode === 'recorded'
    ? 'This recorded request is ready for a matching proof. Verification runs now on this machine.'
    : 'A unique challenge binds the proof to your request. Send the downloaded request to the researcher.';
  elements.download.classList.toggle('is-disabled', !active || state.mutating);
  elements.download.setAttribute('aria-disabled', String(!active || state.mutating));
  elements.download.tabIndex = active && !state.mutating ? 0 : -1;
  elements.proofFile.disabled = !active || state.mutating || state.verifying;
  elements.fileZone.classList.toggle('is-disabled', !active || state.mutating || state.verifying);
  elements.fileZone.classList.toggle('has-file', Boolean(state.file));
  elements.fileTitle.textContent = state.file ? state.file.name : 'Choose a proof file';
  elements.fileDescription.textContent = state.file
    ? `${(state.file.size / 1024).toFixed(1)} KiB · ready for local verification`
    : active ? 'Or drop one here · maximum 8 MiB' : 'Create an owner request to enable upload';
  elements.verify.disabled = !active || !state.file || state.mutating || state.verifying;
  byId('request-mode').textContent = active ? (active.mode === 'recorded' ? 'RECORDED REQUEST' : 'FRESH REQUEST') : 'NO REQUEST';
  byId('nonce-short').textContent = shorten(active?.nonce);
  byId('request-caption').textContent = active ? `Process request ${active.generation}` : 'Create a request to continue.';
  byId('recorded-note').hidden = active?.mode !== 'recorded';
  document.body.dataset.scenario = state.selectedId.includes('patched') ? 'patched' : 'vulnerable';
  const patched = state.selectedId.includes('patched');
  byId('path-label').textContent = patched ? 'CREDIT CHECK' : 'UNCHECKED PATH';
  const note = byId('path-note');
  note.querySelector('.path-symbol').textContent = patched ? '×' : '↗';
  note.querySelector('p').textContent = patched
    ? 'Patched path. The vault requires caller credit and debits it before sending funds. The reference unauthorized payload is rejected.'
    : 'Vulnerable path. A direct withdrawal can transfer a positive amount to an uncredited caller while the victim’s ledger stays unchanged.';
  const hashes = {
    scenario: scenario?.scenario_digest, code: scenario?.code_digest, state: scenario?.state_digest,
    environment: scenario?.environment_digest, claim: scenario?.claim_digest,
    image: scenario?.guest_image_id, nonce: active?.nonce,
  };
  for (const [name, value] of Object.entries(hashes)) byId(`digest-${name}`).textContent = value || '—';
}
function explain(key) {
  const item = explanations[key];
  if (!item) return;
  elements.steps.forEach(button => {
    const chosen = button.dataset.explain === key;
    button.classList.toggle('is-focused', chosen);
    button.setAttribute('aria-pressed', String(chosen));
  });
  byId('explain-label').textContent = item.label;
  byId('explain-body').textContent = item.body;
  byId('explain-boundary').textContent = item.boundary;
}
async function load() {
  try {
    const response = await fetch('/api/scenarios', { cache: 'no-store' });
    if (!response.ok) throw new Error('scenario request failed');
    const data = await response.json();
    if (!Array.isArray(data.scenarios) || !data.scenarios.length) throw new Error('no registered scenarios');
    state.scenarios = data.scenarios;
    if (data.active_request) {
      state.selectedId = data.active_request.scenario_id;
      state.active = data.active_request;
      status('idle', 'Request ready', 'Choose the public proof artifact for this owner request.');
    } else {
      state.selectedId = data.scenarios.some(item => item.id === state.selectedId) ? state.selectedId : data.scenarios[0].id;
      status('idle', 'Awaiting a request', 'Select a contract and create an owner challenge.');
    }
  } catch {
    state.scenarios = [];
    state.active = null;
    status('error', 'Verifier unavailable', 'Could not load the trusted scenario registry. Check that the local portal is running.');
  }
  render();
}

async function createRequest(id) {
  if (state.mutating || !state.scenarios.some(item => item.id === id)) return;
  invalidate();
  state.selectedId = id;
  state.mutating = true;
  const revision = state.revision;
  status('idle', 'Creating owner request', 'A new random challenge will replace any previous result.');
  render();
  try {
    const response = await fetch('/api/challenge', {
      method: 'POST', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-ProofSphere-UI': '1' },
      body: JSON.stringify({ scenario_id: id }),
    });
    const data = await response.json();
    if (state.revision !== revision || state.selectedId !== id) return;
    if (!response.ok || data.challenge?.scenario_id !== id || !data.generation || !data.challenge?.nonce) throw new Error('request rejected');
    state.active = { scenario_id: id, nonce: data.challenge.nonce, generation: data.generation, mode: data.mode };
    status('idle', 'Request ready', 'Download the owner challenge, then choose a matching proof artifact.');
  } catch {
    if (state.revision === revision) status('error', 'Request could not be created', 'The local verifier did not confirm a new challenge. Try again.');
  } finally {
    if (state.revision === revision) { state.mutating = false; render(); }
  }
}

async function selectFile(file) {
  if (!activeForSelection() || state.mutating || state.verifying || !file) return;
  clearFile();
  const revision = ++state.revision;
  status('idle', 'Inspecting proof file', 'Checking the local artifact header before upload.');
  render();
  if (!file.name.endsWith('.psproof') || file.size < 16 || file.size > MAX_PROOF) {
    status('rejected', 'Unsupported proof artifact', 'Choose a .psproof file no larger than 8 MiB. No file was uploaded.');
    render();
    return;
  }
  try {
    const header = new Uint8Array(await file.slice(0, 16).arrayBuffer());
    if (revision !== state.revision || !activeForSelection()) return;
    const magic = new TextDecoder('ascii', { fatal: true }).decode(header.subarray(0, 8));
    const length = new DataView(header.buffer).getBigUint64(8, true);
    if (magic !== 'PSPHP001' || length !== BigInt(file.size - 16)) throw new Error('invalid proof header');
    state.file = file;
    status('selected', 'Proof artifact selected', 'The header is well formed. The independent verifier has not checked the receipt yet.');
  } catch {
    status('rejected', 'Unsupported proof artifact', 'The file header or payload length is invalid. No file was uploaded.');
  }
  render();
}
async function verifySelected() {
  const active = activeForSelection();
  if (!active || !state.file || state.mutating || state.verifying) return;
  const snapshot = { ...active };
  const revision = state.revision;
  const file = state.file;
  const controller = new AbortController();
  state.controller = controller;
  state.verifying = true;
  status('verifying', 'Verifying the receipt', 'Checking the cryptographic proof, registered scenario, and owner nonce now.');
  explain('verify');
  render();
  try {
    const response = await fetch('/api/verify', {
      method: 'POST', cache: 'no-store', signal: controller.signal,
      headers: { 'Content-Type': 'application/octet-stream', 'X-ProofSphere-UI': '1', 'X-ProofSphere-Generation': snapshot.generation },
      body: file,
    });
    const result = await response.json();
    if (!sameRequest(snapshot, revision)) return;
    const contextMatches = result.scenario_id === snapshot.scenario_id && result.nonce === snapshot.nonce
      && result.generation === snapshot.generation && result.mode === snapshot.mode;
    if (!contextMatches) {
      status('error', 'Request context changed', 'The verifier response does not match the visible owner request. Create a new request.');
    } else if (response.ok && result.status === 'accepted' && result.code === 'CLAIM_VERIFIED' && result.claim === CLAIM) {
      status('accepted', CLAIM, 'A genuine proof satisfied this exact scenario and owner challenge. The calldata remains private.');
    } else if (result.status === 'rejected' || response.status === 409) {
      status('rejected', 'Proof not accepted', rejectionMessages[result.code] || 'The receipt did not satisfy this owner request.');
    } else {
      status('error', 'Verification could not finish', 'The local verifier encountered an operational problem. Try again.');
    }
  } catch (error) {
    if (sameRequest(snapshot, revision) && error?.name !== 'AbortError') {
      status('error', 'Verification interrupted', 'The local verifier response was unavailable. Try again.');
    }
  } finally {
    if (sameRequest(snapshot, revision)) {
      state.verifying = false;
      state.controller = null;
      render();
    }
  }
}

elements.options.forEach(button => button.addEventListener('click', () => {
  if (button.dataset.scenarioId !== state.selectedId || !activeForSelection()) createRequest(button.dataset.scenarioId);
}));
elements.steps.forEach(button => button.addEventListener('click', () => explain(button.dataset.explain)));
elements.newRequest.addEventListener('click', () => createRequest(state.selectedId));
elements.proofFile.addEventListener('change', event => selectFile(event.target.files?.[0]));
elements.verify.addEventListener('click', verifySelected);
elements.fileZone.addEventListener('dragover', event => {
  if (!elements.proofFile.disabled) { event.preventDefault(); elements.fileZone.classList.add('is-dragging'); }
});
elements.fileZone.addEventListener('dragleave', () => elements.fileZone.classList.remove('is-dragging'));
elements.fileZone.addEventListener('drop', event => {
  event.preventDefault();
  elements.fileZone.classList.remove('is-dragging');
  selectFile(event.dataTransfer?.files?.[0]);
});

load();
