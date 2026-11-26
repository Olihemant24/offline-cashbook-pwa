const DB_NAME = 'my-cashbook-v1';
const DB_VERSION = 2;  // Kept at 2 — reverting to 1 would break upgraded devices
const STORE_TRANSACTIONS = 'transactions';
const STORE_SETTINGS = 'settings';
const DRIVE_FILE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
const DEFAULT_CURRENCY = 'NPR';
const PERIODS_TAB = 'Cashbook Periods';
const DEFAULT_CLIENT_ID = '1017685550464-um4md5jhrbki0gbna4d7b0osmliuddqm.apps.googleusercontent.com';
const DEFAULT_API_KEY = 'AIzaSyCBYJek40PIcM2Qr8dGJHpYto12SH9qBH8';
const DEFAULT_APP_ID = '1017685550464';
const APP_BUILD = 42;
const MIN_PASSWORD_LENGTH = 4;
const MAX_LOCAL_ARCHIVES = 5;

let dbPromise, accessToken = null, tokenExpiresAt = 0, cryptoKey = null, masterKeyRaw = null;
let unreadableCount = 0, idleTimeout = null, isSyncing = false, toastTimer;
let activeCurrencyCode = DEFAULT_CURRENCY, cachedConfig = null, lastSyncFinishedAt = 0;
let autoSyncInterval = null, openKebabMenu = null, openKebabAnchor = null;
let failedUnlockAttempts = 0;
const currencyFormatters = new Map();
const BOOKS_KEY = 'books', CURRENT_BOOK_KEY = 'currentBookId', CHOOSE_ACCOUNT_KEY = 'cb_choose_account', ARCHIVES_KEY = 'archives';
let books = [], currentBookId = null;

// ===== CRYPTO =====
function bytesToB64(b) { return btoa(String.fromCharCode(...new Uint8Array(b))); }
function b64ToBytes(s) { return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function randomSaltB64() { return bytesToB64(crypto.getRandomValues(new Uint8Array(16))); }
async function importAesKey(b) { return crypto.subtle.importKey('raw', b, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); }
async function exportAesKey(k) { return new Uint8Array(await crypto.subtle.exportKey('raw', k)); }
async function generateMasterKey() { cryptoKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); masterKeyRaw = await exportAesKey(cryptoKey); return cryptoKey; }
async function setMasterKeyFromBytes(b) { cryptoKey = await importAesKey(b); masterKeyRaw = b; return cryptoKey; }
async function derivePasswordKek(pw, saltB64) {
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(pw), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64ToBytes(saltB64), iterations: 600000, hash: 'SHA-256' }, km, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptText(t, key = cryptoKey) {
  if (!key) throw new Error("App is locked.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(t));
  return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(ct)) };
}
async function decryptText(e, key = cryptoKey) {
  if (!key) throw new Error("App is locked.");
  if (!e || !e.iv || !e.data) return null;
  try { return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(e.iv) }, key, b64ToBytes(e.data))); }
  catch { return null; }
}
async function wrapMasterKeyWith(kek) {
  if (!masterKeyRaw) throw new Error('Unlock first.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, masterKeyRaw);
  return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(c)) };
}
async function unwrapMasterKey(w, kek) {
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(w.iv) }, kek, b64ToBytes(w.data));
  await setMasterKeyFromBytes(new Uint8Array(raw));
}

// ===== WEBAUTHN =====
async function createPrfCredential(salt) {
  const ch = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({ publicKey: {
    challenge: ch, rp: { name: 'My Cashbook' },
    user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'cashbook-user', displayName: 'Cashbook User' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
    extensions: { prf: { eval: { first: salt } } }
  }});
  const prf = cred.getClientExtensionResults?.()?.prf;
  if (!prf || (!prf.enabled && !prf.results?.first)) throw new Error('This device does not support secure Face ID / fingerprint.');
  const credId = new Uint8Array(cred.rawId);
  let out = prf.results?.first;
  if (!out) out = await getPrfBytes(credId, salt);
  return { credId, prfBytes: new Uint8Array(out) };
}
async function getPrfBytes(credId, salt) {
  const ch = crypto.getRandomValues(new Uint8Array(32));
  const as = await navigator.credentials.get({ publicKey: { challenge: ch, allowCredentials: [{ id: credId, type: 'public-key' }], userVerification: 'required', extensions: { prf: { eval: { first: salt } } } } });
  const out = as.getClientExtensionResults?.()?.prf?.results?.first;
  if (!out) throw new Error('Biometric key not available.');
  return new Uint8Array(out);
}
async function enableBiometrics() {
  if (!window.PublicKeyCredential) throw new Error('Not supported on this device.');
  if (!localStorage.getItem('cb_key_wrapped')) throw new Error('Set a master password first — otherwise losing this passkey could lock you out.');
  if (!masterKeyRaw) throw new Error('App is locked. Unlock first.');
  const salt = crypto.getRandomValues(new Uint8Array(32));
  let cred;
  try { cred = await createPrfCredential(salt); }
  catch (e) { if (e?.name === 'NotAllowedError') throw new Error('Cancelled.'); throw e; }
  const w = await wrapMasterKeyWith(await importAesKey(cred.prfBytes));
  // Verify wrap
  const test = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(w.iv) }, await importAesKey(cred.prfBytes), b64ToBytes(w.data));
  if (new Uint8Array(test).length !== 32) throw new Error('Internal check failed. Try again.');
  localStorage.setItem('cb_prf_salt', bytesToB64(salt));
  localStorage.setItem('cb_prf_cred_id', bytesToB64(cred.credId));
  localStorage.setItem('cb_prf_key_wrapped', JSON.stringify(w));
  localStorage.removeItem('cb_key_raw');
  // Defense in depth: ensure __auth_check__ exists
  await saveSetting('__auth_check__', 'valid');
  return true;
}
async function authenticateWithBiometrics() {
  const credId = localStorage.getItem('cb_prf_cred_id'), salt = localStorage.getItem('cb_prf_salt'), wj = localStorage.getItem('cb_prf_key_wrapped');
  if (!credId || !salt || !wj) return false;
  try {
    const prf = await getPrfBytes(b64ToBytes(credId), b64ToBytes(salt));
    await unwrapMasterKey(JSON.parse(wj), await importAesKey(prf));
    await openDatabase();
    const check = await getSetting('__auth_check__', null);
    if (check !== 'valid') {
      console.warn('Biometric unlock: key unwrapped but __auth_check__ failed (was:', check, '). Repairing.');
      await saveSetting('__auth_check__', 'valid');
    }
    return true;
  } catch (e) { console.error('Biometric unlock failed:', e); cryptoKey = null; masterKeyRaw = null; return false; }
}
function disableBiometrics() {
  localStorage.removeItem('cb_prf_cred_id'); localStorage.removeItem('cb_prf_salt'); localStorage.removeItem('cb_prf_key_wrapped');
  if (!localStorage.getItem('cb_key_wrapped') && masterKeyRaw) localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
}
function securityState() { return { hasPassword: !!localStorage.getItem('cb_key_wrapped'), hasBiometrics: !!localStorage.getItem('cb_prf_key_wrapped'), hasRaw: !!localStorage.getItem('cb_key_raw') }; }
function isProtected() { const s = securityState(); return s.hasPassword || s.hasBiometrics; }
function updateSecurityUi() {
  if (!elements.securityStatus) return;
  const s = securityState();
  const p = [s.hasPassword ? 'Master password: ON' : 'Master password: OFF', s.hasBiometrics ? 'Face ID / fingerprint: ON' : 'Face ID / fingerprint: OFF'];
  if (!isProtected()) p.push('This device opens without a lock.');
  elements.securityStatus.textContent = p.join('  ·  ');
  if (elements.biometricToggle) {
    elements.biometricToggle.checked = s.hasBiometrics;
    elements.biometricToggle.disabled = !s.hasPassword;
    elements.biometricToggle.title = !s.hasPassword ? 'Set a master password first' : '';
  }
  if (elements.lockNowBtn) elements.lockNowBtn.style.display = isProtected() ? '' : 'none';
}

// ===== TOKEN =====
function saveToken(t, e) { accessToken = t; tokenExpiresAt = Date.now() + ((Number(e) || 3600) * 1000); try { sessionStorage.setItem('cb_token', t); sessionStorage.setItem('cb_token_expires', String(tokenExpiresAt)); } catch {} }
function loadSavedToken() { try { const t = sessionStorage.getItem('cb_token'), e = Number(sessionStorage.getItem('cb_token_expires') || '0'); if (t && e > Date.now() + 60000) { accessToken = t; tokenExpiresAt = e; return true; } } catch {} return false; }
function clearSavedToken() { accessToken = null; tokenExpiresAt = 0; try { sessionStorage.removeItem('cb_token'); sessionStorage.removeItem('cb_token_expires'); } catch {} try { localStorage.removeItem('cb_token'); localStorage.removeItem('cb_token_expires'); } catch {} }
function tokenIsValid() { return !!accessToken && tokenExpiresAt > Date.now() + 60000; }
function activeBook() { return books.find(b => b.id === currentBookId) || books[0] || null; }
async function effectiveConfig() { return bookConfig(activeBook()); }
async function ensureSignedIn() { if (tokenIsValid()) return; await requestGoogleToken(await effectiveConfig()); }

const $ = id => document.getElementById(id);
const elements = {
  lockScreen: $('lockScreen'), lockMessage: $('lockMessage'), unlockForm: $('unlockForm'), unlockPassword: $('unlockPassword'), unlockBtn: $('unlockBtn'), lockError: $('lockError'), appShell: $('appShell'), biometricBtn: $('biometricBtn'), forgotPasswordBtn: $('forgotPasswordBtn'),
  onlineDot: $('onlineDot'), syncTitle: $('syncTitle'), syncMessage: $('syncMessage'), syncNow: $('syncNow'),
  balanceTotal: $('balanceTotal'), balanceNote: $('balanceNote'), incomeTotal: $('incomeTotal'), expenseTotal: $('expenseTotal'),
  transactionForm: $('transactionForm'), moneyIn: $('moneyIn'), moneyOut: $('moneyOut'), remarks: $('remarks'), formFeedback: $('formFeedback'),
  transactionList: $('transactionList'), recordCount: $('recordCount'), historyFootnote: $('historyFootnote'), storageStatus: $('storageStatus'),
  settingsToggle: $('settingsToggle'), settingsPanel: $('settingsPanel'), archivePanel: $('archivePanel'), clientId: $('clientId'), apiKey: $('apiKey'), appId: $('appId'), spreadsheetInput: $('spreadsheetInput'), responseTab: $('responseTab'), dashboardTab: $('dashboardTab'),
  currencyCode: $('currencyCode'), saveSettings: $('saveSettings'), chooseGoogleSheet: $('chooseGoogleSheet'), createNewSheet: $('createNewSheet'), connectGoogle: $('connectGoogle'), setupStatus: $('setupStatus'), toast: $('toast'),
  onboardingCard: $('onboardingCard'), switchGoogleAccount: $('switchGoogleAccount'), onboardCurrency: $('onboardCurrency'), startCreateSheet: $('startCreateSheet'), startChooseSheet: $('startChooseSheet'), onboardingStatus: $('onboardingStatus'), openSheetLink: $('openSheetLink'),
  carryBalance: $('carryBalance'), archiveName: $('archiveName'), archiveNow: $('archiveNow'), archiveStatus: $('archiveStatus'),
  biometricToggle: $('biometricToggle'), lockNowBtn: $('lockNowBtn'), securityStatus: $('securityStatus'), passwordInput: $('passwordInput'), setPasswordBtn: $('setPasswordBtn'), removePasswordBtn: $('removePasswordBtn'), signOutGoogle: $('signOutGoogle'), resetGoogleCreds: $('resetGoogleCreds'),
  bookSelect: $('bookSelect'), newBookBtn: $('newBookBtn'), booksList: $('booksList')
};

// ===== DB =====
function openDatabase() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((res, rej) => {
    const r = indexedDB.open(DB_NAME, DB_VERSION);
    r.onupgradeneeded = () => { const d = r.result; if (!d.objectStoreNames.contains(STORE_TRANSACTIONS)) d.createObjectStore(STORE_TRANSACTIONS, { keyPath: 'id' }); if (!d.objectStoreNames.contains(STORE_SETTINGS)) d.createObjectStore(STORE_SETTINGS, { keyPath: 'key' }); };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error || new Error('Could not open local storage.'));
    r.onblocked = () => rej(new Error('Database upgrade blocked. Close other tabs of this app and try again.'));
  });
  return dbPromise;
}
function txnDone(tx) { return new Promise((res, rej) => { tx.oncomplete = res; tx.onabort = tx.onerror = () => rej(tx.error || new Error('Save failed.')); }); }
async function getAllTransactions() {
  const db = await openDatabase();
  const tx = db.transaction(STORE_TRANSACTIONS, 'readonly');
  const done = txnDone(tx);
  const res = await new Promise((r, j) => { const q = tx.objectStore(STORE_TRANSACTIONS).getAll(); q.onsuccess = () => r(q.result || []); q.onerror = () => j(q.error); });
  await done;
  unreadableCount = 0;
  const out = [];
  for (const rec of res) {
    if (rec.encrypted) { const p = await decryptText(rec.encrypted); if (p) { try { out.push({ id: rec.id, ...JSON.parse(p) }); } catch { unreadableCount++; } } else unreadableCount++; }
    else { out.push(rec); await putTransaction(rec); }
  }
  return out;
}
async function putTransaction(rec) {
  const { id, ...p } = rec;
  const encrypted = await encryptText(JSON.stringify(p));
  const db = await openDatabase();
  const tx = db.transaction(STORE_TRANSACTIONS, 'readwrite');
  const done = txnDone(tx);
  tx.objectStore(STORE_TRANSACTIONS).put({ id, encrypted });
  await done;
}
async function deleteTransaction(id) { const db = await openDatabase(); const tx = db.transaction(STORE_TRANSACTIONS, 'readwrite'); const done = txnDone(tx); tx.objectStore(STORE_TRANSACTIONS).delete(id); await done; }
async function getSetting(k, fb = null) {
  const db = await openDatabase(); const tx = db.transaction(STORE_SETTINGS, 'readonly'); const done = txnDone(tx);
  const r = await new Promise((res, rej) => { const q = tx.objectStore(STORE_SETTINGS).get(k); q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error); });
  await done;
  if (!r) return fb;
  if (r.encrypted) {
    const p = await decryptText(r.encrypted);
    if (p == null) return fb;
    try { return JSON.parse(p); } catch { return fb; }
  }
  return r.value !== undefined ? r.value : fb;
}
async function saveSetting(k, v) {
  const enc = await encryptText(JSON.stringify(v));
  const db = await openDatabase(); const tx = db.transaction(STORE_SETTINGS, 'readwrite'); const done = txnDone(tx);
  tx.objectStore(STORE_SETTINGS).put({ key: k, encrypted: enc }); await done;
}
async function deleteSetting(k) { const db = await openDatabase(); const tx = db.transaction(STORE_SETTINGS, 'readwrite'); const done = txnDone(tx); tx.objectStore(STORE_SETTINGS).delete(k); await done; }

// ===== HELPERS =====
function newBookId() { return crypto.randomUUID ? crypto.randomUUID() : `book-${Date.now()}-${Math.random().toString(36).slice(2,10)}`; }
function newId() { return crypto.randomUUID ? crypto.randomUUID() : `tx-${Date.now()}-${Math.random().toString(36).slice(2,10)}`; }
function monthYearLabel(d = new Date()) { return new Intl.DateTimeFormat(undefined, { month: 'short', year: 'numeric' }).format(d); }
function tsOf(r) { return Date.parse(r?.createdAt || r?.sheetTimestamp || '') || 0; }

// ===== BOOKS =====
async function loadBooks() {
  books = await getSetting(BOOKS_KEY, null);
  const migrated = await getSetting('booksMigrated', false);
  if (!Array.isArray(books)) books = [];
  if (!books.length && !migrated) {
    const legacy = await getSetting('googleConfig', {});
    const first = { id: newBookId(), name: 'Personal', spreadsheetId: legacy.spreadsheetId || '', spreadsheetName: legacy.spreadsheetName || '', responseTab: legacy.responseTab || 'Form responses 1', dashboardTab: legacy.dashboardTab || 'Dashboard' };
    books = [first]; await saveSetting(BOOKS_KEY, books); await saveSetting(CURRENT_BOOK_KEY, first.id);
    const p = await getSetting('periodStartIso', null); if (p) await saveSetting(`periodStart:${first.id}`, p);
    const b = await getSetting('startingBalanceMinor', null); if (b !== null) await saveSetting(`startingBalance:${first.id}`, b);
    const all = await getAllTransactions();
    for (const rec of all) if (!rec.bookId) await putTransaction({ ...rec, bookId: first.id });
    await saveSetting('booksMigrated', true);
  }
  if (!books.length) { currentBookId = null; }
  else {
    currentBookId = await getSetting(CURRENT_BOOK_KEY, null) || books[0].id;
    if (!books.some(b => b.id === currentBookId)) currentBookId = books[0].id;
  }
}
async function saveBooks() { await saveSetting(BOOKS_KEY, books); }
async function bookConfig(book) {
  const saved = await getSetting('googleConfig', {});
  const base = { currencyCode: saved.currencyCode || DEFAULT_CURRENCY, clientId: saved.clientId || DEFAULT_CLIENT_ID, apiKey: saved.apiKey || DEFAULT_API_KEY, appId: saved.appId || DEFAULT_APP_ID };
  if (!book) return { ...base, responseTab: 'Form responses 1', dashboardTab: 'Dashboard', spreadsheetId: '', spreadsheetName: '', bookId: null };
  return { ...base, responseTab: book.responseTab || 'Form responses 1', dashboardTab: book.dashboardTab || 'Dashboard', spreadsheetId: book.spreadsheetId || '', spreadsheetName: book.spreadsheetName || '', bookId: book.id };
}
async function updateActiveBookConfig(patch) { const b = activeBook(); if (!b) return; Object.assign(b, patch); await saveBooks(); cachedConfig = await bookConfig(b); }
async function switchBook(id) {
  if (!books.some(b => b.id === id) || id === currentBookId) return;
  currentBookId = id; await saveSetting(CURRENT_BOOK_KEY, id);
  cachedConfig = await bookConfig(activeBook());
  await refreshView(); announce(`Switched to ${activeBook().name}.`);
}
async function createBook(name) {
  const t = String(name || '').trim();
  if (!t) throw new Error('Enter a name.');
  if (books.some(b => b.name.toLowerCase() === t.toLowerCase())) throw new Error(`A book called “${t}” already exists.`);
  const b = { id: newBookId(), name: t, spreadsheetId: '', spreadsheetName: '', responseTab: t, dashboardTab: 'Dashboard' };
  books.push(b); await saveBooks(); await switchBook(b.id); return b;
}
async function deleteBook(book, opts = {}) {
  const { deleteSheet = false } = opts;
  if (books.length <= 1) throw new Error('You need at least one book.');
  if (isSyncing) throw new Error('Wait for the current sync to finish.');
  if (deleteSheet && book.spreadsheetId && navigator.onLine && tokenIsValid()) { try { await driveDeleteFile(book.spreadsheetId); } catch (e) { console.warn(e); } }
  if (book.id === currentBookId) { const o = books.find(b => b.id !== book.id); currentBookId = o?.id || null; if (currentBookId) await saveSetting(CURRENT_BOOK_KEY, currentBookId); }
  for (const r of await getBookTransactions(book.id)) await deleteTransaction(r.id);
  books = books.filter(b => b.id !== book.id); await saveBooks();
  await deleteSetting(`startingBalance:${book.id}`); await deleteSetting(`periodStart:${book.id}`);
  const arcs = await getSetting(ARCHIVES_KEY, []);
  await saveSetting(ARCHIVES_KEY, arcs.filter(a => a.bookId !== book.id));
  cachedConfig = await bookConfig(activeBook());
}
async function renameBook(book, name) {
  const t = String(name || '').trim();
  if (!t) throw new Error('Enter a name.');
  if (books.some(b => b.id !== book.id && b.name.toLowerCase() === t.toLowerCase())) throw new Error(`A book called “${t}” already exists.`);
  book.name = t; await saveBooks();
}
async function getBookTransactions(bookId = currentBookId) { const all = await getAllTransactions(); return all.filter(r => r.bookId === bookId); }
async function getActiveBookRecords() {
  if (!currentBookId) return [];
  const recs = await getBookTransactions(currentBookId);
  const start = Date.parse(await getSetting(`periodStart:${currentBookId}`, '') || '');
  return recs.filter(r => {
    if (r.deleted) return false;
    if (r.archiveGroup) return false;
    if (Number.isNaN(start)) return true;
    return tsOf(r) >= start;
  });
}

// ===== ARCHIVES =====
async function archiveGetForBook(bookId) {
  const all = await getSetting(ARCHIVES_KEY, []);
  return all.filter(a => a.bookId === bookId);
}
async function archiveSave(arc) {
  const all = await getSetting(ARCHIVES_KEY, []);
  const idx = all.findIndex(a => a.id === arc.id);
  if (idx >= 0) all[idx] = arc; else all.push(arc);
  await saveSetting(ARCHIVES_KEY, all);
}
async function archiveDelete(id) {
  const all = await getSetting(ARCHIVES_KEY, []);
  await saveSetting(ARCHIVES_KEY, all.filter(a => a.id !== id));
}
async function getArchiveTransactions(bookId, archiveName) {
  const all = await getBookTransactions(bookId);
  return all.filter(r => r.archiveGroup === archiveName && !r.deleted).sort((a, b) => tsOf(a) - tsOf(b));
}
async function pruneOldArchives(book) {
  const arcs = await archiveGetForBook(book.id);
  arcs.sort((a, b) => tsOf(b) - tsOf(a));
  const drop = arcs.slice(MAX_LOCAL_ARCHIVES);
  for (const arc of drop) {
    if (!arc.synced) continue;
    const txns = await getBookTransactions(book.id);
    const hasDirty = txns.some(r => r.archiveGroup === arc.archiveName && (r.dirty || r.deleted));
    if (hasDirty) continue;
    for (const t of txns) if (t.archiveGroup === arc.archiveName) await deleteTransaction(t.id);
    await archiveDelete(arc.id);
  }
}

// ===== MODAL UI =====
let activeModal = null;
function closeModal() { if (activeModal) { activeModal.remove(); activeModal = null; } }
function openModal(title, buildContent) {
  closeModal();
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed; inset:0; background:rgba(0,0,0,.5); z-index:10000; display:flex; align-items:center; justify-content:center; padding:16px; font-family:inherit;';
  overlay.onclick = (e) => { if (e.target === overlay) closeModal(); };
  const modal = document.createElement('div');
  modal.style.cssText = 'background:#fff; border-radius:14px; max-width:560px; width:100%; max-height:85vh; display:flex; flex-direction:column; box-shadow:0 20px 60px rgba(0,0,0,.3);';
  const header = document.createElement('div');
  header.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:16px 20px; border-bottom:1px solid #e5e4dc; gap:8px;';
  const titleEl = document.createElement('h3');
  titleEl.textContent = title;
  titleEl.style.cssText = 'margin:0; font-size:16px; color:#202b27; font-family:\'Manrope\',sans-serif; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
  const closeBtn = document.createElement('button');
  closeBtn.textContent = '×'; closeBtn.type = 'button';
  closeBtn.style.cssText = 'background:none; border:0; font-size:26px; line-height:1; cursor:pointer; color:#7d8680; padding:0 4px; flex-shrink:0;';
  closeBtn.onclick = closeModal;
  header.append(titleEl, closeBtn);
  const body = document.createElement('div');
  body.style.cssText = 'padding:16px 20px; overflow-y:auto; flex:1;';
  buildContent(body);
  modal.append(header, body);
  overlay.append(modal);
  document.body.append(overlay);
  activeModal = overlay;
}

function inlineField(parent, labelText, type, value, onChange, opts = {}) {
  const wrap = document.createElement('div');
  wrap.style.cssText = 'margin-bottom:12px;';
  const lab = document.createElement('label');
  lab.textContent = labelText;
  lab.style.cssText = 'display:block; font-size:11px; font-weight:600; color:#4c5851; margin-bottom:4px;';
  const input = document.createElement('input');
  input.type = type; input.value = value; input.inputMode = opts.inputMode || '';
  input.style.cssText = 'width:100%; height:38px; padding:0 10px; border:1px solid #e5e4dc; border-radius:8px; font-size:13px; box-sizing:border-box; font-family:inherit;';
  input.oninput = () => onChange(input.value);
  wrap.append(lab, input);
  parent.append(wrap);
  return input;
}

// ===== ARCHIVES UI =====
async function openArchivesModal(book) {
  const archives = await archiveGetForBook(book.id);
  archives.sort((a, b) => tsOf(b) - tsOf(a));
  openModal(`Archives — ${book.name}`, (body) => {
    if (!archives.length) {
      const empty = document.createElement('p');
      empty.textContent = 'No archives yet. Archive this book from the ⋯ menu to create one.';
      empty.style.cssText = 'color:#7d8680; font-size:13px; text-align:center; padding:24px;';
      body.append(empty); return;
    }
    archives.forEach(arc => {
      const row = document.createElement('div');
      row.style.cssText = 'display:flex; justify-content:space-between; align-items:center; padding:12px; border:1px solid #e5e4dc; border-radius:10px; margin-bottom:8px; cursor:pointer;';
      row.onmouseenter = () => row.style.background = '#f9f9f7';
      row.onmouseleave = () => row.style.background = '';
      const info = document.createElement('div');
      info.style.cssText = 'flex:1; min-width:0;';
      const name = document.createElement('div');
      name.textContent = arc.archiveName;
      name.style.cssText = 'font-size:13px; font-weight:600; color:#202b27; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
      const meta = document.createElement('div');
      const dateStr = new Date(arc.createdAt).toLocaleDateString();
      let syncLabel = arc.synced ? '✓ Synced' : '● Not synced';
      meta.textContent = `${dateStr} · ${syncLabel}`;
      meta.style.cssText = 'font-size:11px; color:#7d8680; margin-top:2px;';
      info.append(name, meta);
      const delBtn = document.createElement('button');
      delBtn.textContent = '⋯';
      delBtn.style.cssText = 'background:none; border:0; cursor:pointer; color:#7d8680; font-size:18px; padding:4px 8px;';
      delBtn.onclick = async (e) => {
        e.stopPropagation();
        const items = [];
        items.push({ label: 'Delete locally only', onClick: async () => {
          if (!window.confirm('Delete this archive from this device? The Sheet tab stays.')) return;
          for (const t of await getBookTransactions(book.id)) if (t.archiveGroup === arc.archiveName) await deleteTransaction(t.id);
          await archiveDelete(arc.id);
          closeModal(); announce('Archive removed from device.');
        }});
        items.push({ label: 'Delete from Sheet too', danger: true, onClick: async () => {
          if (!arc.synced) { alert('This archive was never synced. Use “Delete locally only”.'); return; }
          if (!navigator.onLine) { alert('Deleting from Sheet requires internet.'); return; }
          if (!window.confirm(`Delete the tab “${arc.archiveName}” from your Google Sheet? This cannot be undone.`)) return;
          try {
            await ensureSignedIn();
            const config = await bookConfig(book);
            const tabs = await readSheetTabs(config);
            const tab = tabs.find(t => t.title === arc.archiveName);
            if (tab) await sheetsBatchUpdate(config, [{ deleteSheet: { sheetId: tab.sheetId } }]);
            const dashTab = tabs.find(t => t.title === arc.dashboardName);
            if (dashTab) await sheetsBatchUpdate(config, [{ deleteSheet: { sheetId: dashTab.sheetId } }]);
            for (const t of await getBookTransactions(book.id)) if (t.archiveGroup === arc.archiveName) await deleteTransaction(t.id);
            await archiveDelete(arc.id);
            closeModal(); announce('Archive deleted from Sheet and device.');
          } catch (e) { alert('Failed: ' + (e.message || e)); }
        }});
        showKebabMenu(delBtn, items);
      };
      row.append(info, delBtn);
      row.onclick = () => { closeModal(); openArchiveDetail(book, arc); };
      body.append(row);
    });
    const footer = document.createElement('p');
    footer.style.cssText = 'font-size:11px; color:#7d8680; margin-top:16px; text-align:center; line-height:1.5;';
    footer.innerHTML = `Only your ${MAX_LOCAL_ARCHIVES} most recent archives are stored on this device. Older archives are in your Sheet — <a href="https://docs.google.com/spreadsheets/d/${encodeURIComponent(book.spreadsheetId || '')}/edit" target="_blank" rel="noopener" style="color:#1f6b50;">open the Sheet</a>.`;
    body.append(footer);
  });
}

async function openArchiveDetail(book, arc) {
  const entries = await getArchiveTransactions(book.id, arc.archiveName);
  openModal(arc.archiveName, (body) => {
    if (!entries.length) {
      const p = document.createElement('p');
      p.textContent = 'This archive has no entries.';
      p.style.cssText = 'color:#7d8680; font-size:13px; text-align:center; padding:24px;';
      body.append(p);
    } else {
      const list = document.createElement('div');
      entries.forEach(e => {
        const row = document.createElement('div');
        row.style.cssText = 'display:flex; gap:8px; align-items:center; padding:10px 12px; border-bottom:1px solid #f0efe9;';
        const info = document.createElement('div');
        info.style.cssText = 'flex:1; min-width:0;';
        const rem = document.createElement('div');
        rem.textContent = e.remarks || '—';
        rem.style.cssText = 'font-size:12px; color:#202b27; font-weight:500; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
        const amounts = document.createElement('div');
        const parts = [];
        const inAmt = Number(e.moneyInMinor) || 0, outAmt = Number(e.moneyOutMinor) || 0;
        if (inAmt) parts.push(`<span style="color:#1f6b50;">+ ${formatMoney(inAmt, e.currencyCode || activeCurrencyCode)}</span>`);
        if (outAmt) parts.push(`<span style="color:#ba5a48;">− ${formatMoney(outAmt, e.currencyCode || activeCurrencyCode)}</span>`);
        parts.push(`<span style="color:#a0a59f; margin-left:8px;">${new Date(e.createdAt).toLocaleDateString()}</span>`);
        if (e.dirty) parts.push(`<span style="color:#b17b40; margin-left:8px;">● edited</span>`);
        amounts.innerHTML = parts.join(' ');
        amounts.style.cssText = 'font-size:11px; margin-top:2px;';
        info.append(rem, amounts);
        const editBtn = document.createElement('button');
        editBtn.textContent = 'Edit'; editBtn.className = 'text-button';
        editBtn.style.cssText = 'padding:5px 9px; font-size:10px; min-height:auto;';
        editBtn.onclick = () => openEntryEditor(book, arc, e);
        const delBtn = document.createElement('button');
        delBtn.textContent = 'Delete'; delBtn.className = 'text-button';
        delBtn.style.cssText = 'padding:5px 9px; font-size:10px; min-height:auto; color:#ba5a48;';
        delBtn.onclick = async () => {
          if (!window.confirm('Delete this entry from the archive?')) return;
          if (arc.synced) {
            await putTransaction({ ...e, deleted: true, dirty: true });
            announce('Entry marked for deletion. Sync to update the Sheet.');
          } else {
            await deleteTransaction(e.id);
            announce('Entry removed.');
          }
          closeModal();
          if (navigator.onLine && tokenIsValid()) void syncAll().catch(() => {});
        };
        row.append(info, editBtn, delBtn);
        list.append(row);
      });
      body.append(list);
    }
    const addBtn = document.createElement('button');
    addBtn.className = 'primary-button';
    addBtn.textContent = '+ Add entry';
    addBtn.style.cssText = 'margin-top:16px; width:100%; padding:10px;';
    addBtn.onclick = () => openEntryEditor(book, arc, null);
    body.append(addBtn);
  });
}

function openEntryEditor(book, arc, existing) {
  closeModal();
  const isNew = !existing;
  const draft = existing ? { ...existing } : {
    id: newId(), bookId: book.id, archiveGroup: arc.archiveName, createdAt: new Date().toISOString(),
    currencyCode: activeCurrencyCode, moneyInMinor: 0, moneyOutMinor: 0, remarks: '',
    syncState: arc.synced ? 'synced' : 'pending', dirty: true
  };
  openModal(isNew ? 'Add entry to archive' : 'Edit entry', (body) => {
    let incVal = (Number(draft.moneyInMinor) || 0) / currencyScale();
    let expVal = (Number(draft.moneyOutMinor) || 0) / currencyScale();
    inlineField(body, 'Money came in', 'number', incVal, v => incVal = v, { inputMode: 'decimal' });
    inlineField(body, 'Money went out', 'number', expVal, v => expVal = v, { inputMode: 'decimal' });
    inlineField(body, 'Remarks', 'text', draft.remarks || '', v => draft.remarks = v);
    const saveBtn = document.createElement('button');
    saveBtn.className = 'primary-button';
    saveBtn.textContent = 'Save';
    saveBtn.style.cssText = 'width:100%; padding:10px; margin-top:12px;';
    saveBtn.onclick = async () => {
      const newEntry = {
        ...draft, moneyInMinor: Math.round((Number(incVal) || 0) * currencyScale()),
        moneyOutMinor: Math.round((Number(expVal) || 0) * currencyScale()),
        bookId: book.id, archiveGroup: arc.archiveName, currencyCode: activeCurrencyCode,
        dirty: true, syncState: arc.synced ? 'synced' : 'pending'
      };
      await putTransaction(newEntry);
      closeModal();
      announce(isNew ? 'Entry added to archive.' : 'Entry updated.');
      if (navigator.onLine && tokenIsValid() && arc.synced) void syncAll().catch(() => {});
    };
    body.append(saveBtn);
  });
}

// ===== KEBAB MENU =====
function closeKebabMenu() { if (openKebabMenu) { openKebabMenu.remove(); openKebabMenu = null; openKebabAnchor = null; } document.removeEventListener('click', onDocClickCloseKebab); document.removeEventListener('scroll', closeKebabMenu, true); }
function onDocClickCloseKebab(e) { if (openKebabMenu && !openKebabMenu.contains(e.target) && e.target !== openKebabAnchor) closeKebabMenu(); }
function showKebabMenu(anchor, items) {
  closeKebabMenu();
  const menu = document.createElement('div');
  menu.style.cssText = 'position:fixed; z-index:9999; background:#fff; border:1px solid #e5e4dc; border-radius:10px; box-shadow:0 8px 24px rgba(0,0,0,.12); padding:6px; min-width:200px; font-family:inherit;';
  const rect = anchor.getBoundingClientRect();
  menu.style.top = (rect.bottom + 4) + 'px';
  menu.style.left = Math.max(8, Math.min(rect.right - 200, window.innerWidth - 208)) + 'px';
  for (const item of items) {
    if (item.divider) { const hr = document.createElement('div'); hr.style.cssText = 'height:1px; background:#f0efe9; margin:4px 0;'; menu.append(hr); continue; }
    const btn = document.createElement('button');
    btn.type = 'button'; btn.textContent = item.label;
    btn.style.cssText = 'display:block; width:100%; text-align:left; padding:10px 12px; border:0; background:transparent; cursor:pointer; border-radius:6px; font-size:13px; font-family:inherit;' + (item.danger ? 'color:#ba5a48;' : 'color:#202b27;');
    btn.onmouseenter = () => btn.style.background = '#f5f2ec';
    btn.onmouseleave = () => btn.style.background = 'transparent';
    btn.onclick = () => { closeKebabMenu(); item.onClick(); };
    menu.append(btn);
  }
  document.body.append(menu);
  openKebabMenu = menu; openKebabAnchor = anchor;
  setTimeout(() => { document.addEventListener('click', onDocClickCloseKebab); document.addEventListener('scroll', closeKebabMenu, true); }, 0);
}

// ===== BOOK UI =====
function renderBookSwitcher() {
  const s = elements.bookSelect; if (!s) return;
  const cur = Array.from(s.options).map(o => o.value);
  const want = books.map(b => b.id);
  const match = cur.length === want.length && cur.every((id, i) => id === want[i]);
  const namesChanged = books.some((b, i) => { const o = s.options[i]; return !o || o.textContent !== (b.spreadsheetId ? `${b.name} ✓` : b.name); });
  if (match && !namesChanged) { if (currentBookId) s.value = currentBookId; return; }
  s.replaceChildren();
  if (!books.length) {
    const o = document.createElement('option'); o.value = ''; o.textContent = 'No books yet'; s.append(o); s.disabled = true; return;
  }
  s.disabled = false;
  const had = document.activeElement === s;
  for (const b of books) { const o = document.createElement('option'); o.value = b.id; o.textContent = b.spreadsheetId ? `${b.name} ✓` : b.name; if (b.id === currentBookId) o.selected = true; s.append(o); }
  if (had) s.focus();
}
function renderBooksList() {
  const list = elements.booksList; if (!list) return;
  list.replaceChildren();
  if (!books.length) {
    const empty = document.createElement('div');
    empty.style.cssText = 'padding:16px; text-align:center; color:#7d8680; font-size:12px;';
    empty.textContent = 'No books yet. Use “＋ New book” above to create your first one.';
    list.append(empty); return;
  }
  for (const book of books) {
    const row = document.createElement('div'); row.className = 'books-list-row';
    const nm = document.createElement('span'); nm.className = 'books-list-name';
    nm.textContent = book.name + (book.spreadsheetId ? ' ✓' : ' — no Sheet');
    nm.title = book.spreadsheetId ? (book.spreadsheetName || book.spreadsheetId) : 'No Google Sheet yet';
    nm.style.cssText = 'flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;';
    row.append(nm);
    const kebab = document.createElement('button');
    kebab.type = 'button'; kebab.className = 'text-button'; kebab.textContent = '⋯';
    kebab.setAttribute('aria-label', `Actions for ${book.name}`);
    kebab.style.cssText = 'padding:4px 12px; font-size:20px; line-height:1; min-height:40px; min-width:40px;';
    kebab.onclick = (e) => {
      e.stopPropagation();
      const items = [];
      if (book.spreadsheetId) {
        items.push({ label: 'Open in Google Sheets', onClick: () => window.open(`https://docs.google.com/spreadsheets/d/${encodeURIComponent(book.spreadsheetId)}/edit`, '_blank', 'noopener') });
        items.push({ label: 'Archives…', onClick: () => openArchivesModal(book) });
        items.push({ label: 'Archive this book', onClick: async () => { if (book.id !== currentBookId) await switchBook(book.id); await archiveAndStartFresh(); } });
        items.push({ divider: true });
      } else {
        items.push({ label: 'Create a Sheet for this book', onClick: async () => { const w = book.id === currentBookId; if (!w) await switchBook(book.id); try { await createSheetForBook(book); } finally { if (!w) await switchBook(book.id); } } });
        items.push({ divider: true });
      }
      items.push({ label: 'Rename', onClick: async () => {
        const n = window.prompt('Rename this book:', book.name);
        if (n === null) return;
        try { await renameBook(book, n); renderBookSwitcher(); renderBooksList(); await refreshView(); announce(`Renamed to “${book.name}”.`); }
        catch (e) { alert(e.message); }
      }});
      if (books.length > 1) {
        items.push({ label: 'Delete', danger: true, onClick: async () => {
          const c = (await getBookTransactions(book.id)).length;
          let msg = `Delete the book “${book.name}”?\n\n• ${c} ${c === 1 ? 'entry' : 'entries'} will be erased from this device.\n`;
          if (book.spreadsheetId) msg += `• Its Sheet stays in your Drive unless you also delete it.\n`;
          msg += `\nContinue?`;
          if (!window.confirm(msg)) return;
          let delSheet = false;
          if (book.spreadsheetId) delSheet = window.confirm(`Also delete “${book.spreadsheetName || book.spreadsheetId}” from Drive?\n\nOK = delete Sheet too.\nCancel = keep Sheet, delete only local copy.`);
          try { await deleteBook(book, { deleteSheet: delSheet }); renderBookSwitcher(); renderBooksList(); await refreshView(); announce(`Deleted “${book.name}”.`); }
          catch (e) { alert(e.message); }
        }});
      }
      showKebabMenu(kebab, items);
    };
    row.append(kebab);
    list.append(row);
  }
}

// ===== CURRENCY / MONEY =====
function currencyFractionDigits(c = activeCurrencyCode) { return new Intl.NumberFormat(undefined, { style: 'currency', currency: c }).resolvedOptions().maximumFractionDigits; }
function currencyScale(c = activeCurrencyCode) { return 10 ** currencyFractionDigits(c); }
function configureCurrency(code) {
  const n = String(code || DEFAULT_CURRENCY).trim().toUpperCase();
  const fd = currencyFractionDigits(n);
  activeCurrencyCode = n;
  const st = 1 / (10 ** fd);
  elements.moneyIn.step = String(st); elements.moneyOut.step = String(st);
  const ph = fd ? `0.${'0'.repeat(fd)}` : '0';
  elements.moneyIn.placeholder = ph; elements.moneyOut.placeholder = ph;
  currencyFormatters.set(n, new Intl.NumberFormat(undefined, { style: 'currency', currency: n, minimumFractionDigits: fd, maximumFractionDigits: fd }));
  $('currencyLabelIn').textContent = `(${n})`; $('currencyLabelOut').textContent = `(${n})`;
  return n;
}
function moneyToMinorUnits(v, c = activeCurrencyCode) { const n = Number(v); return Number.isFinite(n) && n >= 0 ? Math.round(n * currencyScale(c)) : 0; }
function parseMoney(v, c = activeCurrencyCode) { if (typeof v === 'number') return Number.isFinite(v) ? Math.round(v * currencyScale(c)) : 0; const n = Number(String(v ?? '').replace(/,/g, '').replace(/[^\d.-]/g, '')); return Number.isFinite(n) ? Math.round(n * currencyScale(c)) : 0; }
function formatMoney(m, c = activeCurrencyCode) {
  let f = currencyFormatters.get(c);
  if (!f) { const fd = currencyFractionDigits(c); f = new Intl.NumberFormat(undefined, { style: 'currency', currency: c, minimumFractionDigits: fd, maximumFractionDigits: fd }); currencyFormatters.set(c, f); }
  return f.format((Number(m) || 0) / currencyScale(c));
}
function localTimeLabel(r) {
  if (r.createdAt) { const d = new Date(r.createdAt); if (!Number.isNaN(d.getTime())) return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(d); }
  return r.sheetTimestamp || 'Saved in Google Sheets';
}
function announce(m) { elements.toast.textContent = m; elements.toast.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => elements.toast.classList.remove('show'), 3200); }
function setFeedback(m, isErr = false) { elements.formFeedback.textContent = m; elements.formFeedback.classList.toggle('error', isErr); }
function setSetupStatus(m, isErr = false) { elements.setupStatus.textContent = m; elements.setupStatus.classList.toggle('error', isErr); if (elements.onboardingStatus) { elements.onboardingStatus.textContent = m; elements.onboardingStatus.classList.toggle('error', isErr); } }
function updateOnboarding() {
  const any = books.some(b => b.spreadsheetId);
  if (elements.onboardingCard) elements.onboardingCard.hidden = any;
  if (elements.archivePanel) elements.archivePanel.hidden = !any;
  const active = activeBook()?.spreadsheetId;
  if (elements.openSheetLink) { elements.openSheetLink.hidden = !active; if (active) elements.openSheetLink.href = `https://docs.google.com/spreadsheets/d/${encodeURIComponent(active)}/edit`; }
}
function setArchiveStatus(m, isErr = false) { if (!elements.archiveStatus) return; elements.archiveStatus.textContent = m; elements.archiveStatus.classList.toggle('error', isErr); }
function setSyncStatus(title, msg, mode = 'ready') {
  elements.syncTitle.textContent = title; elements.syncMessage.textContent = msg;
  elements.onlineDot.classList.toggle('offline', !navigator.onLine || mode === 'offline');
  elements.syncNow.hidden = mode !== 'pending' && mode !== 'error';
}
function setInlineErr(nearEl, msg, id) {
  if (!nearEl) return;
  let err = id ? document.getElementById(id) : null;
  if (!err) { err = document.createElement('div'); if (id) err.id = id; err.style.cssText = 'color:#ba5a48; font-size:11px; margin-top:4px; line-height:1.4;'; nearEl.parentNode.insertBefore(err, nearEl.nextSibling); }
  err.textContent = msg || '';
  err.style.display = msg ? 'block' : 'none';
}

// ===== TRANSACTION ENTRY =====
async function createTransaction(event) {
  event.preventDefault();
  if (!currentBookId) { setFeedback('Create a book first using “＋ New book” at the top.', true); return; }
  const btn = elements.transactionForm.querySelector('button[type="submit"]');
  if (btn?.disabled) return;
  const inc = moneyToMinorUnits(elements.moneyIn.value), exp = moneyToMinorUnits(elements.moneyOut.value), rem = elements.remarks.value.trim();
  if (inc <= 0 && exp <= 0) { setFeedback('Enter an amount for money in or money out.', true); return; }
  const rec = { id: newId(), bookId: currentBookId, createdAt: new Date().toISOString(), currencyCode: activeCurrencyCode, moneyInMinor: inc, moneyOutMinor: exp, remarks: rem, syncState: 'pending', source: 'local' };
  if (btn) btn.disabled = true;
  try {
    await putTransaction(rec);
    elements.transactionForm.reset();
    setFeedback(`Saved to ${activeBook().name} at ${localTimeLabel(rec)}.`);
    await refreshView();
    if (navigator.onLine && tokenIsValid() && activeBook()?.spreadsheetId) void syncBookToSheet(activeBook()).catch(() => {});
    else if (navigator.onLine) setSyncStatus('Saved on this device', 'Connect Google to upload.', 'pending');
    else setSyncStatus('Saved offline', 'Queued for when you are online.', 'offline');
  } catch (e) { setFeedback(e.message || 'Could not save.', true); }
  finally { if (btn) btn.disabled = false; }
}
function renderTransactions(recs) {
  const vis = recs.slice().sort((a, b) => tsOf(b) - tsOf(a)).slice(0, 40);
  elements.recordCount.textContent = `${recs.length} ${recs.length === 1 ? 'record' : 'records'}`;
  elements.transactionList.replaceChildren();
  if (!vis.length) { const e = document.createElement('div'); e.className = 'empty-state'; e.innerHTML = '<span class="empty-icon" aria-hidden="true">＋</span><strong>No transactions yet</strong><span>Your entries will appear here.</span>'; elements.transactionList.append(e); return; }
  for (const r of vis) {
    const im = Number(r.moneyInMinor) || 0, om = Number(r.moneyOutMinor) || 0;
    const kind = im && om ? 'mixed' : im ? 'income' : 'expense';
    const row = document.createElement('article'); row.className = 'transaction-row';
    const main = document.createElement('div'); main.className = 'transaction-main';
    const ic = document.createElement('span'); ic.className = `transaction-icon ${kind}`; ic.setAttribute('aria-hidden', 'true'); ic.textContent = kind === 'income' ? '↙' : kind === 'expense' ? '↗' : '↔';
    const txt = document.createElement('div'); txt.className = 'transaction-text';
    const rem = document.createElement('span'); rem.className = 'transaction-remark'; rem.textContent = r.remarks || (kind === 'income' ? 'Money came in' : kind === 'expense' ? 'Money went out' : 'Money in and out');
    const tm = document.createElement('span'); tm.className = 'transaction-time'; tm.textContent = localTimeLabel(r);
    txt.append(rem, tm); main.append(ic, txt);
    const am = document.createElement('div'); am.className = 'transaction-amounts';
    if (im) { const a = document.createElement('span'); a.className = 'in'; a.textContent = `+ ${formatMoney(im, r.currencyCode || activeCurrencyCode)}`; am.append(a); }
    if (om) { const a = document.createElement('span'); a.className = 'out'; a.textContent = `− ${formatMoney(om, r.currencyCode || activeCurrencyCode)}`; am.append(a); }
    const sy = document.createElement('small'); sy.className = `transaction-sync ${r.syncState === 'pending' ? 'pending' : ''}`;
    sy.textContent = r.syncState === 'pending' ? 'Waiting to sync' : 'On this device and Sheet';
    am.append(sy); row.append(main, am); elements.transactionList.append(row);
  }
}
async function refreshView() {
  const recs = await getActiveBookRecords();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const inc = recs.reduce((s, x) => s + (Number(x.moneyInMinor) || 0), 0);
  const exp = recs.reduce((s, x) => s + (Number(x.moneyOutMinor) || 0), 0);
  const sb = currentBookId ? (Number(await getSetting(`startingBalance:${currentBookId}`, 0)) || 0) : 0;
  elements.incomeTotal.textContent = formatMoney(inc); elements.expenseTotal.textContent = formatMoney(exp);
  elements.balanceTotal.textContent = formatMoney(sb + inc - exp);
  elements.balanceNote.textContent = sb ? `Includes your ${formatMoney(sb)} starting balance` : 'Starting balance plus money in minus money out';
  renderTransactions(recs); renderBookSwitcher(); renderBooksList();
  if (elements.historyFootnote) elements.historyFootnote.textContent = unreadableCount ? `${unreadableCount} saved ${unreadableCount === 1 ? 'entry' : 'entries'} could not be read on this device.` : 'This device keeps your recent records available offline.';
  const pending = recs.filter(x => x.syncState === 'pending').length;
  const allArcs = currentBookId ? await archiveGetForBook(currentBookId) : [];
  const unsyncedArcs = allArcs.filter(a => !a.synced);
  const allTxns = currentBookId ? await getBookTransactions(currentBookId) : [];
  const dirtyArcs = allTxns.filter(r => r.archiveGroup && (r.dirty || r.deleted)).length;
  const hasSheet = !!activeBook()?.spreadsheetId;
  updateOnboarding();
  if (!books.length) setSyncStatus('No books yet', 'Tap “＋ New book” to create your first cashbook.', 'ready');
  else if (unsyncedArcs.length) setSyncStatus('Archive pending', `Sync while online to complete “${unsyncedArcs[0].archiveName}”.`, 'pending');
  else if (!navigator.onLine) setSyncStatus(pending ? 'Saved offline' : 'You are offline', pending ? `${pending} ${pending === 1 ? 'entry is' : 'entries are'} waiting.` : 'Your cashbook is available offline.', 'offline');
  else if (pending || dirtyArcs) setSyncStatus('Waiting to sync', `${pending + dirtyArcs} ${pending + dirtyArcs === 1 ? 'change is' : 'changes are'} saved here. ${hasSheet ? 'Tap “Sync now”.' : 'Connect a Google Sheet.'}`, 'pending');
  else if (!hasSheet) setSyncStatus('Saved on this device', `“${activeBook()?.name || 'This book'}” has no Sheet yet. Open ⋯ in Settings → Books.`, 'pending');
  else if (!tokenIsValid()) setSyncStatus('Google Sheet connected', 'Everything is saved. Tap “Sync now” to refresh.', 'pending');
  else setSyncStatus('Google Sheet connected', 'New entries sync automatically while open and online.', 'ready');
}

// ===== GOOGLE AUTH =====
function spreadsheetIdFrom(v) { const m = String(v || '').trim().match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/); return m ? m[1] : String(v || '').trim(); }
async function loadConfigFromForm() {
  const saved = await getSetting('googleConfig', {}); const book = activeBook();
  return { currencyCode: elements.currencyCode?.value?.trim().toUpperCase() || saved.currencyCode || DEFAULT_CURRENCY, clientId: elements.clientId?.value?.trim() || saved.clientId || DEFAULT_CLIENT_ID, apiKey: elements.apiKey?.value?.trim() || saved.apiKey || DEFAULT_API_KEY, appId: elements.appId?.value?.trim() || saved.appId || DEFAULT_APP_ID, spreadsheetId: spreadsheetIdFrom(elements.spreadsheetInput?.dataset?.spreadsheetId || book?.spreadsheetId || ''), spreadsheetName: elements.spreadsheetInput?.dataset?.spreadsheetName || book?.spreadsheetName || '', responseTab: elements.responseTab?.value?.trim() || book?.responseTab || 'Form responses 1', dashboardTab: elements.dashboardTab?.value?.trim() || book?.dashboardTab || 'Dashboard' };
}
async function loadSavedConfig() {
  const c = await bookConfig(activeBook());
  const cc = configureCurrency(c.currencyCode || DEFAULT_CURRENCY);
  if (elements.currencyCode) elements.currencyCode.value = cc;
  if (elements.clientId) elements.clientId.value = c.clientId || DEFAULT_CLIENT_ID;
  if (elements.apiKey) elements.apiKey.value = c.apiKey || DEFAULT_API_KEY;
  if (elements.appId) elements.appId.value = c.appId || DEFAULT_APP_ID;
  const sid = c.spreadsheetId || '', sn = c.spreadsheetName || '';
  if (elements.spreadsheetInput) { elements.spreadsheetInput.dataset.spreadsheetId = sid; elements.spreadsheetInput.dataset.spreadsheetName = sn; elements.spreadsheetInput.value = sid ? `${sn || 'Selected'} · ${sid}` : ''; }
  if (elements.responseTab) elements.responseTab.value = c.responseTab || 'Form responses 1';
  if (elements.dashboardTab) elements.dashboardTab.value = c.dashboardTab || 'Dashboard';
}
async function saveConfig() {
  const f = await loadConfigFromForm();
  try {
    await persistCurrencyCode(f.currencyCode);
    const saved = await getSetting('googleConfig', {});
    await saveSetting('googleConfig', { ...saved, clientId: f.clientId, apiKey: f.apiKey, appId: f.appId, currencyCode: f.currencyCode });
    await updateActiveBookConfig({ spreadsheetId: f.spreadsheetId, spreadsheetName: f.spreadsheetName, responseTab: f.responseTab, dashboardTab: f.dashboardTab });
    setSetupStatus(`Settings saved for “${activeBook()?.name || 'this device'}”.`);
    announce('Settings saved.'); await refreshView();
  } catch (e) { setSetupStatus(e.message || 'Could not save settings.', true); }
}
async function persistCurrencyCode(code) {
  let n;
  try { n = configureCurrency(code); } catch { throw new Error('Enter a 3-letter currency like NPR, USD, EUR, INR.'); }
  const cur = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const recs = await getAllTransactions();
  if (recs.length && n !== cur) { configureCurrency(cur); elements.currencyCode.value = cur; throw new Error(`This device already has records in ${cur}.`); }
  await saveSetting('currencyCode', n); return n;
}
function loadGoogleIdentity() {
  if (window.google?.accounts?.oauth2) return Promise.resolve();
  return new Promise((res, rej) => {
    const ex = document.querySelector('script[data-google-identity]');
    if (ex) { ex.addEventListener('load', res, { once: true }); ex.addEventListener('error', () => rej(new Error('Could not load Google sign-in.')), { once: true }); return; }
    const s = document.createElement('script'); s.src = 'https://accounts.google.com/gsi/client'; s.async = true; s.defer = true; s.dataset.googleIdentity = 'true';
    s.onload = res; s.onerror = () => rej(new Error('Could not load Google sign-in.')); document.head.append(s);
  });
}
function requestGoogleToken(config, promptMode = '') {
  let ch = false; try { ch = localStorage.getItem(CHOOSE_ACCOUNT_KEY) === '1'; } catch {}
  const pr = ch ? 'select_account' : promptMode;
  return loadGoogleIdentity().then(() => new Promise((res, rej) => {
    const cl = window.google.accounts.oauth2.initTokenClient({ client_id: config.clientId, scope: DRIVE_FILE_SCOPE,
      callback: r => { if (r.error || !r.access_token) { rej(new Error(r.error_description || r.error || 'Not granted.')); return; } saveToken(r.access_token, r.expires_in); try { localStorage.removeItem(CHOOSE_ACCOUNT_KEY); } catch {} res(r.access_token); },
      error_callback: e => rej(new Error(e.message || 'Closed.')) });
    cl.requestAccessToken({ prompt: pr });
  }));
}
function loadGooglePicker() {
  return new Promise((res, rej) => {
    const fin = () => { if (!window.gapi?.load) { rej(new Error('Picker failed.')); return; } window.gapi.load('picker', { callback: res }); };
    if (window.gapi?.load) return fin();
    const ex = document.querySelector('script[data-google-picker]');
    if (ex) { ex.addEventListener('load', fin, { once: true }); ex.addEventListener('error', () => rej(new Error('Could not load Picker.')), { once: true }); return; }
    const s = document.createElement('script'); s.src = 'https://apis.google.com/js/api.js'; s.async = true; s.defer = true; s.dataset.googlePicker = 'true';
    s.onload = fin; s.onerror = () => rej(new Error('Could not load Picker.')); document.head.append(s);
  });
}
function showGoogleSheetPicker(c, token) {
  return loadGooglePicker().then(() => new Promise((res, rej) => {
    try {
      const v = new window.google.picker.DocsView(window.google.picker.ViewId.SPREADSHEETS); v.setIncludeFolders(true); v.setSelectFolderEnabled(false);
      new window.google.picker.PickerBuilder().setAppId(c.appId).setDeveloperKey(c.apiKey).setOAuthToken(token).setOrigin(location.origin).setTitle('Choose a Sheet').addView(v)
        .setCallback(d => { if (d.action === window.google.picker.Action.PICKED) res(d.docs?.[0] || null); if (d.action === window.google.picker.Action.CANCEL) res(null); }).build().setVisible(true);
    } catch (e) { rej(e); }
  }));
}
function showFolderPicker(c, token) {
  return loadGooglePicker().then(() => new Promise((res, rej) => {
    try {
      const v = new window.google.picker.DocsView(window.google.picker.ViewId.FOLDERS); v.setSelectFolderEnabled(true); v.setIncludeFolders(true);
      new window.google.picker.PickerBuilder().setAppId(c.appId).setDeveloperKey(c.apiKey).setOAuthToken(token).setOrigin(location.origin).setTitle('Choose a folder').addView(v)
        .setCallback(d => { if (d.action === window.google.picker.Action.PICKED) res(d.docs?.[0] || null); if (d.action === window.google.picker.Action.CANCEL) res(null); }).build().setVisible(true);
    } catch (e) { rej(e); }
  }));
}
async function connectGoogle() {
  const c = await loadConfigFromForm();
  if (!c.clientId || !c.apiKey || !c.appId) { setSetupStatus('Google credentials missing.', true); elements.settingsPanel.open = true; return; }
  if (!c.spreadsheetId) { setSetupStatus('Choose a Sheet first.', true); elements.settingsPanel.open = true; return; }
  if (!navigator.onLine) { setSetupStatus('Connect while online.', true); return; }
  try { await persistCurrencyCode(c.currencyCode); } catch (e) { setSetupStatus(e.message, true); return; }
  const sv = await getSetting('googleConfig', {});
  await saveSetting('googleConfig', { ...sv, clientId: c.clientId, apiKey: c.apiKey, appId: c.appId, currencyCode: c.currencyCode });
  await updateActiveBookConfig({ responseTab: c.responseTab, dashboardTab: c.dashboardTab });
  elements.connectGoogle.disabled = true; setSetupStatus('Requesting access…');
  try { accessToken = await requestGoogleToken(await bookConfig(activeBook())); await syncAll(); }
  catch (e) { clearSavedToken(); setSetupStatus(e.message, true); }
  finally { elements.connectGoogle.disabled = false; await refreshView(); }
}
async function chooseGoogleSheet() {
  if (!navigator.onLine) { setSetupStatus('Choose while online.', true); return; }
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message, true); return; }
  const c = await loadConfigFromForm();
  if (!c.clientId || !c.apiKey || !c.appId) { setSetupStatus('Google credentials missing.', true); elements.settingsPanel.open = true; return; }
  try { await persistCurrencyCode(c.currencyCode); } catch (e) { setSetupStatus(e.message, true); return; }
  elements.chooseGoogleSheet.disabled = true; setSetupStatus('Opening Sheet picker…');
  try {
    const sv = await getSetting('googleConfig', {}); await saveSetting('googleConfig', { ...sv, clientId: c.clientId, apiKey: c.apiKey, appId: c.appId, currencyCode: c.currencyCode });
    const sel = await showGoogleSheetPicker(c, accessToken);
    if (!sel) { setSetupStatus('No Sheet selected.'); return; }
    c.spreadsheetId = sel.id; c.spreadsheetName = sel.name || 'Selected';
    try { const tabs = await readSheetTabs({ ...c, spreadsheetId: sel.id }); const tt = tabs.map(t => t.title); c.responseTab = tt.find(t => /form responses/i.test(t)) || tt.find(t => !/dashboard/i.test(t) && t !== PERIODS_TAB) || activeBook()?.name || 'Personal'; c.dashboardTab = tt.find(t => /dashboard/i.test(t)) || 'Dashboard'; } catch {}
    elements.spreadsheetInput.dataset.spreadsheetId = c.spreadsheetId; elements.spreadsheetInput.dataset.spreadsheetName = c.spreadsheetName; elements.spreadsheetInput.value = `${c.spreadsheetName} · ${c.spreadsheetId}`;
    if (elements.responseTab) elements.responseTab.value = c.responseTab;
    if (elements.dashboardTab) elements.dashboardTab.value = c.dashboardTab;
    await updateActiveBookConfig({ spreadsheetId: c.spreadsheetId, spreadsheetName: c.spreadsheetName, responseTab: c.responseTab, dashboardTab: c.dashboardTab });
    setSetupStatus(`Selected “${c.spreadsheetName}”. Loading history…`);
    await syncAll();
  } catch (e) { clearSavedToken(); setSetupStatus(e.message, true); }
  finally { elements.chooseGoogleSheet.disabled = false; }
}

// ===== DRIVE =====
async function driveRequest(url, opt = {}) {
  if (!accessToken || tokenExpiresAt <= Date.now() + 5000) throw new Error('Google access expired.');
  const r = await fetch(url, { ...opt, headers: { Authorization: `Bearer ${accessToken}`, ...(opt.body ? { 'Content-Type': 'application/json' } : {}), ...(opt.headers || {}) } });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) { if (r.status === 401) clearSavedToken(); throw new Error(body.error?.message || `Drive ${r.status}`); }
  return body;
}
async function createDriveFolder(name, parentId = null) {
  const body = { name: String(name || 'Untitled'), mimeType: 'application/vnd.google-apps.folder' };
  if (parentId) body.parents = [parentId];
  const b = await driveRequest('https://www.googleapis.com/drive/v3/files?fields=id', { method: 'POST', body: JSON.stringify(body) });
  if (!b.id) throw new Error('Folder ID missing.');
  return b.id;
}
async function moveFileToFolder(fileId, folderId) {
  if (!accessToken || !folderId) return false;
  try { await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?addParents=${encodeURIComponent(folderId)}&removeParents=root&fields=id,parents`, { method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}` } }); return true; }
  catch { return false; }
}
async function driveDeleteFile(fileId) { if (!accessToken) throw new Error('Not signed in.'); await fetch(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}`, { method: 'DELETE', headers: { Authorization: `Bearer ${accessToken}` } }); }

async function askForFolder(c, suggestedName) {
  const i = window.prompt(`Where should the folder go?\n\n• Type a folder name to create a new one (blank = "Untitled").\n• Type "pick" to browse existing folders.`, suggestedName || '');
  if (i === null) return null;
  const t = i.trim();
  if (t.toLowerCase() === 'pick') {
    try { const p = await showFolderPicker(c, accessToken); return { parentFolderId: p ? p.id : null }; }
    catch { return { parentFolderId: null }; }
  }
  const name = t || 'Untitled';
  try { return { folderId: await createDriveFolder(name) }; }
  catch (e) { setSetupStatus(e.message, true); return { folderId: null }; }
}

// ===== SHEET CREATION =====
function buildDashboardValues(c, sb = 0) {
  const t = quoteSheetName(c.responseTab);
  const m = col => `=SUMIFS(${t}!${col}:${col},${t}!A:A,">="&EOMONTH(TODAY(),-1)+1,${t}!A:A,"<"&EOMONTH(TODAY(),0)+1)`;
  return [['MY MONEY DASHBOARD', ''], ['', ''], ['Total Money Came In', `=SUMIFS(${t}!B:B,${t}!A:A,">0")`], ['Total Money Went Out', `=SUMIFS(${t}!C:C,${t}!A:A,">0")`], ['Net money movement', '=B3-B4'], ['', ''], ['MONTHLY SUMMARY', ''], ['Money Came In This Month', m('B')], ['Money Went Out This Month', m('C')], ['Net Movement This Month', '=B8-B9'], ['', ''], ['Starting balance (set it in B13)', ''], ['', sb || 0]];
}
async function styleNewSheet(c, created) {
  const ids = new Map((created.sheets || []).map(s => [s.properties.title, s.properties.sheetId]));
  const rid = ids.get(c.responseTab), did = ids.get(c.dashboardTab);
  if (rid === undefined || did === undefined) return;
  const sym = c.currencyCode === 'NPR' ? 'Rs' : c.currencyCode;
  const money = { type: 'NUMBER', pattern: `"${sym} "#,##0.00` };
  const green = { red: 0.122, green: 0.42, blue: 0.314 }, white = { red: 1, green: 1, blue: 1 };
  const cell = (sid, r0, r1, c0, c1, f, fs) => ({ repeatCell: { range: { sheetId: sid, startRowIndex: r0, endRowIndex: r1, startColumnIndex: c0, endColumnIndex: c1 }, cell: { userEnteredFormat: f }, fields: fs } });
  const w = (sid, s, e, px) => ({ updateDimensionProperties: { range: { sheetId: sid, dimension: 'COLUMNS', startIndex: s, endIndex: e }, properties: { pixelSize: px }, fields: 'pixelSize' } });
  await sheetsBatchUpdate(c, [
    { updateSheetProperties: { properties: { sheetId: rid, gridProperties: { frozenRowCount: 1 } }, fields: 'gridProperties.frozenRowCount' } },
    cell(rid, 0, 1, 0, 4, { backgroundColor: green, textFormat: { bold: true, foregroundColor: white } }, 'userEnteredFormat(backgroundColor,textFormat)'),
    cell(rid, 1, 2000, 0, 1, { numberFormat: { type: 'DATE_TIME', pattern: 'dd mmm yyyy, hh:mm' }, horizontalAlignment: 'LEFT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    cell(rid, 1, 2000, 1, 3, { numberFormat: { type: 'NUMBER', pattern: '#,##0.00' } }, 'userEnteredFormat.numberFormat'),
    w(rid, 0, 1, 190), w(rid, 1, 3, 170), w(rid, 3, 4, 280), w(rid, 4, 5, 300),
    cell(did, 0, 1, 0, 1, { textFormat: { bold: true, fontSize: 14 } }, 'userEnteredFormat.textFormat'),
    cell(did, 6, 7, 0, 1, { textFormat: { bold: true, fontSize: 12 } }, 'userEnteredFormat.textFormat'),
    cell(did, 4, 5, 0, 2, { textFormat: { bold: true } }, 'userEnteredFormat.textFormat'),
    cell(did, 9, 10, 0, 2, { textFormat: { bold: true } }, 'userEnteredFormat.textFormat'),
    cell(did, 2, 5, 1, 2, { numberFormat: money, horizontalAlignment: 'RIGHT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    cell(did, 7, 10, 1, 2, { numberFormat: money, horizontalAlignment: 'RIGHT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    cell(did, 12, 13, 1, 2, { numberFormat: money, horizontalAlignment: 'RIGHT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    w(did, 0, 1, 280), w(did, 1, 2, 180)
  ]);
}
async function createSheetForBook(book, opt = {}) {
  const { syncAfter = true, askFolder = true } = opt;
  if (!navigator.onLine) { setSetupStatus('Creating a Sheet needs internet.', true); return; }
  if (book.spreadsheetId) {
    if (!window.confirm(`"${book.name}" already has a Sheet. Create a new one anyway? The old Sheet stays in your Drive.`)) return;
  }
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message, true); return; }
  const c = await loadConfigFromForm();
  if (!c.clientId || !c.apiKey || !c.appId) { setSetupStatus('Google credentials missing.', true); return; }
  const bookName = book.name;
  const sheetTitle = `${bookName} Entries`;
  const responseTab = book.responseTab || bookName;
  const dashboardTab = book.dashboardTab || 'Dashboard';
  let folderId = null;
  if (askFolder) {
    const res = await askForFolder(c, bookName + ' - My Cashbook');
    if (res === null) { setSetupStatus('Cancelled.'); return; }
    folderId = res.folderId;
  }
  elements.createNewSheet.disabled = true; elements.chooseGoogleSheet.disabled = true;
  setSetupStatus(`Creating “${sheetTitle}”…`);
  let sid = null, created = null;
  try {
    const sv = await getSetting('googleConfig', {}); await saveSetting('googleConfig', { ...sv, clientId: c.clientId, apiKey: c.apiKey, appId: c.appId, currencyCode: c.currencyCode });
    const r = await fetch('https://sheets.googleapis.com/v4/spreadsheets', { method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ properties: { title: sheetTitle }, sheets: [{ properties: { title: responseTab } }, { properties: { title: dashboardTab } }] }) });
    created = await r.json().catch(() => ({}));
    if (!r.ok) { if (r.status === 401) clearSavedToken(); throw new Error(created.error?.message || `Google ${r.status}`); }
    sid = created.spreadsheetId;
    if (!sid) throw new Error('No spreadsheet ID returned.');
    if (folderId) await moveFileToFolder(sid, folderId);
    book.spreadsheetId = sid; book.spreadsheetName = created.properties?.title || sheetTitle; book.responseTab = responseTab; book.dashboardTab = dashboardTab; await saveBooks();
    const headers = ['Timestamp', `Money Came In (${c.currencyCode})`, `Money Went Out (${c.currencyCode})`, 'Remarks'];
    await sheetsRequest(sheetValuesUrl(sid, `${quoteSheetName(responseTab)}!A1:D1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [headers] }) });
    await sheetsRequest(sheetValuesUrl(sid, `${quoteSheetName(dashboardTab)}!A1:B13`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: buildDashboardValues({ ...c, responseTab, dashboardTab }, 0) }) });
    try { await styleNewSheet({ ...c, responseTab, dashboardTab, currencyCode: c.currencyCode }, created); } catch {}
    await saveSetting(`startingBalance:${book.id}`, 0);
    await saveSetting(`periodStart:${book.id}`, '');
    await refreshView();
    const pend = (await getBookTransactions(book.id)).filter(r => r.syncState === 'pending').length;
    setSetupStatus(`Created “${book.spreadsheetName}”. ${pend > 0 ? `${pend} ${pend === 1 ? 'entry is' : 'entries are'} waiting — tap “Sync now”.` : 'Ready.'}`);
    announce('Sheet created.');
    if (syncAfter) await syncAll();
  } catch (e) {
    if (sid) { book.spreadsheetId = sid; book.spreadsheetName = created?.properties?.title || sheetTitle; book.responseTab = responseTab; book.dashboardTab = dashboardTab; try { await saveBooks(); } catch {} setSetupStatus(`Sheet created but setup failed: ${e.message}.`, true); }
    else setSetupStatus(e.message || 'Could not create the Sheet.', true);
  }
  finally { elements.createNewSheet.disabled = false; elements.chooseGoogleSheet.disabled = false; await refreshView(); }
}
async function fullResetWithNewSheet() {
  if (!navigator.onLine) { setSetupStatus('Starting over needs internet.', true); return; }
  if (!window.confirm('Start over completely?\n\n• ALL books and ALL their entries will be erased from this device.\n• Sheets already in Drive are NOT deleted.\n• A new Sheet will be created. Books must be added after.\n\nContinue?')) { setSetupStatus('Cancelled.'); return; }
  const typed = window.prompt('Type ERASE to confirm.'); if (typed === null) { setSetupStatus('Cancelled.'); return; }
  if (typed.trim() !== 'ERASE') { setSetupStatus('Cancelled — type ERASE exactly.', true); return; }
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message, true); return; }
  const c = await loadConfigFromForm();
  if (!c.clientId || !c.apiKey || !c.appId) { setSetupStatus('Google credentials missing.', true); return; }
  setSetupStatus('Erasing this device’s data…');
  try {
    for (const r of await getAllTransactions()) await deleteTransaction(r.id);
    for (const b of books) { await deleteSetting(`startingBalance:${b.id}`); await deleteSetting(`periodStart:${b.id}`); }
    await saveSetting(BOOKS_KEY, []); await saveSetting(ARCHIVES_KEY, []); await saveSetting(CURRENT_BOOK_KEY, ''); books = []; currentBookId = null;
    const folderRes = await askForFolder(c, 'My Cashbook');
    if (folderRes === null) { await refreshView(); setSetupStatus('Cancelled after erase. No books remain — create one with “＋ New book”.'); return; }
    const folderId = folderRes.folderId;
    setSetupStatus('Creating new Sheet…');
    const title = 'My Cashbook';
    const rt = 'Personal';
    const dt = 'Dashboard';
    const r = await fetch('https://sheets.googleapis.com/v4/spreadsheets', { method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ properties: { title }, sheets: [{ properties: { title: rt } }, { properties: { title: dt } }] }) });
    const created = await r.json().catch(() => ({}));
    if (!r.ok) { if (r.status === 401) clearSavedToken(); throw new Error(created.error?.message || `Google ${r.status}`); }
    const sid = created.spreadsheetId;
    if (!sid) throw new Error('No spreadsheet ID returned.');
    if (folderId) await moveFileToFolder(sid, folderId);
    await saveSetting('reservedSheet', { spreadsheetId: sid, spreadsheetName: created.properties?.title || title, responseTab: rt, dashboardTab: dt });
    const headers = ['Timestamp', `Money Came In (${c.currencyCode})`, `Money Went Out (${c.currencyCode})`, 'Remarks'];
    await sheetsRequest(sheetValuesUrl(sid, `${quoteSheetName(rt)}!A1:D1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [headers] }) });
    await sheetsRequest(sheetValuesUrl(sid, `${quoteSheetName(dt)}!A1:B13`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: buildDashboardValues({ ...c, responseTab: rt, dashboardTab: dt }, 0) }) });
    try { await styleNewSheet({ ...c, responseTab: rt, dashboardTab: dt, currencyCode: c.currencyCode }, created); } catch {}
    await refreshView();
    setSetupStatus(`Fresh start. New Sheet “${title}” created. Add a book with “＋ New book” — it will attach to this Sheet.`);
    announce('Fresh start ready.');
  } catch (e) { setSetupStatus(e.message || 'Could not complete reset.', true); }
}

// ===== SHEET I/O =====
function quoteSheetName(n) { return `'${String(n).replace(/'/g, "''")}'`; }
function formatSheetTimestamp(t, tz) {
  const d = new Date(t); if (Number.isNaN(d.getTime())) throw new Error('Invalid date.');
  const p = {};
  for (const x of new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).formatToParts(d)) if (x.type !== 'literal') p[x.type] = x.value;
  return `${p.year}-${p.month}-${p.day} ${p.hour}:${p.minute}:${p.second}`;
}
function sheetSerialToIso(s, tz) {
  const w = Math.round(((Number(s) - 25569) * 86400000) / 1000) * 1000;
  if (!Number.isFinite(w)) return null;
  if (!tz) return new Date(w + new Date(w).getTimezoneOffset() * 60000).toISOString();
  const fm = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
  const off = ms => { const p = {}; for (const x of fm.formatToParts(new Date(ms))) if (x.type !== 'literal') p[x.type] = Number(x.value); return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - Math.floor(ms / 1000) * 1000; };
  let u = w - off(w); u = w - off(u); return new Date(u).toISOString();
}
function columnName(n) { let v = n, r = ''; while (v > 0) { const rem = (v - 1) % 26; r = String.fromCharCode(65 + rem) + r; v = Math.floor((v - 1) / 26); } return r; }
function safeSheetText(v) { const t = String(v ?? ''); if (!t) return ''; return /^[=+\-@\t\r\n]/.test(t) ? `'${t}` : t; }
async function sheetsRequest(url, opt = {}) {
  if (!accessToken || tokenExpiresAt <= Date.now() + 5000) throw new Error('Google access expired. Tap “Sync now”.');
  const r = await fetch(url, { ...opt, headers: { Authorization: `Bearer ${accessToken}`, ...(opt.body ? { 'Content-Type': 'application/json' } : {}), ...(opt.headers || {}) } });
  const b = await r.json().catch(() => ({}));
  if (!r.ok) { if (r.status === 401) clearSavedToken(); throw new Error(b.error?.message || `Sheets ${r.status}`); }
  return b;
}
async function readSpreadsheetTimeZone(c) { const d = await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(c.spreadsheetId)}?fields=properties.timeZone`); return d.properties?.timeZone || undefined; }
function sheetValuesUrl(id, range, q = '') { const b = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(id)}/values/${encodeURIComponent(range)}`; return q ? `${b}?${q}` : b; }
function findHeaderIndex(h, p) { return h.findIndex(x => p.test(String(x || '').toLowerCase().replace(/[()]/g, ''))); }
async function ensureResponseHeader(c) {
  const d = await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(c.responseTab)}!A1:Z1`, 'valueRenderOption=FORMATTED_VALUE'));
  const h = d.values?.[0] || [];
  const ti = findHeaderIndex(h, /timestamp|date\s*(and|&)\s*time/);
  const ii = findHeaderIndex(h, /money\s*came\s*in/);
  const ei = findHeaderIndex(h, /money\s*went\s*out/);
  const ri = findHeaderIndex(h, /remarks?/);
  if ([ti, ii, ei, ri].some(x => x < 0)) throw new Error(`First row of “${c.responseTab}” must include Timestamp, Money Came In, Money Went Out, Remarks.`);
  for (const x of [ii, ei]) { const cur = String(h[x] || '').match(/\(([A-Z]{3})\)/i)?.[1]?.toUpperCase(); if (cur && cur !== c.currencyCode) throw new Error(`Sheet labeled ${cur}. App set to ${c.currencyCode}.`); }
  let idI = h.findIndex(x => String(x || '').trim().toLowerCase() === 'offline entry id');
  if (idI < 0) {
    idI = Math.max(ti, ii, ei, ri) + 1;
    await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(c.responseTab)}!${columnName(idI + 1)}1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [['Offline Entry ID']] }) });
    h[idI] = 'Offline Entry ID';
  }
  return { headers: h, timestampIndex: ti, incomeIndex: ii, expenseIndex: ei, remarksIndex: ri, idIndex: idI };
}
function isSummaryRow(r) { const l = String(r[0] ?? '').trim().toUpperCase(); return l.startsWith('TOTAL') || l.startsWith('REMAINING'); }
function parseSheetRow(r, idx, ix, cur, tz) {
  const rid = String(r[ix.idIndex] || '').trim();
  const rt = r[ix.timestampIndex]; const ts = String(rt ?? '').trim();
  if (!ts && !r[ix.incomeIndex] && !r[ix.expenseIndex] && !r[ix.remarksIndex]) return null;
  if (isSummaryRow(r) || ts.toUpperCase().startsWith('TOTAL')) return null;
  const id = rid || `sheet-row-${idx + 2}`;
  let ca = null;
  if (typeof rt === 'number') ca = sheetSerialToIso(rt, tz);
  else if (ts) { const p = Date.parse(ts); ca = Number.isNaN(p) ? null : new Date(p).toISOString(); }
  return { id, createdAt: ca, sheetTimestamp: typeof rt === 'number' ? '' : ts, currencyCode: cur, moneyInMinor: parseMoney(r[ix.incomeIndex], cur), moneyOutMinor: parseMoney(r[ix.expenseIndex], cur), remarks: String(r[ix.remarksIndex] || ''), syncState: rid ? 'synced' : 'sheet', source: rid ? 'cashbook' : 'sheet' };
}
async function readResponseSheet(c, ix, tz) {
  const lastIndex = Math.max(ix.timestampIndex, ix.incomeIndex, ix.expenseIndex, ix.remarksIndex, ix.idIndex);
  const d = await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(c.responseTab)}!A2:${columnName(lastIndex + 1)}`, 'valueRenderOption=UNFORMATTED_VALUE&dateTimeRenderOption=SERIAL_NUMBER'));
  const records = [], summaryRows = []; let lastEntryRow = 1;
  (d.values || []).forEach((row, i) => { const rn = i + 2; if (isSummaryRow(row)) { summaryRows.push(rn); return; } const rec = parseSheetRow(row, i, ix, c.currencyCode, tz); if (rec) { records.push(rec); lastEntryRow = rn; } });
  return { records, lastEntryRow, summaryRows };
}
async function readResponseRows(c, ix, tz) { return (await readResponseSheet(c, ix, tz)).records; }

const TOTALS_COLORS = { dark: { red: 0.1215, green: 0.4196, blue: 0.3137 }, light: { red: 0.9098, green: 0.9490, blue: 0.9254 }, ink: { red: 0.1215, green: 0.4196, blue: 0.3137 }, white: { red: 1, green: 1, blue: 1 } };
async function responseSheetId(c) { const tabs = await readSheetTabs(c); const t = tabs.find(x => x.title === c.responseTab); return t ? t.sheetId : null; }
const HEADER_STYLE_VERSION = 2;
async function styleHeaderRow(c, ix) {
  const key = `headerStyled:v${HEADER_STYLE_VERSION}:${c.spreadsheetId}`;
  if (await getSetting(key, false)) return;
  const sid = await responseSheetId(c); if (sid === null) return;
  const { dark, white } = TOTALS_COLORS;
  await sheetsBatchUpdate(c, [
    { repeatCell: { range: { sheetId: sid, startRowIndex: 0, endRowIndex: 1, startColumnIndex: 0, endColumnIndex: ix.remarksIndex + 1 }, cell: { userEnteredFormat: { backgroundColor: dark, verticalAlignment: 'MIDDLE', textFormat: { bold: true, fontSize: 10, foregroundColor: white } } }, fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat)' } },
    { updateDimensionProperties: { range: { sheetId: sid, dimension: 'ROWS', startIndex: 0, endIndex: 1 }, properties: { pixelSize: 30 }, fields: 'pixelSize' } }
  ]);
  await saveSetting(key, true);
}
async function styleTotalsBlock(c, ix, totalsRow) {
  const sid = await responseSheetId(c); if (sid === null) return;
  const { dark, light, ink, white } = TOTALS_COLORS;
  const sym = c.currencyCode === 'NPR' ? 'Rs' : c.currencyCode;
  const endCol = ix.idIndex + 1;
  const rowRange = (row, sc = 0, ec = endCol) => ({ sheetId: sid, startRowIndex: row - 1, endRowIndex: row, startColumnIndex: sc, endColumnIndex: ec });
  const rem = totalsRow + 1;
  await sheetsBatchUpdate(c, [
    { repeatCell: { range: rowRange(totalsRow), cell: { userEnteredFormat: { backgroundColor: dark, verticalAlignment: 'MIDDLE', textFormat: { bold: false, fontSize: 10, foregroundColor: white } } }, fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat)' } },
    { repeatCell: { range: rowRange(rem), cell: { userEnteredFormat: { backgroundColor: light, verticalAlignment: 'MIDDLE', textFormat: { bold: false, fontSize: 10, foregroundColor: ink }, borders: { bottom: { style: 'SOLID_MEDIUM', color: ink } } } }, fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat,borders)' } },
    { repeatCell: { range: { sheetId: sid, startRowIndex: totalsRow - 1, endRowIndex: rem, startColumnIndex: ix.incomeIndex, endColumnIndex: ix.expenseIndex + 1 }, cell: { userEnteredFormat: { numberFormat: { type: 'NUMBER', pattern: `"${sym} "#,##0.00` }, horizontalAlignment: 'RIGHT' } }, fields: 'userEnteredFormat(numberFormat,horizontalAlignment)' } },
    { repeatCell: { range: rowRange(rem, ix.remarksIndex, ix.remarksIndex + 1), cell: { userEnteredFormat: { textFormat: { bold: false, italic: true, fontSize: 9, foregroundColor: ink } } }, fields: 'userEnteredFormat.textFormat' } },
    { updateDimensionProperties: { range: { sheetId: sid, dimension: 'ROWS', startIndex: totalsRow - 1, endIndex: rem }, properties: { pixelSize: 28 }, fields: 'pixelSize' } }
  ]);
}
async function appendPendingForBook(c, ix, remoteSheet, tz, bookId, filterFn) {
  const remoteIds = new Set(remoteSheet.records.map(r => r.id));
  const allLocal = await getBookTransactions(bookId);
  const pending = allLocal.filter(r => r.syncState === 'pending' && (!filterFn || filterFn(r))).sort((a, b) => tsOf(a) - tsOf(b));
  const coreCols = Math.max(ix.timestampIndex, ix.incomeIndex, ix.expenseIndex, ix.remarksIndex, ix.idIndex) + 1;
  const endColLetter = columnName(coreCols);
  const tab = quoteSheetName(c.responseTab);
  const inCol = columnName(ix.incomeIndex + 1), outCol = columnName(ix.expenseIndex + 1);
  const dashTab = quoteSheetName(c.dashboardTab || 'Dashboard');
  let lastEntryRow = remoteSheet.lastEntryRow;
  const rowsToUpload = [], recordsToUpdate = [];
  for (const record of pending) {
    if (record.currencyCode && record.currencyCode !== c.currencyCode) throw new Error(`Entry uses ${record.currencyCode}, Sheet uses ${c.currencyCode}.`);
    if (remoteIds.has(record.id)) { await putTransaction({ ...record, syncState: 'synced' }); continue; }
    const row = Array(coreCols).fill('');
    row[ix.timestampIndex] = formatSheetTimestamp(record.createdAt, tz);
    row[ix.incomeIndex] = (Number(record.moneyInMinor) || 0) / currencyScale(record.currencyCode || c.currencyCode);
    row[ix.expenseIndex] = (Number(record.moneyOutMinor) || 0) / currencyScale(record.currencyCode || c.currencyCode);
    row[ix.remarksIndex] = safeSheetText(record.remarks);
    row[ix.idIndex] = record.id;
    rowsToUpload.push(row); recordsToUpdate.push(record); remoteIds.add(record.id);
  }
  if (remoteSheet.summaryRows.length) {
    await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(c.spreadsheetId)}/values:batchClear`, { method: 'POST', body: JSON.stringify({ ranges: remoteSheet.summaryRows.map(r => `${tab}!A${r}:${endColLetter}${r}`) }) });
  }
  if (rowsToUpload.length) {
    const startRow = lastEntryRow + 1, endRow = startRow + rowsToUpload.length - 1;
    await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${tab}!A${startRow}:${endColLetter}${endRow}`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: rowsToUpload }) });
    for (const r of recordsToUpdate) await putTransaction({ ...r, syncState: 'synced' });
    lastEntryRow = endRow;
  }
  if (lastEntryRow <= 1) return '';
  try {
    const totalsRow = lastEntryRow + 2, sumEnd = totalsRow - 1;
    const totalLine = Array(coreCols).fill('');
    totalLine[ix.timestampIndex] = 'TOTAL';
    totalLine[ix.incomeIndex] = `=SUM(${inCol}2:${inCol}${sumEnd})`;
    totalLine[ix.expenseIndex] = `=SUM(${outCol}2:${outCol}${sumEnd})`;
    const remLine = Array(coreCols).fill('');
    remLine[ix.timestampIndex] = 'REMAINING';
    remLine[ix.incomeIndex] = `=${inCol}${totalsRow}-${outCol}${totalsRow}+N(${dashTab}!B13)`;
    remLine[ix.remarksIndex] = 'Money in − money out + starting balance';
    await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${tab}!A${totalsRow}:${endColLetter}${totalsRow + 1}`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [totalLine, remLine] }) });
    try { await styleTotalsBlock(c, ix, totalsRow); } catch {}
    return '';
  } catch (e) { return `Totals could not be written (${e.message || 'unknown'}).`; }
}
async function readStartingBalance(c) {
  const d = await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(c.dashboardTab)}!B13`, 'valueRenderOption=UNFORMATTED_VALUE'));
  const v = d.values?.[0]?.[0]; if (v === undefined || v === null || v === '') return null;
  return typeof v === 'number' ? Math.round(v * currencyScale(c.currencyCode)) : parseMoney(v, c.currencyCode);
}
async function readSheetTabs(c) { const d = await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(c.spreadsheetId)}?fields=sheets.properties(sheetId,title)`); return (d.sheets || []).map(s => s.properties); }
function sheetsBatchUpdate(c, reqs) { return sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(c.spreadsheetId)}:batchUpdate`, { method: 'POST', body: JSON.stringify({ requests: reqs }) }); }
async function usedRowCount(c, tabName) { const d = await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(tabName)}!A:A`)); return (d.values || []).length; }
async function ensurePeriodsTab(c, tabs) {
  if (tabs.some(t => t.title === PERIODS_TAB)) return;
  await sheetsBatchUpdate(c, [{ addSheet: { properties: { title: PERIODS_TAB } } }]);
  await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A1:C1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [['Period started (UTC)', 'Starting balance', 'Archive tab']] }) });
}
async function readPeriodStart(c) {
  const d = await sheetsRequest(sheetValuesUrl(c.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A2:A`, 'valueRenderOption=UNFORMATTED_VALUE'));
  const starts = (d.values || []).map(r => String(r[0] || '').trim()).filter(v => !Number.isNaN(Date.parse(v)));
  return starts.length ? starts[starts.length - 1] : null;
}

// ===== ARCHIVE CREATE + SYNC =====
async function syncArchiveCreation(book, config, arc) {
  let tabs = await readSheetTabs(config);
  const exists = tabs.some(t => t.title === arc.archiveName);
  if (!exists) {
    const indexes = await ensureResponseHeader(config);
    const tz = await readSpreadsheetTimeZone(config);
    const before = await readResponseSheet(config, indexes, tz);
    await appendPendingForBook(config, indexes, before, tz, book.id, r => r.archiveGroup === arc.archiveName && r.syncState === 'pending');
    tabs = await readSheetTabs(config);
    const mainSrc = tabs.find(t => t.title === config.responseTab);
    const dashSrc = tabs.find(t => t.title === config.dashboardTab);
    if (!mainSrc || !dashSrc) throw new Error('Main or dashboard tab missing');
    await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: mainSrc.sheetId, newSheetName: arc.archiveName } }]);
  }
  tabs = await readSheetTabs(config);
  const dashExists = tabs.some(t => t.title === arc.dashboardName);
  if (!dashExists) {
    const dashSrc = tabs.find(t => t.title === config.dashboardTab);
    const dup = await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: dashSrc.sheetId, newSheetName: arc.dashboardName } }]);
    const newSid = dup.replies?.[0]?.duplicateSheet?.properties?.sheetId;
    if (typeof newSid === 'number') {
      const rows = dup.replies[0].duplicateSheet.properties.gridProperties?.rowCount || 1000;
      const cols = dup.replies[0].duplicateSheet.properties.gridProperties?.columnCount || 26;
      await sheetsBatchUpdate(config, [{ copyPaste: { source: { sheetId: newSid, startRowIndex: 0, endRowIndex: rows, startColumnIndex: 0, endColumnIndex: cols }, destination: { sheetId: newSid, startRowIndex: 0, endRowIndex: rows, startColumnIndex: 0, endColumnIndex: cols }, pasteType: 'PASTE_VALUES', pasteOrientation: 'NORMAL' } }]);
    }
  }
  const scale = currencyScale(config.currencyCode || activeCurrencyCode);
  await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.dashboardTab)}!B13`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [[arc.carryBalance / scale]] }) });
  const rowCount = await usedRowCount(config, config.responseTab);
  if (rowCount > 1) {
    tabs = await readSheetTabs(config);
    const mainTab = tabs.find(t => t.title === config.responseTab);
    if (mainTab) await sheetsBatchUpdate(config, [{ deleteDimension: { range: { sheetId: mainTab.sheetId, dimension: 'ROWS', startIndex: 1, endIndex: rowCount } } }]);
  }
  tabs = await readSheetTabs(config);
  await ensurePeriodsTab(config, tabs);
  await sheetsRequest(`${sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A:C`)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`, { method: 'POST', body: JSON.stringify({ majorDimension: 'ROWS', values: [[arc.createdAt, arc.carryBalance / scale, `${arc.archiveName}, ${arc.dashboardName}`]] }) });
  for (const r of await getBookTransactions(book.id)) { if (r.archiveGroup === arc.archiveName && r.syncState === 'pending') await putTransaction({ ...r, syncState: 'synced' }); }
  arc.synced = true;
  await archiveSave(arc);
}
async function syncArchiveDeltas(book, config, arc, dirtyEntries) {
  const tabs = await readSheetTabs(config);
  const tab = tabs.find(t => t.title === arc.archiveName);
  if (!tab) {
    await sheetsBatchUpdate(config, [{ addSheet: { properties: { title: arc.archiveName } } }]);
    const headers = ['Timestamp', `Money Came In (${config.currencyCode})`, `Money Went Out (${config.currencyCode})`, 'Remarks', 'Offline Entry ID'];
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(arc.archiveName)}!A1:E1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [headers] }) });
    const tz = await readSpreadsheetTimeZone(config);
    const allEntries = await getArchiveTransactions(book.id, arc.archiveName);
    if (allEntries.length) {
      const rows = allEntries.map(e => [formatSheetTimestamp(e.createdAt, tz), (Number(e.moneyInMinor) || 0) / currencyScale(config.currencyCode), (Number(e.moneyOutMinor) || 0) / currencyScale(config.currencyCode), safeSheetText(e.remarks), e.id]);
      await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(arc.archiveName)}!A2:E${rows.length + 1}`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: rows }) });
    }
    for (const e of allEntries) await putTransaction({ ...e, dirty: false, syncState: 'synced' });
    return;
  }
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(arc.archiveName)}!A1:E`, 'valueRenderOption=UNFORMATTED_VALUE&dateTimeRenderOption=SERIAL_NUMBER'));
  const rows = data.values || [];
  const idToRow = new Map();
  for (let i = 1; i < rows.length; i++) {
    const id = String(rows[i][4] || '').trim();
    if (id) idToRow.set(id, i + 1);
  }
  const tz = await readSpreadsheetTimeZone(config);
  const scale = currencyScale(config.currencyCode);
  const toDelete = [];
  for (const e of dirtyEntries) {
    if (e.deleted) {
      const row = idToRow.get(e.id);
      if (row) toDelete.push(row);
      continue;
    }
    const values = [formatSheetTimestamp(e.createdAt, tz), (Number(e.moneyInMinor) || 0) / scale, (Number(e.moneyOutMinor) || 0) / scale, safeSheetText(e.remarks), e.id];
    const row = idToRow.get(e.id);
    if (row) {
      await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(arc.archiveName)}!A${row}:E${row}`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [values] }) });
    } else {
      await sheetsRequest(`${sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(arc.archiveName)}!A:E`)}:append?valueInputOption=USER_ENTERED&insertDataOption=INSERT_ROWS`, { method: 'POST', body: JSON.stringify({ majorDimension: 'ROWS', values: [values] }) });
    }
    await putTransaction({ ...e, dirty: false, syncState: 'synced' });
  }
  toDelete.sort((a, b) => b - a);
  const tabId = tabs.find(t => t.title === arc.archiveName)?.sheetId;
  if (tabId) {
    for (const row of toDelete) {
      await sheetsBatchUpdate(config, [{ deleteDimension: { range: { sheetId: tabId, dimension: 'ROWS', startIndex: row - 1, endIndex: row } } }]);
    }
    for (const e of dirtyEntries.filter(e => e.deleted)) await deleteTransaction(e.id);
  }
}

// ===== ARCHIVE BUTTON =====
async function archiveAndStartFresh() {
  const book = activeBook();
  if (!book?.spreadsheetId) { setArchiveStatus('Connect a Sheet first.', true); return; }
  if (isSyncing) { alert('Sync in progress. Try again in a moment.'); return; }
  const unsynced = (await archiveGetForBook(book.id)).find(a => !a.synced);
  if (unsynced) { alert(`"${unsynced.archiveName}" hasn't synced yet. Go online and sync first.`); return; }
  const active = await getActiveBookRecords();
  if (!active.length) { alert('No entries to archive.'); return; }
  const income = active.reduce((s, x) => s + (Number(x.moneyInMinor) || 0), 0);
  const expense = active.reduce((s, x) => s + (Number(x.moneyOutMinor) || 0), 0);
  const sb = Number(await getSetting(`startingBalance:${book.id}`, 0)) || 0;
  const carry = elements.carryBalance?.checked ? sb + income - expense : 0;
  const userInput = (elements.archiveName?.value || '').replace(/[\[\]*?:\/\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 50);
  const suffix = userInput || monthYearLabel(new Date());
  let archiveName = `${suffix} - ${book.name}`;
  let dashboardName = `${suffix} - Dashboard`;
  const existingNames = new Set((await archiveGetForBook(book.id)).map(a => a.archiveName));
  let n = 1;
  while (existingNames.has(archiveName)) { n++; archiveName = `${suffix} - ${book.name} (${n})`; dashboardName = `${suffix} - Dashboard (${n})`; }
  const proceed = window.confirm(`Archive "${book.name}" and start fresh?\n\n• Archive tab: "${archiveName}"\n• Dashboard snapshot: "${dashboardName}"\n• New period starts at: ${formatMoney(carry)}\n\n` + (navigator.onLine ? '' : 'Offline: archive will sync when you go online.') + '\n\nContinue?');
  if (!proceed) { setArchiveStatus('Cancelled. Nothing was changed.'); return; }
  const nowIso = new Date().toISOString();
  for (const r of active) await putTransaction({ ...r, archiveGroup: archiveName });
  await archiveSave({ id: newId(), bookId: book.id, archiveName, dashboardName, createdAt: nowIso, carryBalance: carry, synced: false });
  await saveSetting(`periodStart:${book.id}`, nowIso);
  await saveSetting(`startingBalance:${book.id}`, carry);
  if (elements.archiveName) elements.archiveName.value = '';
  await refreshView();
  if (navigator.onLine && tokenIsValid()) {
    setArchiveStatus('Completing archive in the Sheet…');
    await syncAll();
    setArchiveStatus(`Archive complete. New period started at ${formatMoney(carry)}.`);
    announce('Archive complete.');
  } else {
    setArchiveStatus(`Archived locally. Sync while online to complete "${archiveName}".`);
    announce('Archive queued. Sync when online.');
  }
}

// ===== SYNC =====
async function syncBookToSheet(book) {
  const config = await bookConfig(book);
  if (!config.spreadsheetId) throw new Error('No Sheet.');
  const unsynced = (await archiveGetForBook(book.id)).filter(a => !a.synced).sort((a, b) => tsOf(a) - tsOf(b));
  for (const arc of unsynced) await syncArchiveCreation(book, config, arc);
  const indexes = await ensureResponseHeader(config);
  try { await styleHeaderRow(config, indexes); } catch {}
  const tz = await readSpreadsheetTimeZone(config);
  const before = await readResponseSheet(config, indexes, tz);
  const warning = await appendPendingForBook(config, indexes, before, tz, book.id, r => !r.archiveGroup);
  const after = await readResponseRows(config, indexes, tz);
  await mergeSheetRecords(after, book.id);
  const allArcs = await archiveGetForBook(book.id);
  for (const arc of allArcs) {
    if (!arc.synced) continue;
    const dirty = (await getBookTransactions(book.id)).filter(r => r.archiveGroup === arc.archiveName && (r.dirty || r.deleted));
    if (dirty.length) await syncArchiveDeltas(book, config, arc, dirty);
  }
  const sb = await readStartingBalance(config).catch(() => null);
  if (sb !== null) await saveSetting(`startingBalance:${book.id}`, sb);
  const ps = await readPeriodStart(config).catch(() => null);
  if (ps) {
    const k = `periodStart:${book.id}`;
    const local = Date.parse(await getSetting(k, '') || '');
    if (Number.isNaN(local) || Date.parse(ps) > local) await saveSetting(k, ps);
  }
  if (warning) throw new Error(warning);
  await pruneOldArchives(book);
}
async function mergeSheetRecords(remote, bookId) {
  const local = await getBookTransactions(bookId);
  const byId = new Map(local.map(r => [r.id, r]));
  for (const rem of remote) {
    const cur = byId.get(rem.id);
    if (cur?.syncState === 'pending') continue;
    if (cur?.archiveGroup) continue;
    await putTransaction(cur ? { ...cur, ...rem, bookId, createdAt: cur.createdAt || rem.createdAt, syncState: 'synced' } : { ...rem, bookId });
  }
}
async function syncAll() {
  if (isSyncing) return;
  if (!cryptoKey) return;
  if (!navigator.onLine) { setSyncStatus('Saved offline', 'Your entries are queued on this device.', 'offline'); return; }
  if (!tokenIsValid()) { setSyncStatus('Sign-in needed', 'Tap “Sync now” to sign in.', 'pending'); return; }
  isSyncing = true; elements.syncNow.disabled = true;
  const originalBookId = currentBookId;
  try {
    const allRecs = await getAllTransactions();
    const allArcs = await getSetting(ARCHIVES_KEY, []);
    const noSheet = [];
    for (const b of books) {
      if (!b.spreadsheetId) {
        const cnt = allRecs.filter(r => r.bookId === b.id && (r.syncState === 'pending' || r.dirty || r.deleted)).length;
        const hasArc = allArcs.some(a => a.bookId === b.id && !a.synced);
        if (cnt > 0 || hasArc) noSheet.push({ book: b, count: cnt });
      }
    }
    if (noSheet.length) {
      const names = noSheet.map(x => `"${x.book.name}"`).join(', ');
      if (window.confirm(`${noSheet.length} book${noSheet.length > 1 ? 's' : ''} need${noSheet.length === 1 ? 's' : ''} a Google Sheet: ${names}.\n\nCreate ${noSheet.length > 1 ? 'them' : 'it'} now?`)) {
        for (const { book } of noSheet) {
          if (book.id !== currentBookId) await switchBook(book.id);
          try { await createSheetForBook(book, { syncAfter: false, askFolder: false }); }
          catch (e) { console.warn('Auto-create failed for', book.name, e); }
        }
        if (currentBookId !== originalBookId) await switchBook(originalBookId);
      }
    }
    const targets = books.filter(b => b.spreadsheetId);
    const errors = [];
    let i = 0;
    for (const book of targets) {
      i++;
      setSyncStatus('Syncing', `Syncing ${book.name} (${i} of ${targets.length})…`, 'ready');
      try { await syncBookToSheet(book); }
      catch (e) { errors.push({ name: book.name, message: e.message || 'unknown' }); }
    }
    lastSyncFinishedAt = Date.now();
    if (errors.length) {
      const msg = errors.map(e => `"${e.name}": ${e.message}`).join('; ');
      setSyncStatus('Sync needs attention', `${msg} — you're online. Tap "Sync now" to retry.`, 'error');
      announce('Some syncs failed. Check status.');
    } else if (targets.length === 0) {
      setSyncStatus('Saved on this device', 'No book has a Google Sheet yet.', 'ready');
    } else {
      setSyncStatus('Google Sheets connected', 'All books synced.', 'ready');
    }
  } finally {
    isSyncing = false; elements.syncNow.disabled = false; await refreshView();
  }
}
async function autoSync() {
  if (isSyncing || !cryptoKey || !navigator.onLine) return;
  if (!books.some(b => b.spreadsheetId)) return;
  const all = await getAllTransactions();
  const arcs = await getSetting(ARCHIVES_KEY, []);
  const hasPending = all.some(r => r.syncState === 'pending' || r.dirty || r.deleted) || arcs.some(a => !a.synced);
  const stale = Date.now() - lastSyncFinishedAt > 10 * 60 * 1000;
  if (!hasPending && !stale) return;
  if (!tokenIsValid()) { setSyncStatus('Sign-in needed', 'Tap "Sync now" to sign in.', 'pending'); return; }
  try { await syncAll(); }
  catch (e) { setSyncStatus('Sync needs attention', `${e.message || 'Sync failed'} — you're online. Tap "Sync now" to retry.`, 'error'); }
}
function startAutoSyncTimer() {
  if (autoSyncInterval) clearInterval(autoSyncInterval);
  autoSyncInterval = setInterval(() => { if (navigator.onLine && cryptoKey && !isSyncing) void autoSync(); }, 60000);
}
async function oneTapSync() {
  if (!cryptoKey) return;
  if (!navigator.onLine) { announce('You are offline. Your entries are safe on this device.'); return; }
  if (!books.some(b => b.spreadsheetId)) {
    updateOnboarding(); elements.onboardingCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    announce('Create or choose a Sheet for this book first.'); return;
  }
  try { await ensureSignedIn(); }
  catch (e) { setSyncStatus('Sign-in needed', e.message || 'Google sign-in was not completed.', 'error'); return; }
  await syncAll();
}

// ===== LOCK =====
function showLockScreen(mode) {
  elements.lockScreen.style.display = 'flex'; elements.appShell.style.display = 'none';
  const hp = mode === 'password' || mode === 'both'; const hb = mode === 'biometrics' || mode === 'both';
  elements.unlockForm.style.display = hp ? 'flex' : 'none'; elements.biometricBtn.style.display = hb ? 'flex' : 'none';
  elements.forgotPasswordBtn.style.display = 'inline-block';
  elements.forgotPasswordBtn.textContent = hp ? 'Forgot password?' : 'Can’t unlock? Erase this device';
  elements.unlockPassword.value = ''; elements.unlockBtn.textContent = 'Unlock Cashbook';
}
function lockApp() { cryptoKey = null; masterKeyRaw = null; clearTimeout(idleTimeout); const s = securityState(); showLockScreen(s.hasPassword && s.hasBiometrics ? 'both' : s.hasPassword ? 'password' : 'biometrics'); elements.lockMessage.textContent = s.hasPassword ? 'Enter your master password.' : 'Use Face ID / fingerprint.'; }
function resetIdleTimer() { clearTimeout(idleTimeout); if (!cryptoKey || !isProtected()) return; idleTimeout = setTimeout(() => lockApp(), 5 * 60 * 1000); }
async function updateOfflineStatus() {
  const build = `build ${APP_BUILD}`;
  if (!elements.storageStatus) return;
  elements.storageStatus.textContent = `Checking offline files… · ${build}`;
  if (!('serviceWorker' in navigator) || !('caches' in window)) { elements.storageStatus.textContent = `Offline mode is not supported · ${build}`; return; }
  const active = await Promise.race([navigator.serviceWorker.ready.then(() => true).catch(() => false), new Promise(r => setTimeout(() => r(false), 10000))]);
  let saved = active;
  if (active) { for (const u of ['./', './app.js', './styles.css']) { if (!(await caches.match(u, { ignoreSearch: true }))) { saved = false; break; } } }
  elements.storageStatus.textContent = saved ? `Works offline ✓ · ${build}` : `Offline files not saved yet · ${build}`;
}

async function startApp() {
  elements.lockScreen.style.display = 'none'; elements.appShell.style.display = 'block';
  updateSecurityUi();
  await loadBooks(); await loadSavedConfig();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  loadSavedToken(); cachedConfig = await bookConfig(activeBook());
  if (elements.onboardCurrency) elements.onboardCurrency.value = cachedConfig.currencyCode || activeCurrencyCode || DEFAULT_CURRENCY;
  renderBookSwitcher();
  await refreshView();
  if (navigator.onLine) void loadGoogleIdentity().catch(() => {});
  void autoSync();
  void updateOfflineStatus();
  resetIdleTimer();
  startAutoSyncTimer();
  if ('serviceWorker' in navigator) { navigator.serviceWorker.getRegistration().then(r => r?.update()).catch(() => {}); }
}

async function readAllRaw(s) { const db = await openDatabase(); const tx = db.transaction(s, 'readonly'); return new Promise((res, rej) => { const r = tx.objectStore(s).getAll(); r.onsuccess = () => res(r.result || []); r.onerror = () => rej(r.error); }); }
async function migrateFromLegacy(legacyKey) {
  if (!masterKeyRaw) { await generateMasterKey(); localStorage.setItem('cb_key_pending', JSON.stringify(await wrapMasterKeyWith(legacyKey))); }
  for (const record of await readAllRaw(STORE_TRANSACTIONS)) {
    let p = record;
    if (record.encrypted) { const x = await decryptText(record.encrypted, legacyKey); if (x == null) continue; try { p = JSON.parse(x); } catch { continue; } p.id = record.id; }
    await putTransaction(p);
  }
  for (const s of await readAllRaw(STORE_SETTINGS)) {
    let v;
    if (s.encrypted) { const x = await decryptText(s.encrypted, legacyKey); if (x == null) continue; try { v = JSON.parse(x); } catch { continue; } }
    else if (s.value !== undefined) v = s.value;
    else continue;
    await saveSetting(s.key, v);
  }
  localStorage.setItem('cb_key_wrapped', JSON.stringify(await wrapMasterKeyWith(legacyKey)));
  localStorage.setItem('cb_has_password', 'true');
  localStorage.removeItem('cb_key_pending');
}

// ===== UNLOCK (with rescue path) =====
async function unlockWithPassword(password) {
  const hasWrapped = localStorage.getItem('cb_key_wrapped');
  const hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const salt = localStorage.getItem('cb_salt');
  const pendingMig = localStorage.getItem('cb_key_pending');

  console.log('Unlock attempt. State:', {
    hasWrapped: !!hasWrapped, hasPrf: !!hasPrf, hasSalt: !!salt,
    hasRaw: !!localStorage.getItem('cb_key_raw'), hasPending: !!pendingMig
  });

  if (pendingMig && !salt) {
    throw new Error('Data recovery needed — the app was interrupted during an update. Please use "Forgot password" → ERASE to start fresh, then re-import from your Sheet.');
  }

  const isLegacy = !!salt && !hasWrapped && !hasPrf && !localStorage.getItem('cb_key_raw');

  if (isLegacy) {
    const lk = await derivePasswordKek(password, salt);
    cryptoKey = lk; masterKeyRaw = null;
    await openDatabase();
    let ok = (await getSetting('__auth_check__', null)) === 'valid';
    if (pendingMig) {
      try { await unwrapMasterKey(JSON.parse(pendingMig), lk); ok = true; }
      catch (e) { console.warn('pending unwrap failed', e); }
    }
    if (!ok) { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
    await migrateFromLegacy(lk);
  } else if (hasWrapped) {
    const kek = await derivePasswordKek(password, salt);
    let unwrapErr = null;
    try { await unwrapMasterKey(JSON.parse(hasWrapped), kek); }
    catch (e) { unwrapErr = e; }

    if (unwrapErr) {
      console.error('Unwrap failed:', unwrapErr);
      cryptoKey = null; masterKeyRaw = null;
      throw new Error('The password could not decrypt the stored encryption key. This means either the password is different from the one used to set it, or the stored key data is corrupted. Try again. If it keeps failing, use "Forgot password" to erase and re-import from your Google Sheet.');
    }

    await openDatabase();
    let check;
    try { check = await getSetting('__auth_check__', null); }
    catch (e) { console.error('getSetting(__auth_check__) failed:', e); check = null; }

    console.log('After unwrap. __auth_check__:', check);

    if (check !== 'valid') {
      // Password unwrap succeeded → password IS correct. The check is missing/wrong.
      const txns = await getAllTransactions().catch(() => []);
      const unreadable = unreadableCount;
      const diag = [
        'Your password unlocked the encryption key correctly, but the device verification check failed.',
        '',
        'This usually means:',
        '• The app was interrupted during an update',
        '• The database was partially cleared by your browser',
        '',
        `Data found: ${txns.length} readable entr${txns.length === 1 ? 'y' : 'ies'}${unreadable > 0 ? ` (${unreadable} unreadable)` : ''}`,
        '',
        'Continue anyway? (The app will repair the verification check.)',
        '',
        'If unsure, tap Cancel, then use "Forgot password" to inspect device state.'
      ].join('\n');
      if (!window.confirm(diag)) {
        cryptoKey = null; masterKeyRaw = null;
        throw new Error('Unlock cancelled. Try "Forgot password" to see device state.');
      }
      await saveSetting('__auth_check__', 'valid');
      console.log('__auth_check__ repaired');
    }
  } else {
    throw new Error('No master password is set. Use Face ID / fingerprint.');
  }
  await startApp();
}

async function switchGoogleAccount() {
  if (!window.confirm('Use a different Google account?\n\n• Your current Sheet is NOT changed or deleted.\n• Your entries stay on this device.\n• This book’s entries will be uploaded to the Sheet you create or pick with the new account.\n\nContinue?')) return;
  try {
    clearSavedToken(); localStorage.setItem(CHOOSE_ACCOUNT_KEY, '1');
    const b = activeBook();
    if (b) await updateActiveBookConfig({ spreadsheetId: '', spreadsheetName: '' });
    if (elements.spreadsheetInput) { elements.spreadsheetInput.dataset.spreadsheetId = ''; elements.spreadsheetInput.dataset.spreadsheetName = ''; elements.spreadsheetInput.value = ''; }
    if (b) for (const r of await getActiveBookRecords()) { if (r.syncState !== 'pending') await putTransaction({ ...r, syncState: 'pending' }); }
    lastSyncFinishedAt = 0;
    await refreshView();
    setSetupStatus('Ready for a new account.');
    announce('Choose your new Google account below.');
    elements.onboardingCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (e) { setSetupStatus(e.message, true); }
}

// ===== DIAGNOSTICS =====
async function showDiagnostics() {
  const lines = [
    '=== Device State ===',
    `Master password set: ${localStorage.getItem('cb_key_wrapped') ? 'YES' : 'NO'}`,
    `Biometric key set: ${localStorage.getItem('cb_prf_key_wrapped') ? 'YES' : 'NO'}`,
    `Raw key set: ${localStorage.getItem('cb_key_raw') ? 'YES' : 'NO'}`,
    `Password salt: ${localStorage.getItem('cb_salt') ? 'present' : 'MISSING'}`,
    `Biometric salt: ${localStorage.getItem('cb_prf_salt') ? 'present' : 'MISSING'}`,
    `Biometric credential: ${localStorage.getItem('cb_prf_cred_id') ? 'present' : 'MISSING'}`,
    `Pending migration: ${localStorage.getItem('cb_key_pending') ? 'YES (needs attention)' : 'no'}`,
    '', '=== Database ==='
  ];
  try {
    await openDatabase();
    const settings = await readAllRaw(STORE_SETTINGS);
    const txns = await readAllRaw(STORE_TRANSACTIONS);
    lines.push(`Settings count: ${settings.length}`);
    lines.push(`Has __auth_check__: ${settings.some(s => s.key === '__auth_check__') ? 'YES' : 'NO'}`);
    lines.push(`Transaction count: ${txns.length}`);
  } catch (e) {
    lines.push('Database error: ' + e.message);
  }
  lines.push('', '=== Sync ===');
  lines.push(`Online: ${navigator.onLine ? 'yes' : 'no'}`);
  lines.push(`Books: ${books.length}`);
  lines.push(`Current book: ${activeBook()?.name || 'none'}`);
  lines.push(`Service worker: ${'serviceWorker' in navigator ? 'supported' : 'not supported'}`);
  window.alert(lines.join('\n'));
  console.log('Diagnostics:', lines.join('\n'));
}
async function forgotPassword() {
  const diag = [
    'Your entries on this device are encrypted and cannot be recovered without the password.',
    'If you synced to a Google Sheet, those entries are safe there and can be brought back.',
    '',
    '=== What would you like to do? ===',
    '• Type ERASE — erase this device\'s data and start fresh.',
    '• Type DIAGNOSE — show device state without erasing.',
    '• Leave blank or Cancel — do nothing.'
  ].join('\n');
  const input = window.prompt(diag);
  if (input === null) return;
  const trimmed = input.trim().toUpperCase();
  if (trimmed === 'DIAGNOSE') { await showDiagnostics(); return; }
  if (trimmed !== 'ERASE') { alert('Nothing was erased.'); return; }
  try { await new Promise(r => { const req = indexedDB.deleteDatabase(DB_NAME); req.onsuccess = req.onerror = req.onblocked = () => r(); }); } catch {}
  ['cb_salt', 'cb_key_wrapped', 'cb_key_raw', 'cb_prf_salt', 'cb_prf_cred_id', 'cb_prf_key_wrapped', 'cb_has_password', 'cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled', 'cb_key_pending', 'booksMigrated', 'books', 'currentBookId', 'archives', 'reservedSheet'].forEach(k => localStorage.removeItem(k));
  location.reload();
}
async function setPasswordHandler() {
  const pw = elements.passwordInput.value;
  const pwInput = elements.passwordInput;
  setInlineErr(pwInput, '', 'pw-err');
  if (!pw) { setInlineErr(pwInput, 'Enter a password.', 'pw-err'); return; }
  if (pw.length < MIN_PASSWORD_LENGTH) { setInlineErr(pwInput, `Too short — use at least ${MIN_PASSWORD_LENGTH} characters (e.g. 4-digit PIN).`, 'pw-err'); return; }
  if (!masterKeyRaw) { setInlineErr(pwInput, 'App is locked. Unlock first.', 'pw-err'); return; }
  try {
    const salt = localStorage.getItem('cb_salt') || randomSaltB64();
    const kek = await derivePasswordKek(pw, salt);
    const wrapped = await wrapMasterKeyWith(kek);
    // Verify wrap before committing
    const test = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(wrapped.iv) }, kek, b64ToBytes(wrapped.data));
    if (new Uint8Array(test).length !== 32) throw new Error('Wrap verification failed');
    localStorage.setItem('cb_salt', salt);
    localStorage.setItem('cb_key_wrapped', JSON.stringify(wrapped));
    localStorage.setItem('cb_has_password', 'true');
    localStorage.removeItem('cb_key_raw');
    // Defense in depth
    await saveSetting('__auth_check__', 'valid');
    elements.passwordInput.value = '';
    setInlineErr(pwInput, '', 'pw-err');
    setSetupStatus('Master password saved.'); announce('Master password set.');
    updateSecurityUi();
  } catch (e) { console.error('setPasswordHandler:', e); setInlineErr(pwInput, e.message || 'Could not set password.', 'pw-err'); }
}
async function removePasswordHandler() {
  if (!localStorage.getItem('cb_key_wrapped')) { setSetupStatus('No master password is set.', true); return; }
  if (!securityState().hasBiometrics) {
    if (!window.confirm('Remove your master password?\n\nYour cashbook will then open without any lock on this device.')) return;
  }
  if (securityState().hasBiometrics) disableBiometrics();
  localStorage.removeItem('cb_key_wrapped'); localStorage.removeItem('cb_has_password');
  if (masterKeyRaw) localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
  setSetupStatus('Master password removed.'); announce('Master password removed.');
  updateSecurityUi();
}

function bindBookEvents() {
  elements.bookSelect?.addEventListener('change', e => void switchBook(e.target.value));
  elements.newBookBtn?.addEventListener('click', async () => {
    const name = window.prompt('Name the new book (e.g. Home, Business):');
    if (name === null) return;
    try {
      const book = await createBook(name);
      const reserved = await getSetting('reservedSheet', null);
      if (reserved && reserved.spreadsheetId) {
        book.spreadsheetId = reserved.spreadsheetId;
        book.spreadsheetName = reserved.spreadsheetName;
        book.responseTab = reserved.responseTab;
        book.dashboardTab = reserved.dashboardTab;
        await saveBooks();
        await deleteSetting('reservedSheet');
        announce(`Created "${book.name}" — attached to your fresh Sheet.`);
      } else {
        announce(`Created "${book.name}". Use ⋯ → Create Sheet to back it up.`);
      }
      await refreshView();
    } catch (e) { alert(e.message || 'Could not create the book.'); }
  });
}

function bindEvents() {
  elements.biometricBtn.addEventListener('click', async () => {
    elements.lockError.textContent = 'Waiting for Face ID / fingerprint…';
    const ok = await authenticateWithBiometrics();
    if (ok) { elements.lockError.textContent = ''; failedUnlockAttempts = 0; await startApp(); }
    else elements.lockError.textContent = 'Face ID / fingerprint failed or was cancelled.';
  });
  elements.forgotPasswordBtn.addEventListener('click', () => void forgotPassword());
  elements.unlockForm.addEventListener('submit', async e => {
    e.preventDefault(); elements.unlockBtn.disabled = true; elements.lockError.textContent = '';
    try { await unlockWithPassword(elements.unlockPassword.value); failedUnlockAttempts = 0; }
    catch (err) {
      failedUnlockAttempts++;
      elements.lockError.textContent = err.message || 'Failed to unlock.';
      elements.unlockPassword.value = '';
      if (failedUnlockAttempts >= 3 && !document.getElementById('diagBtn')) {
        const diagBtn = document.createElement('button');
        diagBtn.id = 'diagBtn';
        diagBtn.type = 'button';
        diagBtn.textContent = 'Show diagnostic info';
        diagBtn.style.cssText = 'margin-top:10px; background:none; border:0; color:#ba5a48; font-size:11px; text-decoration:underline; cursor:pointer;';
        diagBtn.onclick = () => showDiagnostics();
        elements.lockError.parentNode.appendChild(diagBtn);
      }
    }
    finally { elements.unlockBtn.disabled = false; }
  });
  elements.biometricToggle?.addEventListener('change', async e => {
    if (e.target.checked) {
      if (!securityState().hasPassword) {
        e.target.checked = false;
        alert('Set a master password first.\n\nWithout a password, losing your passkey could lock you out permanently.');
        return;
      }
      if (!window.confirm('Enable Face ID / fingerprint?\n\nIf you lose this passkey, you can still unlock with your master password.')) { e.target.checked = false; return; }
      try { await enableBiometrics(); e.target.checked = true; setSetupStatus('Face ID / fingerprint enabled.'); announce('Face ID / fingerprint enabled.'); }
      catch (err) { e.target.checked = false; alert(err.message || 'Could not enable Face ID / fingerprint.'); }
    } else { disableBiometrics(); setSetupStatus('Face ID / fingerprint disabled.'); announce('Face ID / fingerprint disabled.'); }
    updateSecurityUi();
  });
  elements.setPasswordBtn?.addEventListener('click', () => void setPasswordHandler());
  elements.removePasswordBtn?.addEventListener('click', () => void removePasswordHandler());
  elements.signOutGoogle?.addEventListener('click', async () => {
    if (!window.confirm('Sign out of Google on this app?\n\nYour entries stay on this device and your Sheet stays connected.')) return;
    clearSavedToken(); try { localStorage.setItem(CHOOSE_ACCOUNT_KEY, '1'); } catch {}
    await refreshView(); setSetupStatus('Signed out. Tap "Sign in & sync" to continue.'); announce('Signed out of Google.');
  });
  elements.switchGoogleAccount?.addEventListener('click', () => void switchGoogleAccount());
  elements.resetGoogleCreds?.addEventListener('click', async () => {
    if (elements.clientId) elements.clientId.value = DEFAULT_CLIENT_ID;
    if (elements.apiKey) elements.apiKey.value = DEFAULT_API_KEY;
    if (elements.appId) elements.appId.value = DEFAULT_APP_ID;
    await saveConfig(); setSetupStatus('Google credentials reset to app defaults.'); announce('Google credentials reset.');
  });
  elements.lockNowBtn?.addEventListener('click', lockApp);
  elements.transactionForm.addEventListener('submit', createTransaction);
  elements.settingsToggle.addEventListener('click', () => {
    elements.settingsPanel.open = !elements.settingsPanel.open;
    elements.settingsToggle.setAttribute('aria-expanded', String(elements.settingsPanel.open));
    if (elements.settingsPanel.open) elements.settingsPanel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
  elements.settingsPanel.addEventListener('toggle', () => elements.settingsToggle.setAttribute('aria-expanded', String(elements.settingsPanel.open)));
  elements.saveSettings.addEventListener('click', () => void saveConfig());
  elements.chooseGoogleSheet.addEventListener('click', () => void chooseGoogleSheet());
  elements.createNewSheet?.addEventListener('click', () => { const b = activeBook(); if (b) void createSheetForBook(b); else alert('Create a book first.'); });
  elements.connectGoogle.addEventListener('click', () => void oneTapSync());
  elements.syncNow.addEventListener('click', () => void oneTapSync());
  elements.startCreateSheet?.addEventListener('click', async () => {
    if (!books.length) {
      const name = window.prompt('Name your first book (e.g. Personal):');
      if (name === null) return;
      try { await createBook(name); } catch (e) { alert(e.message); return; }
    }
    const b = activeBook(); if (b) void createSheetForBook(b);
  });
  elements.startChooseSheet?.addEventListener('click', async () => {
    if (!books.length) {
      const name = window.prompt('Name your first book (e.g. Personal):');
      if (name === null) return;
      try { await createBook(name); } catch (e) { alert(e.message); return; }
    }
    void chooseGoogleSheet();
  });
  elements.archiveNow?.addEventListener('click', () => void archiveAndStartFresh());
  window.addEventListener('online', () => { void refreshView(); void autoSync(); });
  window.addEventListener('offline', () => void refreshView());
  document.addEventListener('visibilitychange', () => { if (!document.hidden && navigator.onLine) void autoSync(); });
  ['click', 'keydown', 'mousemove', 'touchstart'].forEach(evt => document.addEventListener(evt, resetIdleTimer));
  bindBookEvents();
  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
    navigator.serviceWorker.register('./sw.js').catch(() => { elements.storageStatus.textContent = `Offline mode could not start · build ${APP_BUILD}`; });
  }
}

async function initialize() {
  ['cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach(k => localStorage.removeItem(k));
  bindEvents();

  const salt = localStorage.getItem('cb_salt');
  const hasWrapped = localStorage.getItem('cb_key_wrapped');
  const hasRaw = localStorage.getItem('cb_key_raw');
  const hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const pending = localStorage.getItem('cb_key_pending');

  // Detect corrupted state: pending migration but no salt = unrecoverable
  if (pending && !salt) {
    elements.lockMessage.textContent = 'Data recovery needed — the app was interrupted during an update. Use "Forgot password" → ERASE to start fresh, then re-import from your Google Sheet.';
    showLockScreen('password');
    return;
  }

  const isLegacy = !!salt && !hasWrapped && !hasRaw && !hasPrf;

  if (isLegacy || (pending && salt)) {
    elements.lockMessage.textContent = 'Enter your master password to unlock your encrypted cashbook.';
    showLockScreen('password');
    return;
  }
  if (hasWrapped || hasPrf) {
    elements.lockMessage.textContent = hasWrapped ? 'Enter your master password to unlock your encrypted cashbook.' : 'Use Face ID / fingerprint to unlock your cashbook.';
    showLockScreen(hasWrapped && hasPrf ? 'both' : hasWrapped ? 'password' : 'biometrics');
    return;
  }
  if (hasRaw) {
    try { await setMasterKeyFromBytes(b64ToBytes(hasRaw)); await openDatabase(); await startApp(); }
    catch (err) { console.error(err); elements.storageStatus.textContent = 'Could not read local data.'; }
    return;
  }
  // Fresh install
  try {
    await generateMasterKey();
    localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
    await openDatabase();
    await saveSetting('__auth_check__', 'valid');
    await startApp();
  } catch (err) { console.error(err); elements.lockMessage.textContent = 'Could not initialize local storage.'; }
}

void initialize();