const DB_NAME = 'my-cashbook-v1';
const DB_VERSION = 1;
const STORE_TRANSACTIONS = 'transactions';
const STORE_SETTINGS = 'settings';
const DRIVE_FILE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
const DEFAULT_CURRENCY = 'NPR';
const PERIODS_TAB = 'Cashbook Periods';
const DEFAULT_CLIENT_ID = '1017685550464-um4md5jhrbki0gbna4d7b0osmliuddqm.apps.googleusercontent.com';
const DEFAULT_API_KEY = 'AIzaSyCBYJek40PIcM2Qr8dGJHpYto12SH9qBH8';
const DEFAULT_APP_ID = '1017685550464';
const APP_BUILD = 38;

let dbPromise, accessToken = null, tokenExpiresAt = 0, cryptoKey = null, masterKeyRaw = null;
let unreadableCount = 0, idleTimeout = null, isSyncing = false, toastTimer;
let activeCurrencyCode = DEFAULT_CURRENCY, cachedConfig = null, lastSyncFinishedAt = 0;
let autoSyncInterval = null;
const currencyFormatters = new Map();
const BOOKS_KEY = 'books', CURRENT_BOOK_KEY = 'currentBookId', CHOOSE_ACCOUNT_KEY = 'cb_choose_account';
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
  const salt = crypto.getRandomValues(new Uint8Array(32));
  let cred;
  try { cred = await createPrfCredential(salt); }
  catch (e) { if (e?.name === 'NotAllowedError') throw new Error('Cancelled.'); throw e; }
  const w = await wrapMasterKeyWith(await importAesKey(cred.prfBytes));
  localStorage.setItem('cb_prf_salt', bytesToB64(salt));
  localStorage.setItem('cb_prf_cred_id', bytesToB64(cred.credId));
  localStorage.setItem('cb_prf_key_wrapped', JSON.stringify(w));
  localStorage.removeItem('cb_key_raw');
  return true;
}
async function authenticateWithBiometrics() {
  const credId = localStorage.getItem('cb_prf_cred_id'), salt = localStorage.getItem('cb_prf_salt'), wj = localStorage.getItem('cb_prf_key_wrapped');
  if (!credId || !salt || !wj) return false;
  try {
    const prf = await getPrfBytes(b64ToBytes(credId), b64ToBytes(salt));
    await unwrapMasterKey(JSON.parse(wj), await importAesKey(prf));
    await openDatabase();
    if ((await getSetting('__auth_check__', null)) !== 'valid') { cryptoKey = null; masterKeyRaw = null; return false; }
    return true;
  } catch (e) { console.error(e); return false; }
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
  if (elements.biometricToggle) elements.biometricToggle.checked = s.hasBiometrics;
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
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error || new Error('Could not open local storage.'));
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
  if (r.encrypted) { const p = await decryptText(r.encrypted); return p ? JSON.parse(p) : fb; }
  return r.value !== undefined ? r.value : fb;
}
async function saveSetting(k, v) {
  const enc = await encryptText(JSON.stringify(v));
  const db = await openDatabase(); const tx = db.transaction(STORE_SETTINGS, 'readwrite'); const done = txnDone(tx);
  tx.objectStore(STORE_SETTINGS).put({ key: k, encrypted: enc }); await done;
}
async function deleteSetting(k) { const db = await openDatabase(); const tx = db.transaction(STORE_SETTINGS, 'readwrite'); const done = txnDone(tx); tx.objectStore(STORE_SETTINGS).delete(k); await done; }

// ===== BOOKS =====
function newBookId() { return crypto.randomUUID ? crypto.randomUUID() : `book-${Date.now()}-${Math.random().toString(36).slice(2,10)}`; }
function newId() { return crypto.randomUUID ? crypto.randomUUID() : `tx-${Date.now()}-${Math.random().toString(36).slice(2,10)}`; }
function monthYearLabel(d = new Date()) { return new Intl.DateTimeFormat(undefined, { month: 'short', year: 'numeric' }).format(d); }

async function loadBooks() {
  books = await getSetting(BOOKS_KEY, null);
  if (!Array.isArray(books) || !books.length) {
    const legacy = await getSetting('googleConfig', {});
    const first = { id: newBookId(), name: 'Personal', spreadsheetId: legacy.spreadsheetId || '', spreadsheetName: legacy.spreadsheetName || '', responseTab: legacy.responseTab || 'Form responses 1', dashboardTab: legacy.dashboardTab || 'Dashboard' };
    books = [first]; await saveSetting(BOOKS_KEY, books); await saveSetting(CURRENT_BOOK_KEY, first.id);
    const p = await getSetting('periodStartIso', null); if (p) await saveSetting(`periodStart:${first.id}`, p);
    const b = await getSetting('startingBalanceMinor', null); if (b !== null) await saveSetting(`startingBalance:${first.id}`, b);
    const all = await getAllTransactions();
    for (const rec of all) if (!rec.bookId) await putTransaction({ ...rec, bookId: first.id });
  }
  currentBookId = await getSetting(CURRENT_BOOK_KEY, null) || books[0].id;
  if (!books.some(b => b.id === currentBookId)) currentBookId = books[0].id;
}
async function saveBooks() { await saveSetting(BOOKS_KEY, books); }
async function updateActiveBookConfig(patch) { const b = activeBook(); if (!b) return; Object.assign(b, patch); await saveBooks(); cachedConfig = await bookConfig(b); }
async function bookConfig(book) {
  if (!book) return {};
  const saved = await getSetting('googleConfig', {});
  return { currencyCode: saved.currencyCode || DEFAULT_CURRENCY, clientId: saved.clientId || DEFAULT_CLIENT_ID, apiKey: saved.apiKey || DEFAULT_API_KEY, appId: saved.appId || DEFAULT_APP_ID, responseTab: book.responseTab || 'Form responses 1', dashboardTab: book.dashboardTab || 'Dashboard', spreadsheetId: book.spreadsheetId || '', spreadsheetName: book.spreadsheetName || '', bookId: book.id };
}
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
  if (deleteSheet && book.spreadsheetId && navigator.onLine && tokenIsValid()) { try { await driveDeleteFile(book.spreadsheetId); } catch (e) { console.warn(e); } }
  if (book.id === currentBookId) { const o = books.find(b => b.id !== book.id); currentBookId = o.id; await saveSetting(CURRENT_BOOK_KEY, currentBookId); }
  for (const r of await getBookTransactions(book.id)) await deleteTransaction(r.id);
  books = books.filter(b => b.id !== book.id); await saveBooks();
  await deleteSetting(`startingBalance:${book.id}`); await deleteSetting(`periodStart:${book.id}`);
  const q = await getSetting('pendingArchives', []);
  await saveSetting('pendingArchives', q.filter(a => a.bookId !== book.id));
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
  const recs = await getBookTransactions(currentBookId);
  const start = Date.parse(await getSetting(`periodStart:${currentBookId}`, '') || '');
  if (Number.isNaN(start)) return recs;
  return recs.filter(r => {
    if (r.syncState === 'pending') return !r.archivedAs;
    const t = Date.parse(r.createdAt || r.sheetTimestamp || '');
    return !Number.isNaN(t) && t >= start;
  });
}

// ===== BOOK UI =====
function renderBookSwitcher() {
  const s = elements.bookSelect; if (!s) return;
  const cur = Array.from(s.options).map(o => o.value);
  const want = books.map(b => b.id);
  const match = cur.length === want.length && cur.every((id, i) => id === want[i]);
  const namesChanged = books.some((b, i) => { const o = s.options[i]; return !o || o.textContent !== (b.spreadsheetId ? `${b.name} ✓` : b.name); });
  if (match && !namesChanged) { s.value = currentBookId; return; }
  const had = document.activeElement === s;
  s.replaceChildren();
  for (const b of books) { const o = document.createElement('option'); o.value = b.id; o.textContent = b.spreadsheetId ? `${b.name} ✓` : b.name; if (b.id === currentBookId) o.selected = true; s.append(o); }
  if (had) s.focus();
}
function renderBooksList() {
  const list = elements.booksList; if (!list) return;
  list.replaceChildren();
  for (const book of books) {
    const row = document.createElement('div'); row.className = 'books-list-row';
    const nm = document.createElement('span'); nm.className = 'books-list-name';
    nm.textContent = book.name + (book.spreadsheetId ? ' ✓' : ' — no Sheet');
    nm.title = book.spreadsheetId ? (book.spreadsheetName || book.spreadsheetId) : 'No Google Sheet yet';
    row.append(nm);
    if (!book.spreadsheetId) {
      const c = document.createElement('button'); c.type = 'button'; c.className = 'text-button'; c.textContent = 'Create Sheet';
      c.onclick = async () => { const w = book.id === currentBookId; if (!w) await switchBook(book.id); try { await createSheetForBook(book); } finally { if (!w) await switchBook(book.id); } };
      row.append(c);
    } else {
      const a = document.createElement('button'); a.type = 'button'; a.className = 'text-button'; a.textContent = 'Archive';
      a.onclick = async () => { if (book.id !== currentBookId) await switchBook(book.id); await archiveAndStartFresh(); };
      row.append(a);
    }
    const r = document.createElement('button'); r.type = 'button'; r.className = 'text-button'; r.textContent = 'Rename';
    r.onclick = async () => { const n = window.prompt('Rename this book:', book.name); if (n === null) return; try { await renameBook(book, n); renderBookSwitcher(); renderBooksList(); await refreshView(); announce(`Renamed to “${book.name}”.`); } catch (e) { alert(e.message); } };
    row.append(r);
    const d = document.createElement('button'); d.type = 'button'; d.className = 'text-button'; d.textContent = 'Delete'; d.disabled = books.length <= 1;
    d.onclick = async () => {
      if (books.length <= 1) return;
      const c = (await getBookTransactions(book.id)).length;
      let msg = `Delete the book “${book.name}”?\n\n• ${c} ${c === 1 ? 'entry' : 'entries'} will be erased from this device.\n`;
      if (book.spreadsheetId) msg += `• Its Sheet stays in your Drive unless you also delete it.\n`;
      msg += `\nContinue?`;
      if (!window.confirm(msg)) return;
      let delSheet = false;
      if (book.spreadsheetId) delSheet = window.confirm(`Also delete “${book.spreadsheetName || book.spreadsheetId}” from Drive?\n\nOK = delete Sheet too.\nCancel = keep Sheet, delete only local copy.`);
      try { await deleteBook(book, { deleteSheet: delSheet }); renderBookSwitcher(); renderBooksList(); await refreshView(); announce(`Deleted “${book.name}”.`); } catch (e) { alert(e.message); }
    };
    row.append(d);
    list.append(row);
  }
}

// ===== UI HELPERS =====
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
function announce(m) { elements.toast.textContent = m; elements.toast.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => elements.toast.classList.remove('show'), 3000); }
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

async function createTransaction(event) {
  event.preventDefault();
  const btn = elements.transactionForm.querySelector('button[type="submit"]');
  if (btn?.disabled) return;
  const inc = moneyToMinorUnits(elements.moneyIn.value), exp = moneyToMinorUnits(elements.moneyOut.value), rem = elements.remarks.value.trim();
  if (inc <= 0 && exp <= 0) { setFeedback('Enter an amount.', true); return; }
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
function sortedRecords(recs) { return recs.slice().sort((a, b) => { const at = a.createdAt && !Number.isNaN(Date.parse(a.createdAt)) ? Date.parse(a.createdAt) : Date.parse(a.sheetTimestamp || '') || 0; const bt = b.createdAt && !Number.isNaN(Date.parse(b.createdAt)) ? Date.parse(b.createdAt) : Date.parse(b.sheetTimestamp || '') || 0; return bt - at; }); }
function renderTransactions(recs) {
  const sorted = sortedRecords(recs); const vis = sorted.slice(0, 40);
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
    sy.textContent = r.syncState === 'pending' ? (r.archivedAs ? `Waiting → ${r.archivedAs}` : 'Waiting to sync') : 'On this device and Sheet';
    am.append(sy); row.append(main, am); elements.transactionList.append(row);
  }
}
async function refreshView() {
  const recs = await getActiveBookRecords();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const inc = recs.reduce((s, x) => s + (Number(x.moneyInMinor) || 0), 0);
  const exp = recs.reduce((s, x) => s + (Number(x.moneyOutMinor) || 0), 0);
  const sb = Number(await getSetting(`startingBalance:${currentBookId}`, 0)) || 0;
  elements.incomeTotal.textContent = formatMoney(inc); elements.expenseTotal.textContent = formatMoney(exp);
  elements.balanceTotal.textContent = formatMoney(sb + inc - exp);
  elements.balanceNote.textContent = sb ? `Includes your ${formatMoney(sb)} starting balance` : 'Starting balance plus money in minus money out';
  renderTransactions(recs); renderBookSwitcher(); renderBooksList();
  if (elements.historyFootnote) elements.historyFootnote.textContent = unreadableCount ? `${unreadableCount} saved ${unreadableCount === 1 ? 'entry' : 'entries'} could not be read on this device.` : 'This device keeps your recent records available offline.';
  const pending = recs.filter(x => x.syncState === 'pending').length;
  const pendingArchives = (await getSetting('pendingArchives', []) || []).filter(a => a.bookId === currentBookId);
  const hasSheet = !!activeBook()?.spreadsheetId;
  updateOnboarding();
  if (pendingArchives.length) setSyncStatus('Archive pending', `Sync while online to complete the archive of “${activeBook().name}”.`, 'pending');
  else if (!navigator.onLine) setSyncStatus(pending ? 'Saved offline' : 'You are offline', pending ? `${pending} ${pending === 1 ? 'entry is' : 'entries are'} waiting.` : 'Your cashbook is available offline.', 'offline');
  else if (pending) setSyncStatus('Waiting to sync', `${pending} ${pending === 1 ? 'entry is' : 'entries are'} saved here. ${hasSheet ? 'Tap “Sync now”.' : 'Connect a Google Sheet.'}`, 'pending');
  else if (!hasSheet) setSyncStatus('Saved on this device', `“${activeBook()?.name || 'This book'}” has no Sheet yet. Use Settings → Books.`, 'pending');
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
  if (sid) setSetupStatus('Settings saved on this device.');
}
async function saveConfig() {
  const f = await loadConfigFromForm();
  try {
    await persistCurrencyCode(f.currencyCode);
    const saved = await getSetting('googleConfig', {});
    await saveSetting('googleConfig', { ...saved, clientId: f.clientId, apiKey: f.apiKey, appId: f.appId, currencyCode: f.currencyCode });
    await updateActiveBookConfig({ spreadsheetId: f.spreadsheetId, spreadsheetName: f.spreadsheetName, responseTab: f.responseTab, dashboardTab: f.dashboardTab });
    setSetupStatus(`Settings saved for “${activeBook().name}”.`);
    announce('Settings saved.');
    await refreshView();
  } catch (e) { setSetupStatus(e.message || 'Could not save settings.', true); }
}
async function persistCurrencyCode(code) {
  let n;
  try { n = configureCurrency(code); } catch { throw new Error('Enter a 3-letter currency like NPR, USD, EUR, INR.'); }
  const cur = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const recs = await getAllTransactions();
  if (recs.length && n !== cur) { configureCurrency(cur); elements.currencyCode.value = cur; throw new Error(`This device already has records in ${cur}.`); }
  await saveSetting('currencyCode', n);
  return n;
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
    try { const tabs = await readSheetTabs({ ...c, spreadsheetId: sel.id }); const tt = tabs.map(t => t.title); c.responseTab = tt.find(t => /form responses/i.test(t)) || tt.find(t => !/dashboard/i.test(t) && t !== PERIODS_TAB) || activeBook().name; c.dashboardTab = tt.find(t => /dashboard/i.test(t)) || 'Dashboard'; } catch {}
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
  const body = { name: String(name || 'New folder'), mimeType: 'application/vnd.google-apps.folder' };
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

async function askForFolder(c, suggestedFolderName) {
  const i = window.prompt(`Where should the folder for this book go?\n\nFolder will be named: “${suggestedFolderName}”\n\n• Type an EXISTING folder name to nest inside (creates new if not found).\n• Type "pick" to browse folders.\n• Leave blank to create the folder in My Drive root.`, '');
  if (i === null) return null;
  const t = i.trim();
  if (!t) return { parentFolderId: null };
  if (t.toLowerCase() === 'pick') {
    try { const p = await showFolderPicker(c, accessToken); return { parentFolderId: p ? p.id : null }; }
    catch { return { parentFolderId: null }; }
  }
  try { return { parentFolderId: await createDriveFolder(t) }; }
  catch (e) { setSetupStatus(e.message, true); return { parentFolderId: null }; }
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
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message, true); return; }
  const c = await loadConfigFromForm();
  if (!c.clientId || !c.apiKey || !c.appId) { setSetupStatus('Google credentials missing.', true); return; }

  const bookName = book.name;
  const folderName = `${bookName} - My Cashbook`;
  const sheetTitle = `${bookName} Entries`;
  const responseTab = book.responseTab || bookName;
  const dashboardTab = book.dashboardTab || 'Dashboard';

  let placement = { parentFolderId: null };
  if (askFolder) { placement = await askForFolder(c, folderName); if (placement === null) { setSetupStatus('Cancelled.'); return; } }

  elements.createNewSheet.disabled = true; elements.chooseGoogleSheet.disabled = true;
  setSetupStatus(`Creating “${sheetTitle}”…`);
  let sid = null, created = null, folderId = null;
  try {
    const sv = await getSetting('googleConfig', {}); await saveSetting('googleConfig', { ...sv, clientId: c.clientId, apiKey: c.apiKey, appId: c.appId, currencyCode: c.currencyCode });
    folderId = await createDriveFolder(folderName, placement.parentFolderId || null);
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
    setSetupStatus(`Created “${book.spreadsheetName}” in folder “${folderName}”. ${pend > 0 ? `${pend} ${pend === 1 ? 'entry is' : 'entries are'} waiting — tap “Sync now”.` : 'Ready.'}`);
    announce('Sheet created.');
    if (syncAfter) await syncAll();
  } catch (e) {
    if (sid) { book.spreadsheetId = sid; book.spreadsheetName = created?.properties?.title || sheetTitle; book.responseTab = responseTab; book.dashboardTab = dashboardTab; try { await saveBooks(); } catch {} setSetupStatus(`Sheet created but setup failed: ${e.message}.`, true); }
    else setSetupStatus(e.message || 'Could not create the Sheet.', true);
  }
  finally { elements.createNewSheet.disabled = false; elements.chooseGoogleSheet.disabled = false; await refreshView(); }
}

async function fullResetWithNewSheet() {
  if (!navigator.onLine) { setSetupStatus('Starting over needs internet (to create the Sheet).', true); return; }
  if (!window.confirm('Start over completely?\n\n• ALL books and ALL their entries will be erased from this device.\n• Sheets already in Drive are NOT deleted.\n• A new Sheet and one new “Personal” book will be created.\n\nContinue?')) { setSetupStatus('Cancelled.'); return; }
  const typed = window.prompt('Type ERASE to confirm.'); if (typed === null) { setSetupStatus('Cancelled.'); return; }
  if (typed.trim() !== 'ERASE') { setSetupStatus('Cancelled — type ERASE exactly.', true); return; }
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message, true); return; }
  const c = await loadConfigFromForm();
  if (!c.clientId || !c.apiKey || !c.appId) { setSetupStatus('Google credentials missing.', true); return; }

  setSetupStatus('Erasing this device’s data…');
  try {
    for (const r of await getAllTransactions()) await deleteTransaction(r.id);
    for (const b of books) { await deleteSetting(`startingBalance:${b.id}`); await deleteSetting(`periodStart:${b.id}`); }
    await saveSetting(BOOKS_KEY, []); await deleteSetting('pendingArchives'); books = [];

    const placement = await askForFolder(c, 'Personal - My Cashbook');
    if (placement === null) { await refreshView(); setSetupStatus('Cancelled after erase. No book exists now.'); return; }

    setSetupStatus('Creating new Sheet…');
    const nid = newBookId(), folderName = 'Personal - My Cashbook', title = 'Personal Entries', rt = 'Personal', dt = 'Dashboard';
    const folderId = await createDriveFolder(folderName, placement.parentFolderId || null);
    const r = await fetch('https://sheets.googleapis.com/v4/spreadsheets', { method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ properties: { title }, sheets: [{ properties: { title: rt } }, { properties: { title: dt } }] }) });
    const created = await r.json().catch(() => ({}));
    if (!r.ok) { if (r.status === 401) clearSavedToken(); throw new Error(created.error?.message || `Google ${r.status}`); }
    const sid = created.spreadsheetId;
    if (!sid) throw new Error('No spreadsheet ID returned.');
    if (folderId) await moveFileToFolder(sid, folderId);

    const nb = { id: nid, name: 'Personal', spreadsheetId: sid, spreadsheetName: created.properties?.title || title, responseTab: rt, dashboardTab: dt };
    books = [nb]; await saveSetting(BOOKS_KEY, books); await saveSetting(CURRENT_BOOK_KEY, nid);

    const headers = ['Timestamp', `Money Came In (${c.currencyCode})`, `Money Went Out (${c.currencyCode})`, 'Remarks'];
    await sheetsRequest(sheetValuesUrl(sid, `${quoteSheetName(rt)}!A1:D1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [headers] }) });
    await sheetsRequest(sheetValuesUrl(sid, `${quoteSheetName(dt)}!A1:B13`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: buildDashboardValues({ ...c, responseTab: rt, dashboardTab: dt }, 0) }) });
    try { await styleNewSheet({ ...c, responseTab: rt, dashboardTab: dt, currencyCode: c.currencyCode }, created); } catch {}
    await saveSetting(`startingBalance:${nid}`, 0);
    await saveSetting(`periodStart:${nid}`, '');

    await refreshView();
    setSetupStatus(`Fresh start with “${nb.spreadsheetName}” in folder “${folderName}”.`);
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
const HEADER_STYLE_VERSION = 1;
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
  const pending = allLocal.filter(r => r.syncState === 'pending' && (!filterFn || filterFn(r)));
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

// ===== PENDING ARCHIVES =====
async function queuePendingArchive(book, archiveName, dashboardName, carryBalance) {
  const q = await getSetting('pendingArchives', []);
  const filtered = q.filter(a => a.bookId !== book.id);
  filtered.push({ bookId: book.id, bookName: book.name, archiveName, dashboardName, carryBalance, createdAt: new Date().toISOString() });
  await saveSetting('pendingArchives', filtered);
}
async function removePendingArchive(bookId) {
  const q = await getSetting('pendingArchives', []);
  await saveSetting('pendingArchives', q.filter(a => a.bookId !== bookId));
}
async function getPendingArchiveForBook(bookId) {
  const q = await getSetting('pendingArchives', []);
  return q.find(a => a.bookId === bookId) || null;
}
async function completePendingArchive(book, config, req) {
  const tz = await readSpreadsheetTimeZone(config).catch(() => undefined);
  const tabs = await readSheetTabs(config);
  const mainSrc = tabs.find(t => t.title === config.responseTab);
  if (!mainSrc) throw new Error(`Could not find tab “${config.responseTab}”.`);
  const dashSrc = tabs.find(t => t.title === config.dashboardTab);
  if (!dashSrc) throw new Error(`Could not find “${config.dashboardTab}” tab.`);

  // Collision-safe naming: append (2), (3) if name already exists
  let archiveName = req.archiveName;
  let dashboardName = req.dashboardName;
  if (tabs.some(t => t.title === archiveName)) {
    let attempt = 2;
    while (tabs.some(t => t.title === `${req.archiveName} (${attempt})`)) attempt++;
    archiveName = `${req.archiveName} (${attempt})`;
    dashboardName = `${req.dashboardName} (${attempt})`;
  }

  // 1. Upload pending archivedAs entries to the current main tab
  const indexes = await ensureResponseHeader(config);
  const pendingArchived = (await getBookTransactions(book.id)).filter(r => r.syncState === 'pending' && r.archivedAs === req.archiveName);
  if (pendingArchived.length) {
    const before = await readResponseSheet(config, indexes, tz);
    await appendPendingForBook(config, indexes, before, tz, book.id, r => r.archivedAs === req.archiveName);
  }

  // 2. Duplicate main tab → archive
  await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: mainSrc.sheetId, newSheetName: archiveName } }]);

  // 3. Duplicate Dashboard → archive dashboard, then freeze values
  const dup = await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: dashSrc.sheetId, newSheetName: dashboardName } }]);
  const newSid = dup.replies?.[0]?.duplicateSheet?.properties?.sheetId;
  const rows = dup.replies?.[0]?.duplicateSheet?.properties?.gridProperties?.rowCount || 1000;
  const cols = dup.replies?.[0]?.duplicateSheet?.properties?.gridProperties?.columnCount || 26;
  if (typeof newSid === 'number') {
    await sheetsBatchUpdate(config, [{ copyPaste: { source: { sheetId: newSid, startRowIndex: 0, endRowIndex: rows, startColumnIndex: 0, endColumnIndex: cols }, destination: { sheetId: newSid, startRowIndex: 0, endRowIndex: rows, startColumnIndex: 0, endColumnIndex: cols }, pasteType: 'PASTE_VALUES', pasteOrientation: 'NORMAL' } }]);
  }

  // 4. Set dashboard starting balance
  const scale = currencyScale(config.currencyCode || activeCurrencyCode);
  await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.dashboardTab)}!B13`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [[req.carryBalance / scale]] }) });

  // 5. Clear main tab data rows
  const rowCount = await usedRowCount(config, config.responseTab);
  if (rowCount > 1) {
    await sheetsBatchUpdate(config, [{ deleteDimension: { range: { sheetId: mainSrc.sheetId, dimension: 'ROWS', startIndex: 1, endIndex: rowCount } } }]);
  }

  // 6. Write period marker
  await ensurePeriodsTab(config, tabs);
  await sheetsRequest(`${sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A:C`)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`, { method: 'POST', body: JSON.stringify({ majorDimension: 'ROWS', values: [[req.createdAt, req.carryBalance / scale, `${archiveName}, ${dashboardName}`]] }) });
}

async function archiveAndStartFresh() {
  const book = activeBook();
  if (!book?.spreadsheetId) { setArchiveStatus('Connect a Sheet first.', true); return; }
  const existing = await getPendingArchiveForBook(book.id);
  if (existing) { setArchiveStatus(`An archive is already pending for this book. Sync while online to complete “${existing.archiveName}”.`, true); return; }

  const active = await getActiveBookRecords();
  const income = active.reduce((s, x) => s + (Number(x.moneyInMinor) || 0), 0);
  const expense = active.reduce((s, x) => s + (Number(x.moneyOutMinor) || 0), 0);
  const sb = Number(await getSetting(`startingBalance:${book.id}`, 0)) || 0;
  const carry = elements.carryBalance?.checked ? sb + income - expense : 0;

  const userInput = (elements.archiveName?.value || '').replace(/[\[\]*?:\/\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 50);
  const archiveSuffix = userInput || monthYearLabel(new Date());
  const archiveName = `${archiveSuffix} - ${book.name}`;
  const dashboardName = `${archiveSuffix} - Dashboard`;

  const proceed = window.confirm(
    `Archive “${book.name}” and start fresh?\n\n` +
    `• Archive tab will be: “${archiveName}”\n` +
    `• Dashboard snapshot: “${dashboardName}”\n` +
    `• New period starts at: ${formatMoney(carry)}\n\n` +
    (navigator.onLine ? 'Continuing…' : 'You are offline — archive will be queued and completed on next sync.') + '\n\nContinue?'
  );
  if (!proceed) { setArchiveStatus('Cancelled. Nothing was changed.'); return; }

  const nowIso = new Date().toISOString();
  const pending = (await getBookTransactions(book.id)).filter(r => r.syncState === 'pending' && !r.archivedAs);
  for (const r of pending) await putTransaction({ ...r, archivedAs: archiveName });
  await saveSetting(`periodStart:${book.id}`, nowIso);
  await saveSetting(`startingBalance:${book.id}`, carry);
  await queuePendingArchive(book, archiveName, dashboardName, carry);
  if (elements.archiveName) elements.archiveName.value = '';
  await refreshView();

  if (navigator.onLine && tokenIsValid()) {
    setArchiveStatus('Completing archive in the Sheet…');
    await syncAll();
    setArchiveStatus(`Archive complete. New period started at ${formatMoney(carry)}.`);
    announce('Archive complete.');
  } else {
    setArchiveStatus(`Archived locally. Sync while online to complete “${archiveName}”.`);
    announce('Archive queued. Sync when online.');
  }
}

// ===== SYNC =====
async function syncBookToSheet(book) {
  const config = await bookConfig(book);
  if (!config.spreadsheetId) throw new Error('No Sheet.');
  const archiveReq = await getPendingArchiveForBook(book.id);
  if (archiveReq) {
    await completePendingArchive(book, config, archiveReq);
    await removePendingArchive(book.id);
  }
  const indexes = await ensureResponseHeader(config);
  try { await styleHeaderRow(config, indexes); } catch {}
  const tz = await readSpreadsheetTimeZone(config);
  const before = await readResponseSheet(config, indexes, tz);
  const warning = await appendPendingForBook(config, indexes, before, tz, book.id, r => !r.archivedAs);
  const after = await readResponseRows(config, indexes, tz);
  await mergeSheetRecords(after, book.id);
  const sb = await readStartingBalance(config).catch(() => null);
  if (sb !== null) await saveSetting(`startingBalance:${book.id}`, sb);
  const ps = await readPeriodStart(config).catch(() => null);
  if (ps) {
    const k = `periodStart:${book.id}`;
    const local = Date.parse(await getSetting(k, '') || '');
    if (Number.isNaN(local) || Date.parse(ps) > local) await saveSetting(k, ps);
  }
  if (warning) throw new Error(warning);
}
async function mergeSheetRecords(remote, bookId) {
  const local = await getBookTransactions(bookId);
  const byId = new Map(local.map(r => [r.id, r]));
  for (const rem of remote) {
    const cur = byId.get(rem.id);
    if (cur?.syncState === 'pending') continue;
    await putTransaction(cur ? { ...cur, ...rem, bookId, createdAt: cur.createdAt || rem.createdAt, syncState: 'synced' } : { ...rem, bookId });
  }
}

async function syncAll() {
  if (isSyncing) return;
  if (!cryptoKey) return;
  if (!navigator.onLine) { setSyncStatus('Saved offline', 'Your entries are queued on this device.', 'offline'); return; }
  if (!tokenIsValid()) { setSyncStatus('Sign-in needed', 'Tap “Sync now” to sign in and sync.', 'pending'); return; }

  isSyncing = true; elements.syncNow.disabled = true;
  try {
    const allRecs = await getAllTransactions();
    const pendingArchives = await getSetting('pendingArchives', []);

    const noSheet = [];
    for (const b of books) {
      if (!b.spreadsheetId) {
        const cnt = allRecs.filter(r => r.bookId === b.id && r.syncState === 'pending').length;
        const hasArch = pendingArchives.some(a => a.bookId === b.id);
        if (cnt > 0 || hasArch) noSheet.push({ book: b, count: cnt });
      }
    }
    if (noSheet.length) {
      const names = noSheet.map(x => `“${x.book.name}”`).join(', ');
      const ok = window.confirm(`${noSheet.length} book${noSheet.length > 1 ? 's' : ''} need${noSheet.length === 1 ? 's' : ''} a Google Sheet: ${names}.\n\nCreate ${noSheet.length > 1 ? 'them' : 'it'} now in My Drive?`);
      if (ok) {
        for (const { book } of noSheet) {
          const wasActive = book.id === currentBookId;
          if (!wasActive) await switchBook(book.id);
          try { await createSheetForBook(book, { syncAfter: false, askFolder: false }); }
          catch (e) { console.warn('Auto-create failed for', book.name, e); }
          if (!wasActive) await switchBook(book.id);
        }
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
      const msg = errors.map(e => `“${e.name}”: ${e.message}`).join('; ');
      setSyncStatus('Sync needs attention', `${msg} — you're online. Tap “Sync now” to retry.`, 'error');
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
  const pendingArchives = await getSetting('pendingArchives', []);
  const hasPending = all.some(r => r.syncState === 'pending') || pendingArchives.length > 0;
  const stale = Date.now() - lastSyncFinishedAt > 10 * 60 * 1000;
  if (!hasPending && !stale) return;
  if (!tokenIsValid()) { setSyncStatus('Sign-in needed', 'Tap “Sync now” to sign in and sync.', 'pending'); return; }
  try { await syncAll(); }
  catch (e) { setSyncStatus('Sync needs attention', `${e.message || 'Sync failed'} — you're online. Tap “Sync now” to retry.`, 'error'); }
}

function startAutoSyncTimer() {
  if (autoSyncInterval) clearInterval(autoSyncInterval);
  autoSyncInterval = setInterval(() => { if (navigator.onLine && cryptoKey && !isSyncing) void autoSync(); }, 60000);
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
async function unlockWithPassword(password) {
  const hasWrapped = localStorage.getItem('cb_key_wrapped'), hasPrf = localStorage.getItem('cb_prf_key_wrapped'), salt = localStorage.getItem('cb_salt');
  const isLegacy = !!salt && !hasWrapped && !hasPrf && !localStorage.getItem('cb_key_raw');
  if (isLegacy) {
    const lk = await derivePasswordKek(password, salt);
    cryptoKey = lk; masterKeyRaw = null;
    await openDatabase();
    let ok = (await getSetting('__auth_check__', null)) === 'valid';
    const pend = localStorage.getItem('cb_key_pending');
    if (pend) { try { await unwrapMasterKey(JSON.parse(pend), lk); ok = true; } catch {} }
    if (!ok) { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
    await migrateFromLegacy(lk);
  } else if (hasWrapped) {
    const kek = await derivePasswordKek(password, salt);
    try { await unwrapMasterKey(JSON.parse(hasWrapped), kek); }
    catch { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
    await openDatabase();
    if ((await getSetting('__auth_check__', null)) !== 'valid') { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
  } else throw new Error('No master password is set. Use Face ID / fingerprint.');
  await startApp();
}
async function switchGoogleAccount() {
  if (!window.confirm('Use a different Google account?\n\n• Your current Sheet is NOT changed or deleted.\n• Your entries stay on this device.\n• This book’s entries will be uploaded to the Sheet you create or pick with the new account.\n\nContinue?')) return;
  try {
    clearSavedToken(); localStorage.setItem(CHOOSE_ACCOUNT_KEY, '1');
    await updateActiveBookConfig({ spreadsheetId: '', spreadsheetName: '' });
    if (elements.spreadsheetInput) { elements.spreadsheetInput.dataset.spreadsheetId = ''; elements.spreadsheetInput.dataset.spreadsheetName = ''; elements.spreadsheetInput.value = ''; }
    for (const r of await getActiveBookRecords()) { if (r.syncState !== 'pending') await putTransaction({ ...r, syncState: 'pending' }); }
    lastSyncFinishedAt = 0;
    await refreshView();
    setSetupStatus('Ready for a new account. Create or pick a Sheet for this book.');
    announce('Choose your new Google account below.');
    elements.onboardingCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (e) { setSetupStatus(e.message, true); }
}
async function forgotPassword() {
  const msg = ['Forgot your password?', '', 'Your entries on this device are encrypted and cannot be recovered without the password.', 'If you synced to a Google Sheet, those entries are safe there.', '', 'Type ERASE to erase this device\u2019s data and start fresh.'].join('\n');
  const input = window.prompt(msg); if (input === null) return;
  if (input.trim() !== 'ERASE') { alert('Nothing was erased. Type ERASE exactly to confirm.'); return; }
  try { await new Promise(r => { const req = indexedDB.deleteDatabase(DB_NAME); req.onsuccess = req.onerror = req.onblocked = () => r(); }); } catch {}
  ['cb_salt', 'cb_key_wrapped', 'cb_key_raw', 'cb_prf_salt', 'cb_prf_cred_id', 'cb_prf_key_wrapped', 'cb_has_password', 'cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach(k => localStorage.removeItem(k));
  location.reload();
}
async function setPasswordHandler() {
  const pw = elements.passwordInput.value;
  if (!pw) { setSetupStatus('Enter a password first.', true); return; }
  if (pw.length < 10) { setSetupStatus('Password must be at least 10 characters.', true); return; }
  try {
    const salt = localStorage.getItem('cb_salt') || randomSaltB64();
    const kek = await derivePasswordKek(pw, salt);
    localStorage.setItem('cb_salt', salt);
    localStorage.setItem('cb_key_wrapped', JSON.stringify(await wrapMasterKeyWith(kek)));
    localStorage.setItem('cb_has_password', 'true');
    localStorage.removeItem('cb_key_raw');
    elements.passwordInput.value = '';
    setSetupStatus('Master password saved.'); announce('Master password set.');
    updateSecurityUi();
  } catch (e) { setSetupStatus(e.message || 'Could not set the password.', true); }
}
async function removePasswordHandler() {
  if (!localStorage.getItem('cb_key_wrapped')) { setSetupStatus('No master password is set.', true); return; }
  if (!securityState().hasBiometrics) {
    if (!window.confirm('Remove your master password?\n\nYour cashbook will then open without any lock on this device.')) return;
  }
  localStorage.removeItem('cb_key_wrapped'); localStorage.removeItem('cb_has_password');
  if (!securityState().hasBiometrics && masterKeyRaw) localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
  setSetupStatus('Master password removed.'); announce('Master password removed.');
  updateSecurityUi();
}

function bindBookEvents() {
  elements.bookSelect?.addEventListener('change', e => void switchBook(e.target.value));
  elements.newBookBtn?.addEventListener('click', async () => {
    const name = window.prompt('Name the new book (e.g. Home, Business):');
    if (name === null) return;
    try { await createBook(name); await refreshView(); announce(`Created “${activeBook().name}”. Tap “Create Sheet” in Settings → Books to back it up.`); }
    catch (e) { announce(e.message || 'Could not create the book.'); }
  });
}

function bindEvents() {
  elements.biometricBtn.addEventListener('click', async () => {
    elements.lockError.textContent = 'Waiting for Face ID / fingerprint…';
    const ok = await authenticateWithBiometrics();
    if (ok) { elements.lockError.textContent = ''; await startApp(); }
    else elements.lockError.textContent = 'Face ID / fingerprint failed or was cancelled.';
  });
  elements.forgotPasswordBtn.addEventListener('click', () => void forgotPassword());
  elements.unlockForm.addEventListener('submit', async e => {
    e.preventDefault(); elements.unlockBtn.disabled = true; elements.lockError.textContent = '';
    try { await unlockWithPassword(elements.unlockPassword.value); }
    catch (err) { elements.lockError.textContent = err.message || 'Failed to unlock.'; elements.unlockPassword.value = ''; }
    finally { elements.unlockBtn.disabled = false; }
  });
  elements.biometricToggle?.addEventListener('change', async e => {
    if (e.target.checked) {
      if (!securityState().hasPassword && !window.confirm('Use Face ID / fingerprint without a password?\n\nIf you lose this passkey, this device’s entries cannot be unlocked. Entries already in your Google Sheet stay safe there.\n\nContinue?')) { e.target.checked = false; return; }
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
    await refreshView(); setSetupStatus('Signed out. Tap “Sign in & sync” to continue.'); announce('Signed out of Google.');
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
  elements.createNewSheet?.addEventListener('click', () => { const b = activeBook(); if (b) void createSheetForBook(b); });
  elements.connectGoogle.addEventListener('click', () => void oneTapSync());
  elements.syncNow.addEventListener('click', () => void oneTapSync());
  elements.startCreateSheet?.addEventListener('click', () => { const b = activeBook(); if (b) void createSheetForBook(b); });
  elements.startChooseSheet?.addEventListener('click', () => void chooseGoogleSheet());
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

async function initialize() {
  ['cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach(k => localStorage.removeItem(k));
  bindEvents();
  const salt = localStorage.getItem('cb_salt'), hasWrapped = localStorage.getItem('cb_key_wrapped'), hasRaw = localStorage.getItem('cb_key_raw'), hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const isLegacy = !!salt && !hasWrapped && !hasRaw && !hasPrf;
  if (isLegacy) { elements.lockMessage.textContent = 'Enter your master password to unlock your encrypted cashbook.'; showLockScreen('password'); return; }
  if (hasWrapped || hasPrf) {
    elements.lockMessage.textContent = hasWrapped ? 'Enter your master password to unlock your encrypted cashbook.' : 'Use Face ID / fingerprint to unlock your cashbook.';
    showLockScreen(hasWrapped && hasPrf ? 'both' : hasWrapped ? 'password' : 'biometrics'); return;
  }
  if (hasRaw) {
    try { await setMasterKeyFromBytes(b64ToBytes(hasRaw)); await openDatabase(); await startApp(); }
    catch (err) { console.error(err); elements.storageStatus.textContent = 'Could not read local data.'; }
    return;
  }
  try {
    await generateMasterKey();
    localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
    await openDatabase();
    await saveSetting('__auth_check__', 'valid');
    await startApp();
  } catch (err) { console.error(err); elements.lockMessage.textContent = 'Could not initialize local storage.'; }
}

void initialize();