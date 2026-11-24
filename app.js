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
const APP_BUILD = 33;

let dbPromise;
let accessToken = null;
let tokenExpiresAt = 0;
let cryptoKey = null;
let masterKeyRaw = null;
let unreadableCount = 0;
let idleTimeout = null;

const BOOKS_KEY = 'books';
const CURRENT_BOOK_KEY = 'currentBookId';
let books = [];
let currentBookId = null;

// ===== CRYPTO =====
function bytesToB64(bytes) { return btoa(String.fromCharCode(...new Uint8Array(bytes))); }
function b64ToBytes(base64) { return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0)); }
function randomSaltB64() { return bytesToB64(crypto.getRandomValues(new Uint8Array(16))); }
async function importAesKey(bytes) { return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']); }
async function exportAesKey(key) { return new Uint8Array(await crypto.subtle.exportKey('raw', key)); }
async function generateMasterKey() {
  cryptoKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  masterKeyRaw = await exportAesKey(cryptoKey);
  return cryptoKey;
}
async function setMasterKeyFromBytes(bytes) { cryptoKey = await importAesKey(bytes); masterKeyRaw = bytes; return cryptoKey; }
async function derivePasswordKek(password, saltBase64) {
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: b64ToBytes(saltBase64), iterations: 600000, hash: 'SHA-256' }, keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptText(text, key = cryptoKey) {
  if (!key) throw new Error("App is locked.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(ct)) };
}
async function decryptText(encObj, key = cryptoKey) {
  if (!key) throw new Error("App is locked.");
  if (!encObj || !encObj.iv || !encObj.data) return null;
  try { return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(encObj.iv) }, key, b64ToBytes(encObj.data))); }
  catch (e) { console.error("Decryption failed", e); return null; }
}
async function wrapMasterKeyWith(kek) {
  if (!masterKeyRaw) throw new Error('Unlock the cashbook first.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, masterKeyRaw);
  return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(c)) };
}
async function unwrapMasterKey(wrapped, kek) {
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(wrapped.iv) }, kek, b64ToBytes(wrapped.data));
  await setMasterKeyFromBytes(new Uint8Array(raw));
  return cryptoKey;
}

// ===== WEBAUTHN =====
async function createPrfCredential(saltBytes) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge, rp: { name: 'My Cashbook' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'cashbook-user', displayName: 'Cashbook User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' },
      extensions: { prf: { eval: { first: saltBytes } } }
    }
  });
  const prf = credential.getClientExtensionResults?.()?.prf;
  if (!prf || (!prf.enabled && !prf.results?.first)) throw new Error('This device or browser does not support secure Face ID / fingerprint unlock.');
  const credId = new Uint8Array(credential.rawId);
  let output = prf.results?.first;
  if (!output) output = await getPrfBytes(credId, saltBytes);
  return { credId, prfBytes: new Uint8Array(output) };
}
async function getPrfBytes(credIdBytes, saltBytes) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({ publicKey: { challenge, allowCredentials: [{ id: credIdBytes, type: 'public-key' }], userVerification: 'required', extensions: { prf: { eval: { first: saltBytes } } } } });
  const output = assertion.getClientExtensionResults?.()?.prf?.results?.first;
  if (!output) throw new Error('Biometric key is not available on this device.');
  return new Uint8Array(output);
}
async function enableBiometrics() {
  if (!window.PublicKeyCredential) throw new Error('Face ID / fingerprint is not supported on this device.');
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  let cred;
  try { cred = await createPrfCredential(saltBytes); }
  catch (err) {
    if (err?.name === 'NotAllowedError') throw new Error('Face ID / fingerprint was cancelled or not allowed. Nothing was changed.');
    throw new Error(err?.message || 'Could not enable Face ID / fingerprint.');
  }
  const wrapped = await wrapMasterKeyWith(await importAesKey(cred.prfBytes));
  localStorage.setItem('cb_prf_salt', bytesToB64(saltBytes));
  localStorage.setItem('cb_prf_cred_id', bytesToB64(cred.credId));
  localStorage.setItem('cb_prf_key_wrapped', JSON.stringify(wrapped));
  localStorage.removeItem('cb_key_raw');
  return true;
}
async function authenticateWithBiometrics() {
  const credIdB64 = localStorage.getItem('cb_prf_cred_id');
  const saltB64 = localStorage.getItem('cb_prf_salt');
  const wrappedJson = localStorage.getItem('cb_prf_key_wrapped');
  if (!credIdB64 || !saltB64 || !wrappedJson) return false;
  try {
    const prfBytes = await getPrfBytes(b64ToBytes(credIdB64), b64ToBytes(saltB64));
    await unwrapMasterKey(JSON.parse(wrappedJson), await importAesKey(prfBytes));
    await openDatabase();
    if ((await getSetting('__auth_check__', null)) !== 'valid') { cryptoKey = null; masterKeyRaw = null; return false; }
    return true;
  } catch (err) { console.error('Biometric unlock failed', err); return false; }
}
function disableBiometrics() {
  localStorage.removeItem('cb_prf_cred_id');
  localStorage.removeItem('cb_prf_salt');
  localStorage.removeItem('cb_prf_key_wrapped');
  if (!localStorage.getItem('cb_key_wrapped') && masterKeyRaw) localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
}
function securityState() { return { hasPassword: Boolean(localStorage.getItem('cb_key_wrapped')), hasBiometrics: Boolean(localStorage.getItem('cb_prf_key_wrapped')), hasRaw: Boolean(localStorage.getItem('cb_key_raw')) }; }
function isProtected() { const s = securityState(); return s.hasPassword || s.hasBiometrics; }
function updateSecurityUi() {
  if (!elements.securityStatus) return;
  const state = securityState();
  const parts = [state.hasPassword ? 'Master password: ON' : 'Master password: OFF', state.hasBiometrics ? 'Face ID / fingerprint: ON' : 'Face ID / fingerprint: OFF'];
  if (!isProtected()) parts.push('This device opens without a lock.');
  elements.securityStatus.textContent = parts.join('  ·  ');
  if (elements.biometricToggle) elements.biometricToggle.checked = state.hasBiometrics;
  if (elements.lockNowBtn) elements.lockNowBtn.style.display = isProtected() ? '' : 'none';
}

// ===== TOKEN =====
function saveToken(token, expiresIn) {
  accessToken = token; tokenExpiresAt = Date.now() + ((Number(expiresIn) || 3600) * 1000);
  try { sessionStorage.setItem('cb_token', accessToken); sessionStorage.setItem('cb_token_expires', String(tokenExpiresAt)); } catch {}
}
function loadSavedToken() {
  try {
    const t = sessionStorage.getItem('cb_token');
    const e = Number(sessionStorage.getItem('cb_token_expires') || '0');
    if (t && e > Date.now() + 60000) { accessToken = t; tokenExpiresAt = e; return true; }
  } catch {}
  return false;
}
function clearSavedToken() {
  accessToken = null; tokenExpiresAt = 0;
  try { sessionStorage.removeItem('cb_token'); sessionStorage.removeItem('cb_token_expires'); } catch {}
  try { localStorage.removeItem('cb_token'); localStorage.removeItem('cb_token_expires'); } catch {}
}

let cachedConfig = null;
let lastSyncFinishedAt = 0;
const CHOOSE_ACCOUNT_KEY = 'cb_choose_account';
function tokenIsValid() { return Boolean(accessToken) && tokenExpiresAt > Date.now() + 60000; }
function activeBook() { return books.find((b) => b.id === currentBookId) || books[0] || null; }
async function effectiveConfig() { return bookConfig(activeBook()); }
async function ensureSignedIn() { if (tokenIsValid()) return; await requestGoogleToken(await effectiveConfig()); }

let isSyncing = false;
let toastTimer;
let activeCurrencyCode = DEFAULT_CURRENCY;
const currencyFormatters = new Map();

const $ = (id) => document.getElementById(id);
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
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_TRANSACTIONS)) db.createObjectStore(STORE_TRANSACTIONS, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(STORE_SETTINGS)) db.createObjectStore(STORE_SETTINGS, { keyPath: 'key' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Could not open local storage.'));
  });
  return dbPromise;
}
function transactionDone(tx) { return new Promise((res, rej) => { tx.oncomplete = () => res(); tx.onabort = tx.onerror = () => rej(tx.error || new Error('Could not save local data.')); }); }
async function getAllTransactions() {
  const db = await openDatabase();
  const tx = db.transaction(STORE_TRANSACTIONS, 'readonly');
  const done = transactionDone(tx);
  const result = await new Promise((res, rej) => { const r = tx.objectStore(STORE_TRANSACTIONS).getAll(); r.onsuccess = () => res(r.result || []); r.onerror = () => rej(r.error); });
  await done;
  unreadableCount = 0;
  const out = [];
  for (const rec of result) {
    if (rec.encrypted) {
      const p = await decryptText(rec.encrypted);
      if (p) { try { out.push({ id: rec.id, ...JSON.parse(p) }); } catch { unreadableCount++; } }
      else unreadableCount++;
    } else { out.push(rec); await putTransaction(rec); }
  }
  return out;
}
async function putTransaction(record) {
  const { id, ...payload } = record;
  const encrypted = await encryptText(JSON.stringify(payload));
  const db = await openDatabase();
  const tx = db.transaction(STORE_TRANSACTIONS, 'readwrite');
  const done = transactionDone(tx);
  tx.objectStore(STORE_TRANSACTIONS).put({ id, encrypted });
  await done;
}
async function getSetting(key, fallback = null) {
  const db = await openDatabase();
  const tx = db.transaction(STORE_SETTINGS, 'readonly');
  const done = transactionDone(tx);
  const result = await new Promise((res, rej) => { const r = tx.objectStore(STORE_SETTINGS).get(key); r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
  await done;
  if (!result) return fallback;
  if (result.encrypted) { const p = await decryptText(result.encrypted); return p ? JSON.parse(p) : fallback; }
  return result.value !== undefined ? result.value : fallback;
}
async function saveSetting(key, value) {
  const encrypted = await encryptText(JSON.stringify(value));
  const db = await openDatabase();
  const tx = db.transaction(STORE_SETTINGS, 'readwrite');
  const done = transactionDone(tx);
  tx.objectStore(STORE_SETTINGS).put({ key, encrypted });
  await done;
}

// ===== BOOKS =====
function newBookId() { if (crypto.randomUUID) return crypto.randomUUID(); return `book-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`; }
async function loadBooks() {
  books = await getSetting(BOOKS_KEY, null);
  if (!Array.isArray(books) || !books.length) {
    const legacy = await getSetting('googleConfig', {});
    const first = {
      id: newBookId(), name: 'Personal',
      spreadsheetId: legacy.spreadsheetId || '', spreadsheetName: legacy.spreadsheetName || '',
      responseTab: legacy.responseTab || 'Form responses 1', dashboardTab: legacy.dashboardTab || 'Dashboard'
    };
    books = [first];
    await saveSetting(BOOKS_KEY, books);
    await saveSetting(CURRENT_BOOK_KEY, first.id);
    const p = await getSetting('periodStartIso', null); if (p) await saveSetting(`periodStart:${first.id}`, p);
    const b = await getSetting('startingBalanceMinor', null); if (b !== null) await saveSetting(`startingBalance:${first.id}`, b);
    const all = await getAllTransactions();
    for (const rec of all) { if (!rec.bookId) await putTransaction({ ...rec, bookId: first.id }); }
  }
  currentBookId = await getSetting(CURRENT_BOOK_KEY, null) || books[0].id;
  if (!books.some((b) => b.id === currentBookId)) currentBookId = books[0].id;
}
async function saveBooks() { await saveSetting(BOOKS_KEY, books); }
async function updateActiveBookConfig(patch) { const b = activeBook(); if (!b) return; Object.assign(b, patch); await saveBooks(); cachedConfig = await bookConfig(b); }
async function bookConfig(book) {
  if (!book) return {};
  const saved = await getSetting('googleConfig', {});
  return {
    currencyCode: saved.currencyCode || DEFAULT_CURRENCY,
    clientId: saved.clientId || DEFAULT_CLIENT_ID,
    apiKey: saved.apiKey || DEFAULT_API_KEY,
    appId: saved.appId || DEFAULT_APP_ID,
    responseTab: book.responseTab || 'Form responses 1',
    dashboardTab: book.dashboardTab || 'Dashboard',
    spreadsheetId: book.spreadsheetId || '',
    spreadsheetName: book.spreadsheetName || '',
    bookId: book.id
  };
}
async function switchBook(bookId) {
  if (!books.some((b) => b.id === bookId) || bookId === currentBookId) return;
  currentBookId = bookId;
  await saveSetting(CURRENT_BOOK_KEY, bookId);
  cachedConfig = await bookConfig(activeBook());
  await refreshView();
  announce(`Switched to ${activeBook().name}.`);
}
async function createBook(name) {
  const trimmed = String(name || '').trim();
  if (!trimmed) throw new Error('Enter a name for the new book.');
  if (books.some((b) => b.name.toLowerCase() === trimmed.toLowerCase())) throw new Error(`A book called “${trimmed}” already exists.`);
  const book = { id: newBookId(), name: trimmed, spreadsheetId: '', spreadsheetName: '', responseTab: trimmed, dashboardTab: 'Dashboard' };
  books.push(book); await saveBooks(); await switchBook(book.id); return book;
}
async function deleteBook(book) {
  if (books.length <= 1) throw new Error('You need at least one book.');
  if (book.id === currentBookId) {
    const other = books.find((b) => b.id !== book.id);
    currentBookId = other.id;
    await saveSetting(CURRENT_BOOK_KEY, currentBookId);
  }
  const recs = await getBookTransactions(book.id);
  if (recs.length) {
    const db = await openDatabase();
    const tx = db.transaction(STORE_TRANSACTIONS, 'readwrite');
    const done = transactionDone(tx);
    for (const rec of recs) tx.objectStore(STORE_TRANSACTIONS).delete(rec.id);
    await done;
  }
  books = books.filter((b) => b.id !== book.id);
  await saveBooks();
  cachedConfig = await bookConfig(activeBook());
}
async function renameBook(book, newName) {
  const trimmed = String(newName || '').trim();
  if (!trimmed) throw new Error('Enter a name.');
  if (books.some((b) => b.id !== book.id && b.name.toLowerCase() === trimmed.toLowerCase())) throw new Error(`A book called “${trimmed}” already exists.`);
  book.name = trimmed; await saveBooks();
}
async function getBookTransactions(bookId = currentBookId) { const all = await getAllTransactions(); return all.filter((r) => r.bookId === bookId); }
async function getActiveBookRecords() {
  const records = await getBookTransactions(currentBookId);
  const start = Date.parse(await getSetting(`periodStart:${currentBookId}`, '') || '');
  if (Number.isNaN(start)) return records;
  return records.filter((r) => {
    if (r.syncState === 'pending') return true;
    const t = Date.parse(r.createdAt || r.sheetTimestamp || '');
    return !Number.isNaN(t) && t >= start;
  });
}

// ===== BOOK UI =====
function renderBookSwitcher() {
  const select = elements.bookSelect; if (!select) return;
  const existingIds = Array.from(select.options).map((o) => o.value);
  const wantedIds = books.map((b) => b.id);
  const idsMatch = existingIds.length === wantedIds.length && existingIds.every((id, i) => id === wantedIds[i]);
  const namesChanged = books.some((b, i) => { const opt = select.options[i]; if (!opt) return true; return opt.textContent !== (b.spreadsheetId ? `${b.name} ✓` : b.name); });
  if (idsMatch && !namesChanged) { select.value = currentBookId; return; }
  const hadFocus = document.activeElement === select;
  select.replaceChildren();
  for (const b of books) {
    const opt = document.createElement('option'); opt.value = b.id; opt.textContent = b.spreadsheetId ? `${b.name} ✓` : b.name;
    if (b.id === currentBookId) opt.selected = true; select.append(opt);
  }
  if (hadFocus) select.focus();
}
function renderBooksList() {
  const list = elements.booksList; if (!list) return;
  list.replaceChildren();
  for (const book of books) {
    const row = document.createElement('div'); row.className = 'books-list-row';
    const name = document.createElement('span'); name.className = 'books-list-name';
    name.textContent = book.name + (book.spreadsheetId ? ' ✓' : '');
    name.title = book.spreadsheetId ? (book.spreadsheetName || book.spreadsheetId) : 'No Google Sheet yet';
    row.append(name);
    if (!book.spreadsheetId) {
      const create = document.createElement('button'); create.type = 'button'; create.className = 'text-button'; create.textContent = 'Create Sheet';
      create.onclick = async () => { try { if (book.id !== currentBookId) await switchBook(book.id); await createNewSpreadsheet(); } catch (e) {} };
      row.append(create);
    }
    const rename = document.createElement('button'); rename.type = 'button'; rename.className = 'text-button'; rename.textContent = 'Rename';
    rename.onclick = async () => {
      const newName = window.prompt('Rename this book:', book.name);
      if (newName === null) return;
      try { await renameBook(book, newName); renderBookSwitcher(); renderBooksList(); await refreshView(); announce(`Renamed to “${book.name}”.`); }
      catch (e) { alert(e.message || 'Could not rename the book.'); }
    };
    const del = document.createElement('button'); del.type = 'button'; del.className = 'text-button'; del.textContent = 'Delete'; del.disabled = books.length <= 1;
    del.onclick = async () => {
      if (books.length <= 1) return;
      const c = (await getBookTransactions(book.id)).length;
      const ok = window.confirm(`Delete the book “${book.name}”?\n\n• ${c} ${c === 1 ? 'entry' : 'entries'} erased from this device.\n` + (book.spreadsheetId ? `• Its Google Sheet (${book.spreadsheetName || book.spreadsheetId}) is NOT deleted.\n` : '') + `\nThis cannot be undone. Continue?`);
      if (!ok) return;
      try { await deleteBook(book); renderBookSwitcher(); renderBooksList(); await refreshView(); announce(`Deleted “${book.name}”.`); }
      catch (e) { alert(e.message || 'Could not delete the book.'); }
    };
    row.append(rename, del);
    list.append(row);
  }
}

// ===== UI HELPERS =====
function currencyFractionDigits(code = activeCurrencyCode) { return new Intl.NumberFormat(undefined, { style: 'currency', currency: code }).resolvedOptions().maximumFractionDigits; }
function currencyScale(code = activeCurrencyCode) { return 10 ** currencyFractionDigits(code); }
function configureCurrency(currencyCode) {
  const normalized = String(currencyCode || DEFAULT_CURRENCY).trim().toUpperCase();
  const fd = currencyFractionDigits(normalized);
  activeCurrencyCode = normalized;
  const step = 1 / (10 ** fd);
  elements.moneyIn.step = String(step); elements.moneyOut.step = String(step);
  const ph = fd ? `0.${'0'.repeat(fd)}` : '0';
  elements.moneyIn.placeholder = ph; elements.moneyOut.placeholder = ph;
  currencyFormatters.set(normalized, new Intl.NumberFormat(undefined, { style: 'currency', currency: normalized, minimumFractionDigits: fd, maximumFractionDigits: fd }));
  $('currencyLabelIn').textContent = `(${normalized})`; $('currencyLabelOut').textContent = `(${normalized})`;
  return normalized;
}
function moneyToMinorUnits(value, code = activeCurrencyCode) { const n = Number(value); return Number.isFinite(n) && n >= 0 ? Math.round(n * currencyScale(code)) : 0; }
function parseMoney(value, code = activeCurrencyCode) {
  if (typeof value === 'number') return Number.isFinite(value) ? Math.round(value * currencyScale(code)) : 0;
  const n = Number(String(value ?? '').replace(/,/g, '').replace(/[^\d.-]/g, ''));
  return Number.isFinite(n) ? Math.round(n * currencyScale(code)) : 0;
}
function formatMoney(minorUnits, code = activeCurrencyCode) {
  let fmt = currencyFormatters.get(code);
  if (!fmt) { const fd = currencyFractionDigits(code); fmt = new Intl.NumberFormat(undefined, { style: 'currency', currency: code, minimumFractionDigits: fd, maximumFractionDigits: fd }); currencyFormatters.set(code, fmt); }
  return fmt.format((Number(minorUnits) || 0) / currencyScale(code));
}
function localTimeLabel(record) {
  if (record.createdAt) { const d = new Date(record.createdAt); if (!Number.isNaN(d.getTime())) return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(d); }
  return record.sheetTimestamp || 'Date saved in Google Sheets';
}
function announce(message) { elements.toast.textContent = message; elements.toast.classList.add('show'); clearTimeout(toastTimer); toastTimer = setTimeout(() => elements.toast.classList.remove('show'), 3000); }
function setFeedback(msg, isError = false) { elements.formFeedback.textContent = msg; elements.formFeedback.classList.toggle('error', isError); }
function setSetupStatus(msg, isError = false) { elements.setupStatus.textContent = msg; elements.setupStatus.classList.toggle('error', isError); if (elements.onboardingStatus) { elements.onboardingStatus.textContent = msg; elements.onboardingStatus.classList.toggle('error', isError); } }
function updateOnboarding() {
  const connected = Boolean(activeBook()?.spreadsheetId);
  if (elements.onboardingCard) elements.onboardingCard.hidden = connected;
  if (elements.archivePanel) elements.archivePanel.hidden = !connected;
  if (elements.openSheetLink) { elements.openSheetLink.hidden = !connected; if (connected) elements.openSheetLink.href = `https://docs.google.com/spreadsheets/d/${encodeURIComponent(activeBook().spreadsheetId)}/edit`; }
}
function setArchiveStatus(msg, isError = false) { if (!elements.archiveStatus) return; elements.archiveStatus.textContent = msg; elements.archiveStatus.classList.toggle('error', isError); }
function setSyncStatus(title, message, mode = 'ready') {
  elements.syncTitle.textContent = title; elements.syncMessage.textContent = message;
  elements.onlineDot.classList.toggle('offline', !navigator.onLine || mode === 'offline');
  elements.syncNow.hidden = mode !== 'pending' && mode !== 'error';
}
function newId() { if (crypto.randomUUID) return crypto.randomUUID(); return `tx-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`; }

async function createTransaction(event) {
  event.preventDefault();
  const submitBtn = elements.transactionForm.querySelector('button[type="submit"]');
  if (submitBtn?.disabled) return;
  const incomeMinor = moneyToMinorUnits(elements.moneyIn.value, activeCurrencyCode);
  const expenseMinor = moneyToMinorUnits(elements.moneyOut.value, activeCurrencyCode);
  const remarks = elements.remarks.value.trim();
  if (incomeMinor <= 0 && expenseMinor <= 0) { setFeedback('Enter an amount for money in or money out.', true); return; }
  const record = { id: newId(), bookId: currentBookId, createdAt: new Date().toISOString(), currencyCode: activeCurrencyCode, moneyInMinor: incomeMinor, moneyOutMinor: expenseMinor, remarks, syncState: 'pending', source: 'local' };
  if (submitBtn) submitBtn.disabled = true;
  try {
    await putTransaction(record);
    elements.transactionForm.reset();
    setFeedback(`Saved to ${activeBook().name} at ${localTimeLabel(record)}.`);
    await refreshView();
    if (navigator.onLine && accessToken && tokenExpiresAt > Date.now() + 15000 && activeBook()?.spreadsheetId) {
      void syncBookToSheet(activeBook()).catch(() => {});
    } else if (navigator.onLine) {
      setSyncStatus('Saved on this device', 'Connect Google to upload this entry to your Sheet.', 'pending');
    } else {
      setSyncStatus('Saved offline', 'This entry is queued on this device for when you are online.', 'offline');
    }
  } catch (error) { setFeedback(error.message || 'Could not save this entry on the device.', true); }
  finally { if (submitBtn) submitBtn.disabled = false; }
}

function sortedRecords(records) {
  return records.slice().sort((a, b) => {
    const at = a.createdAt && !Number.isNaN(Date.parse(a.createdAt)) ? Date.parse(a.createdAt) : Date.parse(a.sheetTimestamp || '') || 0;
    const bt = b.createdAt && !Number.isNaN(Date.parse(b.createdAt)) ? Date.parse(b.createdAt) : Date.parse(b.sheetTimestamp || '') || 0;
    return bt - at;
  });
}
function renderTransactions(records) {
  const sorted = sortedRecords(records);
  const visible = sorted.slice(0, 40);
  elements.recordCount.textContent = `${records.length} ${records.length === 1 ? 'record' : 'records'}`;
  elements.transactionList.replaceChildren();
  if (!visible.length) {
    const empty = document.createElement('div'); empty.className = 'empty-state';
    empty.innerHTML = '<span class="empty-icon" aria-hidden="true">＋</span><strong>No transactions yet</strong><span>Your saved entries will appear here.</span>';
    elements.transactionList.append(empty);
    return;
  }
  for (const record of visible) {
    const inMinor = Number(record.moneyInMinor) || 0;
    const outMinor = Number(record.moneyOutMinor) || 0;
    const kind = inMinor && outMinor ? 'mixed' : inMinor ? 'income' : 'expense';
    const row = document.createElement('article'); row.className = 'transaction-row';
    const main = document.createElement('div'); main.className = 'transaction-main';
    const icon = document.createElement('span'); icon.className = `transaction-icon ${kind}`; icon.setAttribute('aria-hidden', 'true');
    icon.textContent = kind === 'income' ? '↙' : kind === 'expense' ? '↗' : '↔';
    const text = document.createElement('div'); text.className = 'transaction-text';
    const remark = document.createElement('span'); remark.className = 'transaction-remark';
    remark.textContent = record.remarks || (kind === 'income' ? 'Money came in' : kind === 'expense' ? 'Money went out' : 'Money in and out');
    const time = document.createElement('span'); time.className = 'transaction-time'; time.textContent = localTimeLabel(record);
    text.append(remark, time); main.append(icon, text);
    const amounts = document.createElement('div'); amounts.className = 'transaction-amounts';
    if (inMinor) { const a = document.createElement('span'); a.className = 'in'; a.textContent = `+ ${formatMoney(inMinor, record.currencyCode || activeCurrencyCode)}`; amounts.append(a); }
    if (outMinor) { const a = document.createElement('span'); a.className = 'out'; a.textContent = `− ${formatMoney(outMinor, record.currencyCode || activeCurrencyCode)}`; amounts.append(a); }
    const sync = document.createElement('small'); sync.className = `transaction-sync ${record.syncState === 'pending' ? 'pending' : ''}`;
    sync.textContent = record.syncState === 'pending' ? 'Waiting to sync' : 'On this device and Sheet';
    amounts.append(sync); row.append(main, amounts); elements.transactionList.append(row);
  }
}
async function refreshView() {
  const records = await getActiveBookRecords();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const income = records.reduce((s, x) => s + (Number(x.moneyInMinor) || 0), 0);
  const expense = records.reduce((s, x) => s + (Number(x.moneyOutMinor) || 0), 0);
  const sb = Number(await getSetting(`startingBalance:${currentBookId}`, 0)) || 0;
  elements.incomeTotal.textContent = formatMoney(income);
  elements.expenseTotal.textContent = formatMoney(expense);
  elements.balanceTotal.textContent = formatMoney(sb + income - expense);
  elements.balanceNote.textContent = sb ? `Includes your ${formatMoney(sb)} starting balance` : 'Starting balance plus money in minus money out';
  renderTransactions(records); renderBookSwitcher(); renderBooksList();
  if (elements.historyFootnote) {
    elements.historyFootnote.textContent = unreadableCount
      ? `${unreadableCount} saved ${unreadableCount === 1 ? 'entry' : 'entries'} could not be read on this device.`
      : 'This device keeps your recent records available offline.';
  }
  const pending = records.filter((x) => x.syncState === 'pending').length;
  const hasSheet = Boolean(activeBook()?.spreadsheetId);
  updateOnboarding();
  if (!navigator.onLine) {
    setSyncStatus(pending ? 'Saved offline' : 'You are offline', pending ? `${pending} ${pending === 1 ? 'entry is' : 'entries are'} waiting on this device.` : 'Your saved cashbook is available on this device.', 'offline');
  } else if (pending) {
    setSyncStatus('Waiting to sync', `${pending} ${pending === 1 ? 'entry is' : 'entries are'} saved here. ${hasSheet ? 'Tap “Sync now” to send them to your Sheet.' : 'Tap “Create a new Sheet” in Settings.'}`, 'pending');
  } else if (!hasSheet) {
    setSyncStatus('Saved on this device', `“${activeBook()?.name || 'This book'}” has no Sheet yet. Tap “Create a new Sheet” in Settings.`, 'pending');
  } else if (!tokenIsValid()) {
    setSyncStatus('Google Sheet connected', 'Everything is saved. Tap “Sync now” any time to refresh your Sheet.', 'pending');
  } else {
    setSyncStatus('Google Sheet connected', 'New entries sync automatically while this app is open and online.', 'ready');
  }
}

// ===== GOOGLE =====
function spreadsheetIdFrom(value) { const m = String(value || '').trim().match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/); return m ? m[1] : String(value || '').trim(); }
async function loadConfigFromForm() {
  const saved = await getSetting('googleConfig', {});
  const book = activeBook();
  return {
    currencyCode: elements.currencyCode?.value?.trim().toUpperCase() || saved.currencyCode || DEFAULT_CURRENCY,
    clientId: elements.clientId?.value?.trim() || saved.clientId || DEFAULT_CLIENT_ID,
    apiKey: elements.apiKey?.value?.trim() || saved.apiKey || DEFAULT_API_KEY,
    appId: elements.appId?.value?.trim() || saved.appId || DEFAULT_APP_ID,
    spreadsheetId: spreadsheetIdFrom(elements.spreadsheetInput?.dataset?.spreadsheetId || book?.spreadsheetId || ''),
    spreadsheetName: elements.spreadsheetInput?.dataset?.spreadsheetName || book?.spreadsheetName || '',
    responseTab: elements.responseTab?.value?.trim() || book?.responseTab || 'Form responses 1',
    dashboardTab: elements.dashboardTab?.value?.trim() || book?.dashboardTab || 'Dashboard'
  };
}
async function loadSavedConfig() {
  const config = await bookConfig(activeBook());
  const currencyCode = configureCurrency(config.currencyCode || DEFAULT_CURRENCY);
  if (elements.currencyCode) elements.currencyCode.value = currencyCode;
  if (elements.clientId) elements.clientId.value = config.clientId || DEFAULT_CLIENT_ID;
  if (elements.apiKey) elements.apiKey.value = config.apiKey || DEFAULT_API_KEY;
  if (elements.appId) elements.appId.value = config.appId || DEFAULT_APP_ID;
  const sheetId = config.spreadsheetId || '', sheetName = config.spreadsheetName || '';
  if (elements.spreadsheetInput) {
    elements.spreadsheetInput.dataset.spreadsheetId = sheetId;
    elements.spreadsheetInput.dataset.spreadsheetName = sheetName;
    elements.spreadsheetInput.value = sheetId ? `${sheetName || 'Selected Sheet'} · ${sheetId}` : '';
  }
  if (elements.responseTab) elements.responseTab.value = config.responseTab || 'Form responses 1';
  if (elements.dashboardTab) elements.dashboardTab.value = config.dashboardTab || 'Dashboard';
  if (sheetId) setSetupStatus('Settings saved on this device. Connect Google when you’re ready.');
}
async function saveConfig() {
  const form = await loadConfigFromForm();
  try {
    await persistCurrencyCode(form.currencyCode);
    const saved = await getSetting('googleConfig', {});
    await saveSetting('googleConfig', { ...saved, clientId: form.clientId, apiKey: form.apiKey, appId: form.appId, currencyCode: form.currencyCode });
    await updateActiveBookConfig({ spreadsheetId: form.spreadsheetId, spreadsheetName: form.spreadsheetName, responseTab: form.responseTab, dashboardTab: form.dashboardTab });
    setSetupStatus(`Settings saved for “${activeBook().name}”. No Google access has been requested.`);
    announce('Sync settings saved for this book.');
    await refreshView();
  } catch (error) { setSetupStatus(error.message || 'Could not save settings.', true); }
}
async function persistCurrencyCode(currencyCode) {
  let n;
  try { n = configureCurrency(currencyCode); } catch { throw new Error('Enter a three-letter ISO 4217 currency code supported by this browser, such as NPR, USD, EUR, or INR.'); }
  const current = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const records = await getAllTransactions();
  if (records.length && n !== current) { configureCurrency(current); elements.currencyCode.value = current; throw new Error(`This cashbook already has records in ${current}. Use a new device or clear records to start in ${n}.`); }
  await saveSetting('currencyCode', n);
  return n;
}
function loadGoogleIdentity() {
  if (window.google?.accounts?.oauth2) return Promise.resolve();
  return new Promise((res, rej) => {
    const ex = document.querySelector('script[data-google-identity]');
    if (ex) { ex.addEventListener('load', res, { once: true }); ex.addEventListener('error', () => rej(new Error('Could not load Google sign-in. Check your internet connection.')), { once: true }); return; }
    const s = document.createElement('script'); s.src = 'https://accounts.google.com/gsi/client'; s.async = true; s.defer = true; s.dataset.googleIdentity = 'true';
    s.onload = res; s.onerror = () => rej(new Error('Could not load Google sign-in. Check your internet connection.')); document.head.append(s);
  });
}
async function connectGoogle() {
  const config = await loadConfigFromForm();
  if (!config.clientId || !config.apiKey || !config.appId) { setSetupStatus('Google credentials missing. Please check settings.', true); elements.settingsPanel.open = true; return; }
  if (!config.spreadsheetId) { setSetupStatus('Choose your Google Sheet first, or tap “Create New Sheet”.', true); elements.settingsPanel.open = true; return; }
  if (!navigator.onLine) { setSetupStatus('Connect Google while online. Your offline entries are safe on this device.', true); return; }
  try { await persistCurrencyCode(config.currencyCode); } catch (error) { setSetupStatus(error.message || 'Check the currency code.', true); return; }
  const saved = await getSetting('googleConfig', {});
  await saveSetting('googleConfig', { ...saved, clientId: config.clientId, apiKey: config.apiKey, appId: config.appId, currencyCode: config.currencyCode });
  await updateActiveBookConfig({ responseTab: config.responseTab, dashboardTab: config.dashboardTab });
  elements.connectGoogle.disabled = true;
  setSetupStatus('Requesting access to your Google Sheet…');
  try { accessToken = await requestGoogleToken(await bookConfig(activeBook())); await syncAllBooks(); }
  catch (error) { clearSavedToken(); setSetupStatus(error.message || 'Could not connect to Google Sheets.', true); }
  finally { elements.connectGoogle.disabled = false; await refreshView(); }
}
function requestGoogleToken(config, promptMode = '') {
  let wantsChooser = false; try { wantsChooser = localStorage.getItem(CHOOSE_ACCOUNT_KEY) === '1'; } catch {}
  const prompt = wantsChooser ? 'select_account' : promptMode;
  return loadGoogleIdentity().then(() => new Promise((res, rej) => {
    const client = window.google.accounts.oauth2.initTokenClient({
      client_id: config.clientId, scope: DRIVE_FILE_SCOPE,
      callback: (response) => {
        if (response.error || !response.access_token) { rej(new Error(response.error_description || response.error || 'Google access was not granted.')); return; }
        saveToken(response.access_token, response.expires_in);
        try { localStorage.removeItem(CHOOSE_ACCOUNT_KEY); } catch {}
        res(response.access_token);
      },
      error_callback: (error) => rej(new Error(error.message || 'Google permission was closed.'))
    });
    client.requestAccessToken({ prompt });
  }));
}
function loadGooglePicker() {
  return new Promise((res, rej) => {
    const finish = () => { if (!window.gapi?.load) { rej(new Error('Google Picker could not start.')); return; } window.gapi.load('picker', { callback: res }); };
    if (window.gapi?.load) return finish();
    const ex = document.querySelector('script[data-google-picker]');
    if (ex) { ex.addEventListener('load', finish, { once: true }); ex.addEventListener('error', () => rej(new Error('Could not load Google Picker.')), { once: true }); return; }
    const s = document.createElement('script'); s.src = 'https://apis.google.com/js/api.js'; s.async = true; s.defer = true; s.dataset.googlePicker = 'true';
    s.onload = finish; s.onerror = () => rej(new Error('Could not load Google Picker. Check your internet connection.')); document.head.append(s);
  });
}
function showGoogleSheetPicker(config, token) {
  return loadGooglePicker().then(() => new Promise((res, rej) => {
    try {
      const view = new window.google.picker.DocsView(window.google.picker.ViewId.SPREADSHEETS);
      view.setIncludeFolders(true); view.setSelectFolderEnabled(false);
      const picker = new window.google.picker.PickerBuilder()
        .setAppId(config.appId).setDeveloperKey(config.apiKey).setOAuthToken(token)
        .setOrigin(window.location.origin).setTitle('Choose a Sheet for this book').addView(view)
        .setCallback((data) => {
          if (data.action === window.google.picker.Action.PICKED) res(data.docs?.[0] || null);
          if (data.action === window.google.picker.Action.CANCEL) res(null);
        }).build();
      picker.setVisible(true);
    } catch (e) { rej(e); }
  }));
}
function showFolderPicker(config, token) {
  return loadGooglePicker().then(() => new Promise((res, rej) => {
    try {
      const view = new window.google.picker.DocsView(window.google.picker.ViewId.FOLDERS);
      view.setSelectFolderEnabled(true); view.setIncludeFolders(true);
      const picker = new window.google.picker.PickerBuilder()
        .setAppId(config.appId).setDeveloperKey(config.apiKey).setOAuthToken(token)
        .setOrigin(window.location.origin).setTitle('Choose a folder for this Sheet').addView(view)
        .setCallback((data) => {
          if (data.action === window.google.picker.Action.PICKED) res(data.docs?.[0]?.id || null);
          if (data.action === window.google.picker.Action.CANCEL) res(null);
        }).build();
      picker.setVisible(true);
    } catch (e) { rej(e); }
  }));
}
async function chooseGoogleSheet() {
  if (!navigator.onLine) { setSetupStatus('Choose a Google Sheet while online.', true); return; }
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message || 'Google sign-in was not completed.', true); return; }
  const config = await loadConfigFromForm();
  if (!config.clientId || !config.apiKey || !config.appId) { setSetupStatus('Google credentials missing. Please check settings.', true); elements.settingsPanel.open = true; return; }
  try { await persistCurrencyCode(config.currencyCode); } catch (e) { setSetupStatus(e.message || 'Check the currency code.', true); return; }
  elements.chooseGoogleSheet.disabled = true;
  setSetupStatus('Opening Google Sheets picker…');
  try {
    const saved = await getSetting('googleConfig', {});
    await saveSetting('googleConfig', { ...saved, clientId: config.clientId, apiKey: config.apiKey, appId: config.appId, currencyCode: config.currencyCode });
    const selected = await showGoogleSheetPicker(config, accessToken);
    if (!selected) { setSetupStatus('No Sheet selected.'); return; }
    config.spreadsheetId = selected.id;
    config.spreadsheetName = selected.name || 'Selected Sheet';
    try {
      const tabs = await readSheetTabs({ ...config, spreadsheetId: config.spreadsheetId });
      const titles = tabs.map((t) => t.title);
      config.responseTab = titles.find((t) => /form responses/i.test(t)) || titles.find((t) => !/dashboard/i.test(t) && t !== PERIODS_TAB) || 'Form responses 1';
      config.dashboardTab = titles.find((t) => /dashboard/i.test(t)) || 'Dashboard';
    } catch {}
    elements.spreadsheetInput.dataset.spreadsheetId = config.spreadsheetId;
    elements.spreadsheetInput.dataset.spreadsheetName = config.spreadsheetName;
    elements.spreadsheetInput.value = `${config.spreadsheetName} · ${config.spreadsheetId}`;
    if (elements.responseTab) elements.responseTab.value = config.responseTab;
    if (elements.dashboardTab) elements.dashboardTab.value = config.dashboardTab;
    await updateActiveBookConfig({ spreadsheetId: config.spreadsheetId, spreadsheetName: config.spreadsheetName, responseTab: config.responseTab, dashboardTab: config.dashboardTab });
    setSetupStatus(`Selected “${config.spreadsheetName}” for ${activeBook().name}. Loading history…`);
    await syncAllBooks();
  } catch (e) { clearSavedToken(); setSetupStatus(e.message || 'Could not select the Google Sheet.', true); }
  finally { elements.chooseGoogleSheet.disabled = false; }
}

// ===== DRIVE FOLDER HELPERS =====
async function createDriveFolder(name) {
  if (!accessToken || tokenExpiresAt <= Date.now() + 5000) throw new Error('Google access expired.');
  const res = await fetch('https://www.googleapis.com/drive/v3/files?fields=id', {
    method: 'POST',
    headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: String(name || 'New folder'), mimeType: 'application/vnd.google-apps.folder' })
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { if (res.status === 401) clearSavedToken(); throw new Error(body.error?.message || `Could not create folder (${res.status}).`); }
  if (!body.id) throw new Error('Folder created but Google did not return an ID.');
  return body.id;
}
async function moveFileToFolder(fileId, folderId) {
  if (!accessToken || !folderId) return false;
  try {
    let res = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?addParents=${encodeURIComponent(folderId)}&removeParents=root&fields=id,parents`,
      { method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (res.ok) return true;
    // Fallback: try only addParents (may leave file visible in both locations)
    res = await fetch(
      `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(fileId)}?addParents=${encodeURIComponent(folderId)}&fields=id,parents`,
      { method: 'PATCH', headers: { Authorization: `Bearer ${accessToken}` } }
    );
    if (res.ok) return true;
    const body = await res.json().catch(() => ({}));
    console.warn('Move to folder failed:', res.status, body);
    return false;
  } catch (e) { console.warn('Move to folder error:', e); return false; }
}

// ===== DASHBOARD / SHEET CREATION =====
function buildDashboardValues(config, startingBalance = 0) {
  const tab = quoteSheetName(config.responseTab);
  const thisMonth = (c) => `=SUMIFS(${tab}!${c}:${c},${tab}!A:A,">="&EOMONTH(TODAY(),-1)+1,${tab}!A:A,"<"&EOMONTH(TODAY(),0)+1)`;
  return [
    ['MY MONEY DASHBOARD', ''], ['', ''],
    ['Total Money Came In', `=SUMIFS(${tab}!B:B,${tab}!A:A,">0")`],
    ['Total Money Went Out', `=SUMIFS(${tab}!C:C,${tab}!A:A,">0")`],
    ['Net money movement', '=B3-B4'], ['', ''],
    ['MONTHLY SUMMARY', ''],
    ['Money Came In This Month', thisMonth('B')],
    ['Money Went Out This Month', thisMonth('C')],
    ['Net Movement This Month', '=B8-B9'], ['', ''],
    ['Starting balance (set it in B13)', ''], ['', startingBalance || 0]
  ];
}
async function styleNewSheet(config, created) {
  const ids = new Map((created.sheets || []).map((s) => [s.properties.title, s.properties.sheetId]));
  const responseId = ids.get(config.responseTab), dashboardId = ids.get(config.dashboardTab);
  if (responseId === undefined || dashboardId === undefined) return;
  const symbol = config.currencyCode === 'NPR' ? 'Rs' : config.currencyCode;
  const money = { type: 'NUMBER', pattern: `"${symbol} "#,##0.00` };
  const green = { red: 0.122, green: 0.42, blue: 0.314 };
  const white = { red: 1, green: 1, blue: 1 };
  const cells = (sheetId, r0, r1, c0, c1, uf, fields) => ({ repeatCell: { range: { sheetId, startRowIndex: r0, endRowIndex: r1, startColumnIndex: c0, endColumnIndex: c1 }, cell: { userEnteredFormat: uf }, fields } });
  const width = (sheetId, s, e, px) => ({ updateDimensionProperties: { range: { sheetId, dimension: 'COLUMNS', startIndex: s, endIndex: e }, properties: { pixelSize: px }, fields: 'pixelSize' } });
  await sheetsBatchUpdate(config, [
    { updateSheetProperties: { properties: { sheetId: responseId, gridProperties: { frozenRowCount: 1 } }, fields: 'gridProperties.frozenRowCount' } },
    cells(responseId, 0, 1, 0, 4, { backgroundColor: green, textFormat: { bold: true, foregroundColor: white } }, 'userEnteredFormat(backgroundColor,textFormat)'),
    cells(responseId, 1, 2000, 0, 1, { numberFormat: { type: 'DATE_TIME', pattern: 'dd mmm yyyy, hh:mm' }, horizontalAlignment: 'LEFT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    cells(responseId, 1, 2000, 1, 3, { numberFormat: { type: 'NUMBER', pattern: '#,##0.00' } }, 'userEnteredFormat.numberFormat'),
    width(responseId, 0, 1, 190), width(responseId, 1, 3, 170), width(responseId, 3, 4, 280), width(responseId, 4, 5, 300),
    cells(dashboardId, 0, 1, 0, 1, { textFormat: { bold: true, fontSize: 14 } }, 'userEnteredFormat.textFormat'),
    cells(dashboardId, 6, 7, 0, 1, { textFormat: { bold: true, fontSize: 12 } }, 'userEnteredFormat.textFormat'),
    cells(dashboardId, 4, 5, 0, 2, { textFormat: { bold: true } }, 'userEnteredFormat.textFormat'),
    cells(dashboardId, 9, 10, 0, 2, { textFormat: { bold: true } }, 'userEnteredFormat.textFormat'),
    cells(dashboardId, 2, 5, 1, 2, { numberFormat: money, horizontalAlignment: 'RIGHT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    cells(dashboardId, 7, 10, 1, 2, { numberFormat: money, horizontalAlignment: 'RIGHT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    cells(dashboardId, 12, 13, 1, 2, { numberFormat: money, horizontalAlignment: 'RIGHT' }, 'userEnteredFormat(numberFormat,horizontalAlignment)'),
    width(dashboardId, 0, 1, 280), width(dashboardId, 1, 2, 180)
  ]);
}

// Simplified: one prompt, sheet created FIRST, folder best-effort AFTER.
async function createNewSpreadsheet(options = {}) {
  const { syncAfter = false, askFolder = true } = options;
  if (!navigator.onLine) { setSetupStatus('You are offline. Creating a Sheet needs the internet.', true); return; }
  try { await ensureSignedIn(); } catch (e) { setSetupStatus(e.message || 'Google sign-in was not completed.', true); return; }
  const config = await loadConfigFromForm();
  if (!config.clientId || !config.apiKey || !config.appId) { setSetupStatus('Google credentials missing. Please check settings.', true); elements.settingsPanel.open = true; return; }
  try { await persistCurrencyCode(config.currencyCode); } catch (e) { setSetupStatus(e.message || 'Check the currency code.', true); return; }

  const book = activeBook();
  const bookName = book.name;

  // Single prompt. Sheet is created FIRST regardless of what happens below.
  let folderName = '';
  let pickedFolderId = null;
  if (askFolder) {
    const input = window.prompt(
      `Create a new Google Sheet for "${bookName}"?\n\n` +
      `• Type a folder name to create a new folder and save inside.\n` +
      `• Type "pick" to choose an existing folder.\n` +
      `• Leave blank to save in My Drive root.`,
      ''
    );
    if (input === null) { setSetupStatus('Cancelled. Nothing was created.'); return; }
    const trimmed = input.trim();
    if (trimmed.toLowerCase() === 'pick') {
      try { pickedFolderId = await showFolderPicker(config, accessToken); }
      catch { pickedFolderId = null; }
    } else if (trimmed) {
      folderName = trimmed;
    }
  }

  elements.createNewSheet.disabled = true;
  elements.chooseGoogleSheet.disabled = true;
  setSetupStatus('Creating the spreadsheet in your Drive…');

  let spreadsheetId = null;
  try {
    // 1. Create sheet FIRST (critical - guaranteed to happen)
    const title = `My Cashbook — ${bookName}`;
    const responseTab = (config.responseTab && config.responseTab !== 'Form responses 1' && config.responseTab !== 'Form responses')
      ? config.responseTab : bookName;
    const dashboardTab = config.dashboardTab || 'Dashboard';

    const savedCfg = await getSetting('googleConfig', {});
    await saveSetting('googleConfig', { ...savedCfg, clientId: config.clientId, apiKey: config.apiKey, appId: config.appId, currencyCode: config.currencyCode });

    const res = await fetch('https://sheets.googleapis.com/v4/spreadsheets', {
      method: 'POST',
      headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        properties: { title },
        sheets: [{ properties: { title: responseTab } }, { properties: { title: dashboardTab } }]
      })
    });
    const created = await res.json().catch(() => ({}));
    if (!res.ok) { if (res.status === 401) clearSavedToken(); throw new Error(created.error?.message || `Google returned ${res.status}.`); }
    spreadsheetId = created.spreadsheetId;
    if (!spreadsheetId) throw new Error('Google did not return the new spreadsheet ID.');

    // 2. Folder step (best-effort - failure doesn't kill the sheet)
    let folderNote = '';
    if (folderName) {
      setSetupStatus(`Creating folder “${folderName}” and moving the Sheet…`);
      try {
        const folderId = await createDriveFolder(folderName);
        const moved = await moveFileToFolder(spreadsheetId, folderId);
        if (moved) folderNote = ` (in folder “${folderName}”)`;
        else folderNote = ` (folder “${folderName}” created, but the Sheet couldn't be moved — find it in My Drive root)`;
      } catch (e) {
        folderNote = ` (folder step failed: ${e.message || 'unknown error'} — Sheet is in My Drive root)`;
      }
    } else if (pickedFolderId) {
      setSetupStatus('Moving the Sheet into your chosen folder…');
      const moved = await moveFileToFolder(spreadsheetId, pickedFolderId);
      if (!moved) folderNote = ' (could not move into the chosen folder — Sheet is in My Drive root)';
    }

    // 3. Save to book
    config.spreadsheetId = spreadsheetId;
    config.spreadsheetName = created.properties?.title || title;
    config.responseTab = responseTab;
    config.dashboardTab = dashboardTab;
    if (elements.spreadsheetInput) {
      elements.spreadsheetInput.dataset.spreadsheetId = spreadsheetId;
      elements.spreadsheetInput.dataset.spreadsheetName = config.spreadsheetName;
      elements.spreadsheetInput.value = `${config.spreadsheetName} · ${spreadsheetId}`;
    }
    if (elements.responseTab) elements.responseTab.value = responseTab;
    if (elements.dashboardTab) elements.dashboardTab.value = dashboardTab;
    await updateActiveBookConfig({ spreadsheetId, spreadsheetName: config.spreadsheetName, responseTab, dashboardTab });

    // 4. Headers + dashboard (starting balance = 0 for "from 0" feel)
    setSetupStatus('Setting up headers and dashboard…');
    const headers = ['Timestamp', `Money Came In (${config.currencyCode})`, `Money Went Out (${config.currencyCode})`, 'Remarks'];
    await sheetsRequest(sheetValuesUrl(spreadsheetId, `${quoteSheetName(responseTab)}!A1:D1`, 'valueInputOption=RAW'), {
      method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [headers] })
    });
    await sheetsRequest(sheetValuesUrl(spreadsheetId, `${quoteSheetName(dashboardTab)}!A1:B13`, 'valueInputOption=USER_ENTERED'), {
      method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: buildDashboardValues(config, 0) })
    });
    try { await styleNewSheet(config, created); } catch {}

    // 5. Reset local starting balance so book + sheet agree (fresh start)
    await saveSetting(`startingBalance:${book.id}`, 0);

    // 6. Optional sync (off by default -> sheet stays at 0 until you tap "Sync now")
    if (syncAfter) {
      setSetupStatus('Syncing saved entries…');
      await syncAllBooks();
    } else {
      const pending = (await getBookTransactions(book.id)).filter((r) => r.syncState === 'pending').length;
      setSetupStatus(
        `Created “${config.spreadsheetName}”${folderNote}. ` +
        (pending > 0
          ? `${pending} ${pending === 1 ? 'entry is' : 'entries are'} waiting on this device — tap “Sync now” to upload them.`
          : 'Ready for new entries.')
      );
    }
    announce('New Google Sheet created and connected.');
  } catch (error) {
    if (spreadsheetId) {
      // Sheet was created but setup failed partway - still save it so user can retry
      try { await updateActiveBookConfig({ spreadsheetId, spreadsheetName: config.spreadsheetName || title, responseTab: config.responseTab, dashboardTab: config.dashboardTab }); } catch {}
      setSetupStatus(`Sheet created (${spreadsheetId}) but setup failed: ${error.message || 'unknown error'}. You can retry sync from Settings.`, true);
    } else {
      setSetupStatus(error.message || 'Could not create the Google Sheet.', true);
    }
  } finally {
    elements.createNewSheet.disabled = false;
    elements.chooseGoogleSheet.disabled = false;
    await refreshView();
  }
}

// ===== SHEET I/O =====
function quoteSheetName(name) { return `'${String(name).replace(/'/g, "''")}'`; }
function formatSheetTimestamp(timestamp, timeZone) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) throw new Error('This entry has an invalid saved date and time.');
  const parts = {};
  for (const p of new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' }).formatToParts(date)) if (p.type !== 'literal') parts[p.type] = p.value;
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}
function sheetSerialToIso(serial, timeZone) {
  const wallMs = Math.round(((Number(serial) - 25569) * 86400000) / 1000) * 1000;
  if (!Number.isFinite(wallMs)) return null;
  if (!timeZone) return new Date(wallMs + new Date(wallMs).getTimezoneOffset() * 60000).toISOString();
  const formatter = new Intl.DateTimeFormat('en-CA', { timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
  const offsetAt = (utcMs) => { const parts = {}; for (const p of formatter.formatToParts(new Date(utcMs))) if (p.type !== 'literal') parts[p.type] = Number(p.value); return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) - Math.floor(utcMs / 1000) * 1000; };
  let utcMs = wallMs - offsetAt(wallMs); utcMs = wallMs - offsetAt(utcMs);
  return new Date(utcMs).toISOString();
}
function columnName(n) { let v = n, r = ''; while (v > 0) { const rem = (v - 1) % 26; r = String.fromCharCode(65 + rem) + r; v = Math.floor((v - 1) / 26); } return r; }
function safeSheetText(value) { const t = String(value ?? ''); if (!t) return ''; return /^[=+\-@\t\r\n]/.test(t) ? `'${t}` : t; }
async function sheetsRequest(url, options = {}) {
  if (!accessToken || tokenExpiresAt <= Date.now() + 5000) throw new Error('Google access expired. Tap “Sync now” to sign in again.');
  const res = await fetch(url, { ...options, headers: { Authorization: `Bearer ${accessToken}`, ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...(options.headers || {}) } });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) { if (res.status === 401) clearSavedToken(); throw new Error(body.error?.message || `Google Sheets returned ${res.status}.`); }
  return body;
}
async function readSpreadsheetTimeZone(config) { const d = await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}?fields=properties.timeZone`); return d.properties?.timeZone || undefined; }
function sheetValuesUrl(id, range, query = '') { const base = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(id)}/values/${encodeURIComponent(range)}`; return query ? `${base}?${query}` : base; }
function findHeaderIndex(headers, pattern) { return headers.findIndex((item) => pattern.test(String(item || '').toLowerCase().replace(/[()]/g, ''))); }
async function ensureResponseHeader(config) {
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.responseTab)}!A1:Z1`, 'valueRenderOption=FORMATTED_VALUE'));
  const headers = data.values?.[0] || [];
  const timestampIndex = findHeaderIndex(headers, /timestamp|date\s*(and|&)\s*time/);
  const incomeIndex = findHeaderIndex(headers, /money\s*came\s*in/);
  const expenseIndex = findHeaderIndex(headers, /money\s*went\s*out/);
  const remarksIndex = findHeaderIndex(headers, /remarks?/);
  if ([timestampIndex, incomeIndex, expenseIndex, remarksIndex].some((i) => i < 0)) throw new Error(`The first row in “${config.responseTab}” must include Timestamp, Money Came In, Money Went Out, and Remarks.`);
  for (const i of [incomeIndex, expenseIndex]) {
    const c = String(headers[i] || '').match(/\(([A-Z]{3})\)/i)?.[1]?.toUpperCase();
    if (c && c !== config.currencyCode) throw new Error(`The response tab is labeled ${c}. Set the app to ${c}, or use a Sheet labeled ${config.currencyCode}.`);
  }
  let idIndex = headers.findIndex((item) => String(item || '').trim().toLowerCase() === 'offline entry id');
  if (idIndex < 0) {
    idIndex = Math.max(timestampIndex, incomeIndex, expenseIndex, remarksIndex) + 1;
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.responseTab)}!${columnName(idIndex + 1)}1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [['Offline Entry ID']] }) });
    headers[idIndex] = 'Offline Entry ID';
  }
  return { headers, timestampIndex, incomeIndex, expenseIndex, remarksIndex, idIndex };
}
function isSummaryRow(row) { const l = String(row[0] ?? '').trim().toUpperCase(); return l.startsWith('TOTAL') || l.startsWith('REMAINING'); }
function parseSheetRow(row, rowIndex, indexes, currencyCode, timeZone) {
  const rawId = String(row[indexes.idIndex] || '').trim();
  const rawT = row[indexes.timestampIndex];
  const ts = String(rawT ?? '').trim();
  if (!ts && !row[indexes.incomeIndex] && !row[indexes.expenseIndex] && !row[indexes.remarksIndex]) return null;
  if (isSummaryRow(row) || ts.toUpperCase().startsWith('TOTAL')) return null;
  const id = rawId || `sheet-row-${rowIndex + 2}`;
  let createdAt = null;
  if (typeof rawT === 'number') createdAt = sheetSerialToIso(rawT, timeZone);
  else if (ts) { const p = Date.parse(ts); createdAt = Number.isNaN(p) ? null : new Date(p).toISOString(); }
  return { id, createdAt, sheetTimestamp: typeof rawT === 'number' ? '' : ts, currencyCode, moneyInMinor: parseMoney(row[indexes.incomeIndex], currencyCode), moneyOutMinor: parseMoney(row[indexes.expenseIndex], currencyCode), remarks: String(row[indexes.remarksIndex] || ''), syncState: rawId ? 'synced' : 'sheet', source: rawId ? 'cashbook' : 'sheet' };
}
async function readResponseSheet(config, indexes, timeZone) {
  const lastIndex = Math.max(indexes.timestampIndex, indexes.incomeIndex, indexes.expenseIndex, indexes.remarksIndex, indexes.idIndex);
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.responseTab)}!A2:${columnName(lastIndex + 1)}`, 'valueRenderOption=UNFORMATTED_VALUE&dateTimeRenderOption=SERIAL_NUMBER'));
  const records = [], summaryRows = [];
  let lastEntryRow = 1;
  (data.values || []).forEach((row, i) => {
    const rn = i + 2;
    if (isSummaryRow(row)) { summaryRows.push(rn); return; }
    const rec = parseSheetRow(row, i, indexes, config.currencyCode, timeZone);
    if (rec) { records.push(rec); lastEntryRow = rn; }
  });
  return { records, lastEntryRow, summaryRows };
}
async function readResponseRows(config, indexes, timeZone) { return (await readResponseSheet(config, indexes, timeZone)).records; }

const TOTALS_COLORS = { dark: { red: 0.1215, green: 0.4196, blue: 0.3137 }, light: { red: 0.9098, green: 0.9490, blue: 0.9254 }, ink: { red: 0.1215, green: 0.4196, blue: 0.3137 }, white: { red: 1, green: 1, blue: 1 } };

async function responseSheetId(config) { const tabs = await readSheetTabs(config); const t = tabs.find((x) => x.title === config.responseTab); return t ? t.sheetId : null; }
const HEADER_STYLE_VERSION = 1;
async function styleHeaderRow(config, indexes) {
  const key = `headerStyled:v${HEADER_STYLE_VERSION}:${config.spreadsheetId}`;
  if (await getSetting(key, false)) return;
  const sheetId = await responseSheetId(config);
  if (sheetId === null) return;
  const { dark, white } = TOTALS_COLORS;
  await sheetsBatchUpdate(config, [
    { repeatCell: { range: { sheetId, startRowIndex: 0, endRowIndex: 1, startColumnIndex: 0, endColumnIndex: indexes.remarksIndex + 1 }, cell: { userEnteredFormat: { backgroundColor: dark, verticalAlignment: 'MIDDLE', textFormat: { bold: true, fontSize: 10, foregroundColor: white } } }, fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat)' } },
    { updateDimensionProperties: { range: { sheetId, dimension: 'ROWS', startIndex: 0, endIndex: 1 }, properties: { pixelSize: 30 }, fields: 'pixelSize' } }
  ]);
  await saveSetting(key, true);
}
async function resetSummaryFormatting(config, summaryRows, endCol) {
  if (!summaryRows.length) return;
  const sheetId = await responseSheetId(config);
  if (sheetId === null) return;
  const reqs = [];
  for (const row of summaryRows) {
    reqs.push({ repeatCell: { range: { sheetId, startRowIndex: row - 1, endRowIndex: row, startColumnIndex: 0, endColumnIndex: endCol }, cell: { userEnteredFormat: {} }, fields: 'userEnteredFormat' } });
    reqs.push({ updateDimensionProperties: { range: { sheetId, dimension: 'ROWS', startIndex: row - 1, endIndex: row }, properties: { pixelSize: 21 }, fields: 'pixelSize' } });
  }
  await sheetsBatchUpdate(config, reqs);
}
async function styleTotalsBlock(config, indexes, totalsRow) {
  const sheetId = await responseSheetId(config);
  if (sheetId === null) return;
  const { dark, light, ink, white } = TOTALS_COLORS;
  const symbol = config.currencyCode === 'NPR' ? 'Rs' : config.currencyCode;
  const endCol = indexes.idIndex + 1;
  const rowRange = (row, sc = 0, ec = endCol) => ({ sheetId, startRowIndex: row - 1, endRowIndex: row, startColumnIndex: sc, endColumnIndex: ec });
  const remainingRow = totalsRow + 1;
  await sheetsBatchUpdate(config, [
    { repeatCell: { range: rowRange(totalsRow), cell: { userEnteredFormat: { backgroundColor: dark, verticalAlignment: 'MIDDLE', textFormat: { bold: false, fontSize: 10, foregroundColor: white } } }, fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat)' } },
    { repeatCell: { range: rowRange(remainingRow), cell: { userEnteredFormat: { backgroundColor: light, verticalAlignment: 'MIDDLE', textFormat: { bold: false, fontSize: 10, foregroundColor: ink }, borders: { bottom: { style: 'SOLID_MEDIUM', color: ink } } } }, fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat,borders)' } },
    { repeatCell: { range: { sheetId, startRowIndex: totalsRow - 1, endRowIndex: remainingRow, startColumnIndex: indexes.incomeIndex, endColumnIndex: indexes.expenseIndex + 1 }, cell: { userEnteredFormat: { numberFormat: { type: 'NUMBER', pattern: `"${symbol} "#,##0.00` }, horizontalAlignment: 'RIGHT' } }, fields: 'userEnteredFormat(numberFormat,horizontalAlignment)' } },
    { repeatCell: { range: rowRange(remainingRow, indexes.remarksIndex, indexes.remarksIndex + 1), cell: { userEnteredFormat: { textFormat: { bold: false, italic: true, fontSize: 9, foregroundColor: ink } } }, fields: 'userEnteredFormat.textFormat' } },
    { updateDimensionProperties: { range: { sheetId, dimension: 'ROWS', startIndex: totalsRow - 1, endIndex: remainingRow }, properties: { pixelSize: 28 }, fields: 'pixelSize' } }
  ]);
}
async function appendPendingForBook(config, indexes, remoteSheet, timeZone, bookId) {
  const remoteIds = new Set(remoteSheet.records.map((r) => r.id));
  const allLocal = await getBookTransactions(bookId);
  const pending = allLocal.filter((r) => r.syncState === 'pending');
  const coreCols = Math.max(indexes.timestampIndex, indexes.incomeIndex, indexes.expenseIndex, indexes.remarksIndex, indexes.idIndex) + 1;
  const endColLetter = columnName(coreCols);
  const tab = quoteSheetName(config.responseTab);
  const inCol = columnName(indexes.incomeIndex + 1);
  const outCol = columnName(indexes.expenseIndex + 1);
  const dashTab = quoteSheetName(config.dashboardTab || 'Dashboard');
  let lastEntryRow = remoteSheet.lastEntryRow;
  const rowsToUpload = [];
  const recordsToUpdate = [];
  for (const record of pending) {
    if (record.currencyCode && record.currencyCode !== config.currencyCode) throw new Error(`A saved entry uses ${record.currencyCode}, but this Sheet uses ${config.currencyCode}.`);
    if (remoteIds.has(record.id)) { await putTransaction({ ...record, syncState: 'synced' }); continue; }
    const row = Array(coreCols).fill('');
    row[indexes.timestampIndex] = formatSheetTimestamp(record.createdAt, timeZone);
    row[indexes.incomeIndex] = (Number(record.moneyInMinor) || 0) / currencyScale(record.currencyCode || config.currencyCode);
    row[indexes.expenseIndex] = (Number(record.moneyOutMinor) || 0) / currencyScale(record.currencyCode || config.currencyCode);
    row[indexes.remarksIndex] = safeSheetText(record.remarks);
    row[indexes.idIndex] = record.id;
    rowsToUpload.push(row); recordsToUpdate.push(record); remoteIds.add(record.id);
  }
  if (remoteSheet.summaryRows.length) {
    await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}/values:batchClear`, { method: 'POST', body: JSON.stringify({ ranges: remoteSheet.summaryRows.map((r) => `${tab}!A${r}:${endColLetter}${r}`) }) });
    try { await resetSummaryFormatting(config, remoteSheet.summaryRows, indexes.idIndex + 1); } catch {}
  }
  if (rowsToUpload.length) {
    const startRow = lastEntryRow + 1, endRow = startRow + rowsToUpload.length - 1;
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${tab}!A${startRow}:${endColLetter}${endRow}`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: rowsToUpload }) });
    for (const r of recordsToUpdate) await putTransaction({ ...r, syncState: 'synced' });
    lastEntryRow = endRow;
  }
  if (lastEntryRow <= 1) return '';
  try {
    const totalsRow = lastEntryRow + 2, sumEnd = totalsRow - 1;
    const totalLine = Array(coreCols).fill('');
    totalLine[indexes.timestampIndex] = 'TOTAL';
    totalLine[indexes.incomeIndex] = `=SUM(${inCol}2:${inCol}${sumEnd})`;
    totalLine[indexes.expenseIndex] = `=SUM(${outCol}2:${outCol}${sumEnd})`;
    const remainingLine = Array(coreCols).fill('');
    remainingLine[indexes.timestampIndex] = 'REMAINING';
    remainingLine[indexes.incomeIndex] = `=${inCol}${totalsRow}-${outCol}${totalsRow}+N(${dashTab}!B13)`;
    remainingLine[indexes.remarksIndex] = 'Money in − money out + starting balance';
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${tab}!A${totalsRow}:${endColLetter}${totalsRow + 1}`, 'valueInputOption=USER_ENTERED'), { method: 'PUT', body: JSON.stringify({ majorDimension: 'ROWS', values: [totalLine, remainingLine] }) });
    try { await styleTotalsBlock(config, indexes, totalsRow); } catch {}
    return '';
  } catch (e) { return `the totals under your entries could not be written (${e.message || 'unknown'}).`; }
}
async function readStartingBalance(config) {
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.dashboardTab)}!B13`, 'valueRenderOption=UNFORMATTED_VALUE'));
  const v = data.values?.[0]?.[0];
  if (v === undefined || v === null || v === '') return null;
  return typeof v === 'number' ? Math.round(v * currencyScale(config.currencyCode)) : parseMoney(v, config.currencyCode);
}
function archiveStamp(date) { const pad = (n) => String(n).padStart(2, '0'); return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}${pad(date.getMinutes())}`; }
async function readSheetTabs(config) { const data = await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}?fields=sheets.properties(sheetId,title)`); return (data.sheets || []).map((s) => s.properties); }
function sheetsBatchUpdate(config, requests) { return sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}:batchUpdate`, { method: 'POST', body: JSON.stringify({ requests }) }); }
async function copySpreadsheetToDrive(config, name) { try { await sheetsRequest(`https://www.googleapis.com/drive/v3/files/${encodeURIComponent(config.spreadsheetId)}/copy`, { method: 'POST', body: JSON.stringify({ name }) }); return true; } catch { return false; } }
async function archiveResponseTab(config, tabs, name) { const src = tabs.find((t) => t.title === config.responseTab); if (!src) throw new Error(`Could not find the “${config.responseTab}” tab.`); await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: src.sheetId, newSheetName: name } }]); }
async function archiveDashboardTab(config, tabs, name) {
  const src = tabs.find((t) => t.title === (config.dashboardTab || 'Dashboard'));
  if (!src) throw new Error(`Could not find the “${config.dashboardTab || 'Dashboard'}” tab.`);
  const dup = await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: src.sheetId, newSheetName: name } }]);
  const newSheetId = dup.replies?.[0]?.duplicateSheet?.properties?.sheetId;
  const rows = dup.replies?.[0]?.duplicateSheet?.properties?.gridProperties?.rowCount || 1000;
  const cols = dup.replies?.[0]?.duplicateSheet?.properties?.gridProperties?.columnCount || 26;
  if (typeof newSheetId !== 'number') throw new Error('Could not duplicate the dashboard tab.');
  await sheetsBatchUpdate(config, [{ copyPaste: { source: { sheetId: newSheetId, startRowIndex: 0, endRowIndex: rows, startColumnIndex: 0, endColumnIndex: cols }, destination: { sheetId: newSheetId, startRowIndex: 0, endRowIndex: rows, startColumnIndex: 0, endColumnIndex: cols }, pasteType: 'PASTE_VALUES', pasteOrientation: 'NORMAL' } }]);
}
async function usedRowCount(config, tabName) { const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(tabName)}!A:A`)); return (data.values || []).length; }
async function deleteOldRows(config, tabs, lastRowNumber) {
  if (lastRowNumber <= 1) return;
  const src = tabs.find((t) => t.title === config.responseTab);
  if (!src) throw new Error(`Could not find the “${config.responseTab}” tab.`);
  await sheetsBatchUpdate(config, [{ deleteDimension: { range: { sheetId: src.sheetId, dimension: 'ROWS', startIndex: 1, endIndex: lastRowNumber } } }]);
}
async function ensurePeriodsTab(config, tabs) {
  if (tabs.some((t) => t.title === PERIODS_TAB)) return;
  await sheetsBatchUpdate(config, [{ addSheet: { properties: { title: PERIODS_TAB } } }]);
  await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A1:C1`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [['Period started (UTC)', 'Starting balance', 'Archive tab']] }) });
}
async function readPeriodStart(config) {
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A2:A`, 'valueRenderOption=UNFORMATTED_VALUE'));
  const starts = (data.values || []).map((r) => String(r[0] || '').trim()).filter((v) => !Number.isNaN(Date.parse(v)));
  return starts.length ? starts[starts.length - 1] : null;
}
async function applySheetPeriod(config, bookId) {
  try {
    const sheetStart = await readPeriodStart(config);
    if (!sheetStart) return;
    const key = `periodStart:${bookId}`;
    const local = Date.parse(await getSetting(key, '') || '');
    if (Number.isNaN(local) || Date.parse(sheetStart) > local) await saveSetting(key, sheetStart);
  } catch {}
}

async function archiveAndStartFresh() {
  const book = activeBook();
  const config = await bookConfig(book);
  if (!config.spreadsheetId || !config.responseTab) { setArchiveStatus('Choose this book’s Sheet and tap Connect & sync first.', true); return; }
  if (!navigator.onLine) { setArchiveStatus('You are offline. Archiving needs the internet so the copy can be saved.', true); return; }
  if (!accessToken || tokenExpiresAt <= Date.now() + 60000) { setArchiveStatus('Tap Connect & sync above first, then try again.', true); return; }
  elements.archiveNow.disabled = true;
  try {
    setArchiveStatus('Syncing this book first…');
    try { await syncBookToSheet(book); } catch (e) { setArchiveStatus(`Could not sync first: ${e.message || 'unknown'}`, true); return; }
    const active = await getActiveBookRecords();
    if (active.some((r) => r.syncState === 'pending')) throw new Error('Some entries are not on your Sheet yet.');
    const income = active.reduce((s, x) => s + (Number(x.moneyInMinor) || 0), 0);
    const expense = active.reduce((s, x) => s + (Number(x.moneyOutMinor) || 0), 0);
    const sb = Number(await getSetting(`startingBalance:${book.id}`, 0)) || 0;
    const carry = elements.carryBalance?.checked ? sb + income - expense : 0;
    const nameForConfirm = (elements.archiveName?.value || '').trim();
    const proceed = window.confirm(
      'Archive this book and start fresh?\n\n' +
      (nameForConfirm ? `• Archive tabs: “${nameForConfirm}” and “${nameForConfirm} - Dashboard”.\n` : '• Archive tabs will be created for your entries and dashboard.\n') +
      `• A copy of your Sheet is saved in Drive first.\n• New balance: ${formatMoney(carry)}.\n\nContinue?`
    );
    if (!proceed) { setArchiveStatus('Cancelled. Nothing was changed.'); return; }
    const now = new Date();
    const stamp = archiveStamp(now);
    const typed = (elements.archiveName?.value || '').replace(/[\[\]*?:\/\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
    const archiveName = typed || `Archive ${stamp}`;
    const dashName = `${archiveName} - Dashboard`;
    const scale = currencyScale(config.currencyCode || activeCurrencyCode);
    setArchiveStatus('Saving a copy…');
    const tabs = await readSheetTabs(config);
    if (tabs.some((t) => t.title.toLowerCase() === archiveName.toLowerCase())) throw new Error(`A tab called “${archiveName}” already exists.`);
    if (tabs.some((t) => t.title.toLowerCase() === dashName.toLowerCase())) throw new Error(`A tab called “${dashName}” already exists.`);
    const driveCopied = await copySpreadsheetToDrive(config, `${config.spreadsheetName || 'Cashbook'} - ${archiveName}`);
    const sourceRows = await usedRowCount(config, config.responseTab);
    setArchiveStatus('Archiving…');
    await archiveResponseTab(config, tabs, archiveName);
    await archiveDashboardTab(config, tabs, dashName);
    setArchiveStatus('Moving old entries…');
    let cleared = false, clearProblem = '';
    try {
      const archived = await usedRowCount(config, archiveName);
      if (archived !== sourceRows) throw new Error('archive copy mismatch');
      await deleteOldRows(config, tabs, sourceRows);
      cleared = true;
    } catch (e) { clearProblem = e.message || 'unknown'; }
    setArchiveStatus('Starting the new period…');
    await ensurePeriodsTab(config, tabs);
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.dashboardTab || 'Dashboard')}!B13`, 'valueInputOption=RAW'), { method: 'PUT', body: JSON.stringify({ values: [[carry / scale]] }) });
    const periodStart = new Date(Math.floor(now.getTime() / 1000) * 1000).toISOString();
    await sheetsRequest(`${sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A:C`)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`, { method: 'POST', body: JSON.stringify({ majorDimension: 'ROWS', values: [[periodStart, carry / scale, `${archiveName}, ${dashName}`]] }) });
    await saveSetting(`periodStart:${book.id}`, periodStart);
    await saveSetting(`startingBalance:${book.id}`, carry);
    if (elements.archiveName) elements.archiveName.value = '';
    await refreshView();
    const where = driveCopied ? `“${archiveName}” + “${dashName}” tabs and a Drive copy` : `“${archiveName}” + “${dashName}” tabs (Drive copy skipped)`;
    const clearNote = cleared ? ' Main tab is empty.' : ` Old rows could not be removed (${clearProblem}). Your data is safe.`;
    setArchiveStatus(`Done. Saved to ${where}.${clearNote}`);
    announce('New period started.');
  } catch (e) { setArchiveStatus(e.message || 'Could not archive. Nothing was deleted.', true); }
  finally { elements.archiveNow.disabled = false; }
}

async function cleanupOldRightSummary(config) { try { await sheetsRequest(`${sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(config.responseTab)}!G1:Z1`)}:clear`, { method: 'POST' }); } catch {} }

async function syncBookToSheet(book) {
  const config = await bookConfig(book);
  if (!config.spreadsheetId) throw new Error('This book has no Google Sheet assigned.');
  const indexes = await ensureResponseHeader(config);
  try { await styleHeaderRow(config, indexes); } catch {}
  await cleanupOldRightSummary(config);
  const timeZone = await readSpreadsheetTimeZone(config);
  const before = await readResponseSheet(config, indexes, timeZone);
  const totalsWarning = await appendPendingForBook(config, indexes, before, timeZone, book.id);
  const after = await readResponseRows(config, indexes, timeZone);
  await mergeSheetRecords(after, book.id);
  const sb = await readStartingBalance(config).catch(() => null);
  if (sb !== null) await saveSetting(`startingBalance:${book.id}`, sb);
  await applySheetPeriod(config, book.id);
  if (totalsWarning) throw new Error(totalsWarning);
}
async function syncAllBooks() {
  if (isSyncing) return;
  if (!cryptoKey) return;
  if (!navigator.onLine) { setSyncStatus('Saved offline', 'Your entries are queued on this device for when you are online.', 'offline'); return; }
  if (!tokenIsValid()) { setSyncStatus('Waiting to sync', 'Tap “Sync now” to sign in and send your entries.', 'pending'); return; }
  isSyncing = true; elements.syncNow.disabled = true;
  const allRecs = await getAllTransactions();
  const targets = [], skipped = [], seen = new Set();
  for (const b of [activeBook(), ...books]) {
    if (!b || seen.has(b.id)) continue;
    seen.add(b.id);
    if (b.spreadsheetId) targets.push(b);
    else {
      const c = allRecs.filter((r) => r.bookId === b.id && r.syncState === 'pending').length;
      if (c > 0) skipped.push({ name: b.name, count: c });
    }
  }
  const total = targets.length; let i = 0;
  const errors = [];
  try {
    for (const book of targets) {
      i++;
      setSyncStatus('Syncing', `Syncing ${book.name} (${i} of ${total})…`, 'ready');
      try { await syncBookToSheet(book); } catch (e) { errors.push({ name: book.name, message: e.message || 'unknown error' }); }
    }
    lastSyncFinishedAt = Date.now();
    if (errors.length) {
      const msg = errors.map((e) => `“${e.name}”: ${e.message}`).join('; ');
      setSyncStatus('Sync needs attention', msg, 'error');
      setSetupStatus(`Sync problems: ${msg}`, true);
    } else if (skipped.length) {
      const msg = skipped.map((s) => `“${s.name}” has ${s.count} waiting ${s.count === 1 ? 'entry' : 'entries'} but no Sheet`).join('; ');
      setSyncStatus('Some books need a Sheet', msg + '. Open Settings → Books to create one.', 'pending');
      setSetupStatus(msg + '. Open Settings → Books to create one.', true);
    } else if (total === 0) {
      setSyncStatus('Saved on this device', 'No book has a Google Sheet connected yet.', 'ready');
    } else {
      setSyncStatus('Google Sheets connected', 'All connected books are synced.', 'ready');
      setSetupStatus('All connected books synced.');
    }
  } finally { isSyncing = false; elements.syncNow.disabled = false; await refreshView(); }
}
async function oneTapSync() {
  if (!cryptoKey) return;
  if (!navigator.onLine) { announce('You are offline. Your entries are safe on this device.'); return; }
  const allRecs = await getAllTransactions();
  const pendingNoSheet = [];
  for (const b of books) {
    if (!b.spreadsheetId) {
      const c = allRecs.filter((r) => r.bookId === b.id && r.syncState === 'pending').length;
      if (c > 0) pendingNoSheet.push({ book: b, count: c });
    }
  }
  if (!books.some((b) => b.spreadsheetId) && !pendingNoSheet.length) {
    updateOnboarding(); elements.onboardingCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    announce('Create or choose a Sheet for this book first.'); return;
  }
  try { await ensureSignedIn(); } catch (e) { setSyncStatus('Sign-in needed', e.message || 'Google sign-in was not completed.', 'error'); return; }
  const original = currentBookId;
  for (const { book, count } of pendingNoSheet) {
    const ok = window.confirm(`Book “${book.name}” has ${count} ${count === 1 ? 'entry' : 'entries'} waiting but no Google Sheet.\n\nCreate a Sheet for “${book.name}” now?\n\nYes = create it (in My Drive root).\nNo = skip.`);
    if (!ok) continue;
    if (book.id !== currentBookId) await switchBook(book.id);
    try { await createNewSpreadsheet({ syncAfter: false, askFolder: false }); } catch (e) {}
  }
  if (currentBookId !== original) await switchBook(original);
  await syncAllBooks();
}
async function autoSync() {
  if (isSyncing || !cryptoKey || !navigator.onLine) return;
  if (!books.some((b) => b.spreadsheetId)) return;
  const all = await getAllTransactions();
  const hasPending = all.some((r) => r.syncState === 'pending');
  const stale = Date.now() - lastSyncFinishedAt > 10 * 60 * 1000;
  if (!hasPending && !stale) return;
  if (!tokenIsValid()) { await refreshView(); return; }
  await syncAllBooks();
}
async function mergeSheetRecords(remoteRecords, bookId) {
  const local = await getBookTransactions(bookId);
  const byId = new Map(local.map((r) => [r.id, r]));
  for (const remote of remoteRecords) {
    const current = byId.get(remote.id);
    if (current?.syncState === 'pending') continue;
    await putTransaction(current ? { ...current, ...remote, bookId, createdAt: current.createdAt || remote.createdAt, syncState: 'synced' } : { ...remote, bookId });
  }
}

// ===== LOCK =====
function showLockScreen(mode) {
  elements.lockScreen.style.display = 'flex'; elements.appShell.style.display = 'none';
  const hp = mode === 'password' || mode === 'both';
  const hb = mode === 'biometrics' || mode === 'both';
  elements.unlockForm.style.display = hp ? 'flex' : 'none';
  elements.biometricBtn.style.display = hb ? 'flex' : 'none';
  elements.forgotPasswordBtn.style.display = 'inline-block';
  elements.forgotPasswordBtn.textContent = hp ? 'Forgot password?' : 'Can’t unlock? Erase this device';
  elements.unlockPassword.value = ''; elements.unlockBtn.textContent = 'Unlock Cashbook';
}
function lockApp() {
  cryptoKey = null; masterKeyRaw = null; clearTimeout(idleTimeout);
  const state = securityState();
  showLockScreen(state.hasPassword && state.hasBiometrics ? 'both' : state.hasPassword ? 'password' : 'biometrics');
  elements.lockMessage.textContent = state.hasPassword ? 'Enter your master password to unlock your encrypted cashbook.' : 'Use Face ID / fingerprint to unlock your cashbook.';
}
function resetIdleTimer() { clearTimeout(idleTimeout); if (!cryptoKey || !isProtected()) return; idleTimeout = setTimeout(() => lockApp(), 5 * 60 * 1000); }
async function updateOfflineStatus() {
  const build = `build ${APP_BUILD}`;
  if (!elements.storageStatus) return;
  elements.storageStatus.textContent = `Checking offline files… · ${build}`;
  if (!('serviceWorker' in navigator) || !('caches' in window)) { elements.storageStatus.textContent = `Offline mode is not supported in this browser · ${build}`; return; }
  const active = await Promise.race([navigator.serviceWorker.ready.then(() => true).catch(() => false), new Promise((r) => setTimeout(() => r(false), 10000))]);
  let saved = active;
  if (active) { for (const u of ['./', './app.js', './styles.css']) { if (!(await caches.match(u, { ignoreSearch: true }))) { saved = false; break; } } }
  elements.storageStatus.textContent = saved ? `Works offline ✓ · ${build}` : `Offline files not saved yet. Open the app once while online. · ${build}`;
}
async function startApp() {
  elements.lockScreen.style.display = 'none'; elements.appShell.style.display = 'block';
  updateSecurityUi();
  await loadBooks();
  await loadSavedConfig();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  loadSavedToken();
  cachedConfig = await bookConfig(activeBook());
  if (elements.onboardCurrency) elements.onboardCurrency.value = cachedConfig.currencyCode || activeCurrencyCode || DEFAULT_CURRENCY;
  renderBookSwitcher();
  await refreshView();
  if (navigator.onLine) void loadGoogleIdentity().catch(() => {});
  void autoSync();
  void updateOfflineStatus();
  resetIdleTimer();
  if ('serviceWorker' in navigator) { navigator.serviceWorker.getRegistration().then((r) => r?.update()).catch(() => {}); }
}
async function readAllRaw(storeName) {
  const db = await openDatabase();
  const tx = db.transaction(storeName, 'readonly');
  return new Promise((res, rej) => { const r = tx.objectStore(storeName).getAll(); r.onsuccess = () => res(r.result || []); r.onerror = () => rej(r.error); });
}
async function migrateFromLegacy(legacyKey) {
  if (!masterKeyRaw) { await generateMasterKey(); localStorage.setItem('cb_key_pending', JSON.stringify(await wrapMasterKeyWith(legacyKey))); }
  const transactions = await readAllRaw(STORE_TRANSACTIONS);
  for (const record of transactions) {
    let payload = record;
    if (record.encrypted) { const p = await decryptText(record.encrypted, legacyKey); if (p == null) continue; try { payload = JSON.parse(p); } catch { continue; } payload.id = record.id; }
    await putTransaction(payload);
  }
  const settings = await readAllRaw(STORE_SETTINGS);
  for (const setting of settings) {
    let value;
    if (setting.encrypted) { const p = await decryptText(setting.encrypted, legacyKey); if (p == null) continue; try { value = JSON.parse(p); } catch { continue; } }
    else if (setting.value !== undefined) value = setting.value;
    else continue;
    await saveSetting(setting.key, value);
  }
  localStorage.setItem('cb_key_wrapped', JSON.stringify(await wrapMasterKeyWith(legacyKey)));
  localStorage.setItem('cb_has_password', 'true');
  localStorage.removeItem('cb_key_pending');
}
async function unlockWithPassword(password) {
  const hasWrapped = localStorage.getItem('cb_key_wrapped');
  const hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const salt = localStorage.getItem('cb_salt');
  const isLegacy = !!salt && !hasWrapped && !hasPrf && !localStorage.getItem('cb_key_raw');
  if (isLegacy) {
    const legacyKey = await derivePasswordKek(password, salt);
    cryptoKey = legacyKey; masterKeyRaw = null;
    await openDatabase();
    let ok = (await getSetting('__auth_check__', null)) === 'valid';
    const pending = localStorage.getItem('cb_key_pending');
    if (pending) { try { await unwrapMasterKey(JSON.parse(pending), legacyKey); ok = true; } catch {} }
    if (!ok) { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
    await migrateFromLegacy(legacyKey);
  } else if (hasWrapped) {
    const kek = await derivePasswordKek(password, salt);
    try { await unwrapMasterKey(JSON.parse(hasWrapped), kek); }
    catch { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
    await openDatabase();
    if ((await getSetting('__auth_check__', null)) !== 'valid') { cryptoKey = null; masterKeyRaw = null; throw new Error('Incorrect password.'); }
  } else throw new Error('No master password is set. Use Face ID / fingerprint to unlock.');
  await startApp();
}
async function switchGoogleAccount() {
  const ok = window.confirm('Use a different Google account?\n\n• Your current Google Sheet is NOT changed or deleted.\n• Your entries stay on this device.\n• This book’s entries will be uploaded to the Sheet you create or pick with the new account.\n\nContinue?');
  if (!ok) return;
  try {
    clearSavedToken();
    localStorage.setItem(CHOOSE_ACCOUNT_KEY, '1');
    await updateActiveBookConfig({ spreadsheetId: '', spreadsheetName: '' });
    if (elements.spreadsheetInput) { elements.spreadsheetInput.dataset.spreadsheetId = ''; elements.spreadsheetInput.dataset.spreadsheetName = ''; elements.spreadsheetInput.value = ''; }
    for (const record of await getActiveBookRecords()) { if (record.syncState !== 'pending') await putTransaction({ ...record, syncState: 'pending' }); }
    lastSyncFinishedAt = 0;
    await refreshView();
    setSetupStatus('Ready for a new account. Create or pick a Sheet for this book.');
    announce('Choose your new Google account below.');
    elements.onboardingCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  } catch (e) { setSetupStatus(e.message || 'Could not switch accounts.', true); }
}
async function forgotPassword() {
  const msg = ['Forgot your password?', '', 'Your entries on this device are encrypted and cannot be recovered without the password.', 'If you synced to a Google Sheet, those entries are safe there.', '', 'Type ERASE to erase this device\u2019s data and start fresh.'].join('\n');
  const input = window.prompt(msg);
  if (input === null) return;
  if (input.trim() !== 'ERASE') { alert('Nothing was erased. Type ERASE exactly to confirm.'); return; }
  try { await new Promise((r) => { const req = indexedDB.deleteDatabase(DB_NAME); req.onsuccess = req.onerror = req.onblocked = () => r(); }); } catch {}
  ['cb_salt', 'cb_key_wrapped', 'cb_key_raw', 'cb_prf_salt', 'cb_prf_cred_id', 'cb_prf_key_wrapped', 'cb_has_password', 'cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach((k) => localStorage.removeItem(k));
  location.reload();
}
async function setPasswordHandler() {
  const password = elements.passwordInput.value;
  if (!password) { setSetupStatus('Enter a password first.', true); return; }
  if (password.length < 10) { setSetupStatus('Password must be at least 10 characters.', true); return; }
  try {
    const salt = localStorage.getItem('cb_salt') || randomSaltB64();
    const kek = await derivePasswordKek(password, salt);
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
    const ok = window.confirm('Remove your master password?\n\nYour cashbook will then open without any lock on this device.');
    if (!ok) return;
  }
  localStorage.removeItem('cb_key_wrapped'); localStorage.removeItem('cb_has_password');
  if (!securityState().hasBiometrics && masterKeyRaw) localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
  setSetupStatus('Master password removed.'); announce('Master password removed.');
  updateSecurityUi();
}

function bindBookEvents() {
  elements.bookSelect?.addEventListener('change', (e) => void switchBook(e.target.value));
  elements.newBookBtn?.addEventListener('click', async () => {
    const name = window.prompt('Name the new book (e.g. Home, Business):');
    if (name === null) return;
    try { await createBook(name); await refreshView(); announce(`Created “${activeBook().name}”. Tap “Create a new Sheet” in Settings → Books to back it up.`); }
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
  elements.unlockForm.addEventListener('submit', async (e) => {
    e.preventDefault(); elements.unlockBtn.disabled = true; elements.lockError.textContent = '';
    try { await unlockWithPassword(elements.unlockPassword.value); }
    catch (err) { elements.lockError.textContent = err.message || 'Failed to unlock.'; elements.unlockPassword.value = ''; }
    finally { elements.unlockBtn.disabled = false; }
  });
  elements.biometricToggle?.addEventListener('change', async (e) => {
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
    const ok = window.confirm('Sign out of Google on this app?\n\nYour entries stay on this device and your Sheet stays connected.');
    if (!ok) return;
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
  elements.createNewSheet?.addEventListener('click', () => void createNewSpreadsheet());
  elements.connectGoogle.addEventListener('click', () => void oneTapSync());
  elements.syncNow.addEventListener('click', () => void oneTapSync());
  elements.startCreateSheet?.addEventListener('click', () => {
    if (elements.currencyCode && elements.onboardCurrency) elements.currencyCode.value = elements.onboardCurrency.value.trim().toUpperCase() || DEFAULT_CURRENCY;
    void createNewSpreadsheet();
  });
  elements.startChooseSheet?.addEventListener('click', () => {
    if (elements.currencyCode && elements.onboardCurrency) elements.currencyCode.value = elements.onboardCurrency.value.trim().toUpperCase() || DEFAULT_CURRENCY;
    void chooseGoogleSheet();
  });
  elements.archiveNow?.addEventListener('click', () => void archiveAndStartFresh());
  window.addEventListener('online', () => void autoSync());
  window.addEventListener('offline', () => void refreshView());
  document.addEventListener('visibilitychange', () => { if (!document.hidden && navigator.onLine) void autoSync(); });
  ['click', 'keydown', 'mousemove', 'touchstart'].forEach((evt) => document.addEventListener(evt, resetIdleTimer));
  bindBookEvents();
  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
    navigator.serviceWorker.register('./sw.js').catch(() => { elements.storageStatus.textContent = `Offline mode could not start · build ${APP_BUILD}`; });
  }
}

async function initialize() {
  ['cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach((k) => localStorage.removeItem(k));
  bindEvents();
  const salt = localStorage.getItem('cb_salt');
  const hasWrapped = localStorage.getItem('cb_key_wrapped');
  const hasRaw = localStorage.getItem('cb_key_raw');
  const hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const isLegacy = !!salt && !hasWrapped && !hasRaw && !hasPrf;
  if (isLegacy) { elements.lockMessage.textContent = 'Enter your master password to unlock your encrypted cashbook.'; showLockScreen('password'); return; }
  if (hasWrapped || hasPrf) {
    elements.lockMessage.textContent = hasWrapped ? 'Enter your master password to unlock your encrypted cashbook.' : 'Use Face ID / fingerprint to unlock your cashbook.';
    showLockScreen(hasWrapped && hasPrf ? 'both' : hasWrapped ? 'password' : 'biometrics'); return;
  }
  if (hasRaw) {
    try { await setMasterKeyFromBytes(b64ToBytes(hasRaw)); await openDatabase(); await startApp(); }
    catch (err) { console.error('Could not open the local cashbook', err); elements.storageStatus.textContent = 'Could not read local data.'; }
    return;
  }
  try {
    await generateMasterKey();
    localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
    await openDatabase();
    await saveSetting('__auth_check__', 'valid');
    await startApp();
  } catch (err) { console.error('Setup failed', err); elements.lockMessage.textContent = 'Could not initialize local storage.'; }
}

void initialize();