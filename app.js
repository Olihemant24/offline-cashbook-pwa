const DB_NAME = 'my-cashbook-v1';
const DB_VERSION = 1;
const STORE_TRANSACTIONS = 'transactions';
const STORE_SETTINGS = 'settings';
const DRIVE_FILE_SCOPE = 'https://www.googleapis.com/auth/drive.file';
const DEFAULT_CURRENCY = 'NPR';
const PERIODS_TAB = 'Cashbook Periods';

const DEFAULT_CLIENT_ID = '1017685550464-um4md5jhrbki0gbna4d7b0osmliuddqm.apps.googleusercontent.com';
const DEFAULT_API_KEY = 'AIzaSyAq99qSOcAgYuODAXNiqrZEpNS6OsyGMb8';
const DEFAULT_APP_ID = '1017685550464';
const APP_BUILD = 27;

let dbPromise;
let accessToken = null;
let tokenExpiresAt = 0;
let cryptoKey = null;
let masterKeyRaw = null;
let unreadableCount = 0;
let idleTimeout = null;

// ===== CRYPTO HELPERS =====
// All cashbook data is encrypted with a random 256-bit master key held in
// memory. That master key is "wrapped" (encrypted) with either a password-
// derived key, a device passkey (WebAuthn PRF), or left raw when the user
// opts out of a lock. The master password is never stored in plain text.
function bytesToB64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}
function b64ToBytes(base64) {
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}
function randomSaltB64() {
  return bytesToB64(crypto.getRandomValues(new Uint8Array(16)));
}
async function importAesKey(bytes) {
  return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
}
async function exportAesKey(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}
async function generateMasterKey() {
  cryptoKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  masterKeyRaw = await exportAesKey(cryptoKey);
  return cryptoKey;
}
async function setMasterKeyFromBytes(bytes) {
  cryptoKey = await importAesKey(bytes);
  masterKeyRaw = bytes;
  return cryptoKey;
}
async function derivePasswordKek(password, saltBase64) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), { name: 'PBKDF2' }, false, ['deriveBits', 'deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: b64ToBytes(saltBase64), iterations: 600000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptText(text, key = cryptoKey) {
  if (!key) throw new Error("App is locked.");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
  return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(ciphertext)) };
}

async function decryptText(encObj, key = cryptoKey) {
  if (!key) throw new Error("App is locked.");
  if (!encObj || !encObj.iv || !encObj.data) return null;
  try {
    const iv = b64ToBytes(encObj.iv);
    const data = b64ToBytes(encObj.data);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error("Decryption failed", e);
    return null;
  }
}

async function wrapMasterKeyWith(kek) {
  if (!masterKeyRaw) throw new Error('Unlock the cashbook first.');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, masterKeyRaw);
  return { iv: bytesToB64(iv), data: bytesToB64(new Uint8Array(cipher)) };
}

async function unwrapMasterKey(wrapped, kek) {
  const iv = b64ToBytes(wrapped.iv);
  const data = b64ToBytes(wrapped.data);
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, kek, data);
  await setMasterKeyFromBytes(new Uint8Array(raw));
  return cryptoKey;
}

// ===== WEBAUTHN PRF (SECURE FACE ID / FINGERPRINT) =====
// The passkey's PRF extension derives a secret from the device's biometric /
// PIN credential. That secret wraps the master key, so the master password is
// never stored anywhere on the device.
async function createPrfCredential(saltBytes) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: 'My Cashbook' },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'cashbook-user', displayName: 'Cashbook User' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
      extensions: { prf: { eval: { first: saltBytes } } }
    }
  });
  const output = credential.getClientExtensionResults?.()?.prf?.results?.first;
  if (!output) throw new Error('This device or browser does not support secure Face ID / fingerprint unlock.');
  return { credId: new Uint8Array(credential.rawId), prfBytes: new Uint8Array(output) };
}

async function getPrfBytes(credIdBytes, saltBytes) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{ id: credIdBytes, type: 'public-key' }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: saltBytes } } }
    }
  });
  const output = assertion.getClientExtensionResults?.()?.prf?.results?.first;
  if (!output) throw new Error('Biometric key is not available on this device.');
  return new Uint8Array(output);
}

async function enableBiometrics() {
  if (!window.PublicKeyCredential) throw new Error('Face ID / fingerprint is not supported on this device.');
  const saltBytes = crypto.getRandomValues(new Uint8Array(32));
  let cred;
  try {
    cred = await createPrfCredential(saltBytes);
  } catch (err) {
    throw new Error(err?.message || 'Could not enable Face ID / fingerprint.');
  }
  const kek = await importAesKey(cred.prfBytes);
  const wrapped = await wrapMasterKeyWith(kek);
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
    const kek = await importAesKey(prfBytes);
    await unwrapMasterKey(JSON.parse(wrappedJson), kek);
    await openDatabase();
    const check = await getSetting('__auth_check__', null);
    if (check !== 'valid') {
      cryptoKey = null;
      masterKeyRaw = null;
      return false;
    }
    return true;
  } catch (err) {
    console.error('Biometric unlock failed', err);
    return false;
  }
}

function disableBiometrics() {
  localStorage.removeItem('cb_prf_cred_id');
  localStorage.removeItem('cb_prf_salt');
  localStorage.removeItem('cb_prf_key_wrapped');
  if (!localStorage.getItem('cb_key_wrapped') && masterKeyRaw) {
    localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
  }
}

// ===== SECURITY STATE =====
function securityState() {
  return {
    hasPassword: Boolean(localStorage.getItem('cb_key_wrapped')),
    hasBiometrics: Boolean(localStorage.getItem('cb_prf_key_wrapped')),
    hasRaw: Boolean(localStorage.getItem('cb_key_raw'))
  };
}
function isProtected() {
  const state = securityState();
  return state.hasPassword || state.hasBiometrics;
}
function updateSecurityUi() {
  if (!elements.securityStatus) return;
  const state = securityState();
  const parts = [];
  parts.push(state.hasPassword ? 'Master password: ON' : 'Master password: OFF');
  parts.push(state.hasBiometrics ? 'Face ID / fingerprint: ON' : 'Face ID / fingerprint: OFF');
  if (!isProtected()) parts.push('This device opens without a lock.');
  elements.securityStatus.textContent = parts.join('  ·  ');
  if (elements.biometricToggle) elements.biometricToggle.checked = state.hasBiometrics;
  if (elements.lockNowBtn) elements.lockNowBtn.style.display = isProtected() ? '' : 'none';
}

// ===== TOKEN MANAGEMENT =====
function saveToken(token, expiresIn) {
  accessToken = token;
  tokenExpiresAt = Date.now() + ((Number(expiresIn) || 3600) * 1000);
  try {
    sessionStorage.setItem('cb_token', accessToken);
    sessionStorage.setItem('cb_token_expires', String(tokenExpiresAt));
  } catch {}
}

function loadSavedToken() {
  try {
    const token = sessionStorage.getItem('cb_token');
    const expires = Number(sessionStorage.getItem('cb_token_expires') || '0');
    if (token && expires > Date.now() + 60000) {
      accessToken = token;
      tokenExpiresAt = expires;
      return true;
    }
  } catch {}
  return false;
}

function clearSavedToken() {
  accessToken = null;
  tokenExpiresAt = 0;
  try {
    sessionStorage.removeItem('cb_token');
    sessionStorage.removeItem('cb_token_expires');
  } catch {}
  try {
    localStorage.removeItem('cb_token');
    localStorage.removeItem('cb_token_expires');
  } catch {}
}

let cachedConfig = null;
let lastSyncFinishedAt = 0;

function tokenIsValid() {
  return Boolean(accessToken) && tokenExpiresAt > Date.now() + 60000;
}

function effectiveConfig() {
  const saved = cachedConfig || {};
  return {
    ...saved,
    clientId: saved.clientId || DEFAULT_CLIENT_ID,
    apiKey: saved.apiKey || DEFAULT_API_KEY,
    appId: saved.appId || DEFAULT_APP_ID,
    currencyCode: saved.currencyCode || DEFAULT_CURRENCY,
    responseTab: saved.responseTab || 'Form responses 1',
    dashboardTab: saved.dashboardTab || 'Dashboard'
  };
}

async function ensureSignedIn() {
  if (tokenIsValid()) return;
  await requestGoogleToken(effectiveConfig());
}

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
  onboardingCard: $('onboardingCard'), onboardCurrency: $('onboardCurrency'), startCreateSheet: $('startCreateSheet'), startChooseSheet: $('startChooseSheet'), onboardingStatus: $('onboardingStatus'), openSheetLink: $('openSheetLink'),
  carryBalance: $('carryBalance'), archiveName: $('archiveName'), archiveNow: $('archiveNow'), archiveStatus: $('archiveStatus'),
  biometricToggle: $('biometricToggle'), lockNowBtn: $('lockNowBtn'), securityStatus: $('securityStatus'), passwordInput: $('passwordInput'), setPasswordBtn: $('setPasswordBtn'), removePasswordBtn: $('removePasswordBtn'), signOutGoogle: $('signOutGoogle'), resetGoogleCreds: $('resetGoogleCreds')
};

// ===== DATABASE & ENCRYPTION =====
function openDatabase() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(STORE_TRANSACTIONS)) db.createObjectStore(STORE_TRANSACTIONS, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(STORE_SETTINGS)) db.createObjectStore(STORE_SETTINGS, { keyPath: 'key' });
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('Could not open local storage.'));
  });
  return dbPromise;
}

function transactionDone(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = tx.onerror = () => reject(tx.error || new Error('Could not save local data.'));
  });
}

async function getAllTransactions() {
  const db = await openDatabase();
  const tx = db.transaction(STORE_TRANSACTIONS, 'readonly');
  const done = transactionDone(tx);
  const result = await new Promise((resolve, reject) => {
    const request = tx.objectStore(STORE_TRANSACTIONS).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
  await done;

  unreadableCount = 0;
  const decryptedRecords = [];
  for (const record of result) {
    if (record.encrypted) {
      const plaintext = await decryptText(record.encrypted);
      if (plaintext) {
        try {
          const parsed = JSON.parse(plaintext);
          decryptedRecords.push({ id: record.id, ...parsed });
        } catch (e) {
          unreadableCount++;
          console.error("Failed to parse decrypted record", record.id);
        }
      } else {
        unreadableCount++;
      }
    } else {
      decryptedRecords.push(record);
      await putTransaction(record); 
    }
  }
  return decryptedRecords;
}

async function getActiveRecords() {
  const all = await getAllTransactions();
  const start = Date.parse(await getSetting('periodStartIso', '') || '');
  if (Number.isNaN(start)) return all;
  return all.filter((record) => {
    if (record.syncState === 'pending') return true;
    const time = Date.parse(record.createdAt || record.sheetTimestamp || '');
    return !Number.isNaN(time) && time >= start;
  });
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
  const result = await new Promise((resolve, reject) => {
    const request = tx.objectStore(STORE_SETTINGS).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  await done;
  
  if (!result) return fallback;
  if (result.encrypted) {
    const plaintext = await decryptText(result.encrypted);
    return plaintext ? JSON.parse(plaintext) : fallback;
  }
  return result.value !== undefined ? result.value : fallback;
}

async function saveSetting(key, value) {
  const encrypted = await encryptText(JSON.stringify(value));

  const db = await openDatabase();
  const tx = db.transaction(STORE_SETTINGS, 'readwrite');
  const done = transactionDone(tx);
  
  tx.objectStore(STORE_SETTINGS).put({ key, encrypted });
  await done;
  if (key === 'googleConfig') cachedConfig = value;
}

// ===== UI HELPERS =====
function currencyFractionDigits(currencyCode = activeCurrencyCode) {
  return new Intl.NumberFormat(undefined, { style: 'currency', currency: currencyCode }).resolvedOptions().maximumFractionDigits;
}
function currencyScale(currencyCode = activeCurrencyCode) {
  return 10 ** currencyFractionDigits(currencyCode);
}
function configureCurrency(currencyCode) {
  const normalized = String(currencyCode || DEFAULT_CURRENCY).trim().toUpperCase();
  const fractionDigits = currencyFractionDigits(normalized);
  activeCurrencyCode = normalized;
  const amountStep = 1 / (10 ** fractionDigits);
  elements.moneyIn.step = String(amountStep);
  elements.moneyOut.step = String(amountStep);
  const amountPlaceholder = fractionDigits ? `0.${'0'.repeat(fractionDigits)}` : '0';
  elements.moneyIn.placeholder = amountPlaceholder;
  elements.moneyOut.placeholder = amountPlaceholder;
  currencyFormatters.set(normalized, new Intl.NumberFormat(undefined, {
    style: 'currency', currency: normalized, minimumFractionDigits: fractionDigits, maximumFractionDigits: fractionDigits
  }));
  $('currencyLabelIn').textContent = `(${normalized})`;
  $('currencyLabelOut').textContent = `(${normalized})`;
  return normalized;
}
function moneyToMinorUnits(value, currencyCode = activeCurrencyCode) {
  const number = Number(value);
  if (!Number.isFinite(number) || number < 0) return 0;
  return Math.round(number * currencyScale(currencyCode));
}
function parseMoney(value, currencyCode = activeCurrencyCode) {
  if (typeof value === 'number') return Number.isFinite(value) ? Math.round(value * currencyScale(currencyCode)) : 0;
  const normalized = String(value ?? '').replace(/,/g, '').replace(/[^\d.-]/g, '');
  const number = Number(normalized);
  return Number.isFinite(number) ? Math.round(number * currencyScale(currencyCode)) : 0;
}
function formatMoney(minorUnits, currencyCode = activeCurrencyCode) {
  let formatter = currencyFormatters.get(currencyCode);
  if (!formatter) {
    const fractionDigits = currencyFractionDigits(currencyCode);
    formatter = new Intl.NumberFormat(undefined, { style: 'currency', currency: currencyCode, minimumFractionDigits: fractionDigits, maximumFractionDigits: fractionDigits });
    currencyFormatters.set(currencyCode, formatter);
  }
  return formatter.format((Number(minorUnits) || 0) / currencyScale(currencyCode));
}
function localTimeLabel(record) {
  if (record.createdAt) {
    const date = new Date(record.createdAt);
    if (!Number.isNaN(date.getTime())) {
      return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(date);
    }
  }
  return record.sheetTimestamp || 'Date saved in Google Sheets';
}
function announce(message) {
  elements.toast.textContent = message;
  elements.toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => elements.toast.classList.remove('show'), 3000);
}
function setFeedback(message, isError = false) {
  elements.formFeedback.textContent = message;
  elements.formFeedback.classList.toggle('error', isError);
}
function setSetupStatus(message, isError = false) {
  elements.setupStatus.textContent = message;
  elements.setupStatus.classList.toggle('error', isError);
  if (elements.onboardingStatus) {
    elements.onboardingStatus.textContent = message;
    elements.onboardingStatus.classList.toggle('error', isError);
  }
}
function updateOnboarding() {
  const connected = Boolean(cachedConfig?.spreadsheetId);
  if (elements.onboardingCard) elements.onboardingCard.hidden = connected;
  if (elements.archivePanel) elements.archivePanel.hidden = !connected;
  if (elements.openSheetLink) {
    elements.openSheetLink.hidden = !connected;
    if (connected) elements.openSheetLink.href = `https://docs.google.com/spreadsheets/d/${encodeURIComponent(cachedConfig.spreadsheetId)}/edit`;
  }
}
function setArchiveStatus(message, isError = false) {
  if (!elements.archiveStatus) return;
  elements.archiveStatus.textContent = message;
  elements.archiveStatus.classList.toggle('error', isError);
}
function setSyncStatus(title, message, mode = 'ready') {
  elements.syncTitle.textContent = title;
  elements.syncMessage.textContent = message;
  elements.onlineDot.classList.toggle('offline', !navigator.onLine || mode === 'offline');
  elements.syncNow.hidden = mode !== 'pending' && mode !== 'error';
}
function newId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return `tx-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

async function createTransaction(event) {
  event.preventDefault();
  const submitBtn = elements.transactionForm.querySelector('button[type="submit"]');
  if (submitBtn?.disabled) return;
  const incomeMinor = moneyToMinorUnits(elements.moneyIn.value, activeCurrencyCode);
  const expenseMinor = moneyToMinorUnits(elements.moneyOut.value, activeCurrencyCode);
  const remarks = elements.remarks.value.trim();
  if (incomeMinor <= 0 && expenseMinor <= 0) {
    setFeedback('Enter an amount for money in or money out.', true);
    return;
  }

  const record = {
    id: newId(),
    createdAt: new Date().toISOString(),
    currencyCode: activeCurrencyCode,
    moneyInMinor: incomeMinor,
    moneyOutMinor: expenseMinor,
    remarks,
    syncState: 'pending',
    source: 'local'
  };

  if (submitBtn) submitBtn.disabled = true;
  try {
    await putTransaction(record);
    elements.transactionForm.reset();
    setFeedback(`Saved on this device at ${localTimeLabel(record)}.`);
    await refreshView();
    if (navigator.onLine && accessToken && tokenExpiresAt > Date.now() + 15000) {
      void syncToSheet();
    } else if (navigator.onLine) {
      setSyncStatus('Saved on this device', 'Connect Google to upload this entry to your Sheet.', 'pending');
    } else {
      setSyncStatus('Saved offline', 'This entry is queued on this device for when you are online.', 'offline');
    }
  } catch (error) {
    setFeedback(error.message || 'Could not save this entry on the device.', true);
  } finally {
    if (submitBtn) submitBtn.disabled = false;
  }
}

function sortedRecords(records) {
  return records.slice().sort((a, b) => {
    const aTime = a.createdAt && !Number.isNaN(Date.parse(a.createdAt)) ? Date.parse(a.createdAt) : Date.parse(a.sheetTimestamp || '') || 0;
    const bTime = b.createdAt && !Number.isNaN(Date.parse(b.createdAt)) ? Date.parse(b.createdAt) : Date.parse(b.sheetTimestamp || '') || 0;
    return bTime - aTime;
  });
}

function renderTransactions(records) {
  const sorted = sortedRecords(records);
  const visible = sorted.slice(0, 40);
  elements.recordCount.textContent = `${records.length} ${records.length === 1 ? 'record' : 'records'}`;
  elements.transactionList.replaceChildren();

  if (!visible.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = '<span class="empty-icon" aria-hidden="true">＋</span><strong>No transactions yet</strong><span>Your saved entries will appear here.</span>';
    elements.transactionList.append(empty);
    return;
  }

  for (const record of visible) {
    const inMinor = Number(record.moneyInMinor) || 0;
    const outMinor = Number(record.moneyOutMinor) || 0;
    const kind = inMinor && outMinor ? 'mixed' : inMinor ? 'income' : 'expense';
    const row = document.createElement('article');
    row.className = 'transaction-row';

    const main = document.createElement('div');
    main.className = 'transaction-main';
    const icon = document.createElement('span');
    icon.className = `transaction-icon ${kind}`;
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = kind === 'income' ? '↙' : kind === 'expense' ? '↗' : '↔';
    const text = document.createElement('div');
    text.className = 'transaction-text';
    const remark = document.createElement('span');
    remark.className = 'transaction-remark';
    remark.textContent = record.remarks || (kind === 'income' ? 'Money came in' : kind === 'expense' ? 'Money went out' : 'Money in and out');
    const time = document.createElement('span');
    time.className = 'transaction-time';
    time.textContent = localTimeLabel(record);
    text.append(remark, time);
    main.append(icon, text);

    const amounts = document.createElement('div');
    amounts.className = 'transaction-amounts';
    if (inMinor) {
      const amount = document.createElement('span');
      amount.className = 'in';
      amount.textContent = `+ ${formatMoney(inMinor, record.currencyCode || activeCurrencyCode)}`;
      amounts.append(amount);
    }
    if (outMinor) {
      const amount = document.createElement('span');
      amount.className = 'out';
      amount.textContent = `− ${formatMoney(outMinor, record.currencyCode || activeCurrencyCode)}`;
      amounts.append(amount);
    }
    const sync = document.createElement('small');
    sync.className = `transaction-sync ${record.syncState === 'pending' ? 'pending' : ''}`;
    sync.textContent = record.syncState === 'pending' ? 'Waiting to sync' : 'On this device and Sheet';
    amounts.append(sync);
    row.append(main, amounts);
    elements.transactionList.append(row);
  }
}

async function refreshView() {
  const records = await getActiveRecords();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const income = records.reduce((sum, item) => sum + (Number(item.moneyInMinor) || 0), 0);
  const expense = records.reduce((sum, item) => sum + (Number(item.moneyOutMinor) || 0), 0);
  const startingBalance = Number(await getSetting('startingBalanceMinor', 0)) || 0;
  elements.incomeTotal.textContent = formatMoney(income);
  elements.expenseTotal.textContent = formatMoney(expense);
  elements.balanceTotal.textContent = formatMoney(startingBalance + income - expense);
  elements.balanceNote.textContent = startingBalance ? `Includes your ${formatMoney(startingBalance)} starting balance` : 'Starting balance plus money in minus money out';
  renderTransactions(records);
  if (elements.historyFootnote) {
    elements.historyFootnote.textContent = unreadableCount
      ? `${unreadableCount} saved ${unreadableCount === 1 ? 'entry' : 'entries'} could not be read on this device.`
      : 'This device keeps your recent records available offline.';
  }
  const pending = records.filter((item) => item.syncState === 'pending').length;
  const hasSheet = Boolean(cachedConfig?.spreadsheetId);
  updateOnboarding();
  if (!navigator.onLine) {
    setSyncStatus(pending ? 'Saved offline' : 'Offline-ready', pending ? `${pending} ${pending === 1 ? 'entry is' : 'entries are'} waiting on this device.` : 'Your saved cashbook is available on this device.', 'offline');
  } else if (pending) {
    setSyncStatus('Waiting to sync', `${pending} ${pending === 1 ? 'entry is' : 'entries are'} saved here. ${hasSheet ? 'Tap “Sync now” to send them to your Sheet.' : 'Connect a Google Sheet to back them up.'}`, 'pending');
  } else if (!hasSheet) {
    setSyncStatus('Offline-ready', 'Your entries save on this device. Connect a Google Sheet to back them up.', 'ready');
  } else if (!tokenIsValid()) {
    setSyncStatus('Google Sheet connected', 'Everything is saved. Tap “Sync now” any time to refresh your Sheet.', 'pending');
  } else {
    setSyncStatus('Google Sheet connected', 'New entries sync automatically while this app is open and online.', 'ready');
  }
}

// ===== GOOGLE & SHEET LOGIC =====
function spreadsheetIdFrom(value) {
  const raw = String(value || '').trim();
  const match = raw.match(/\/spreadsheets\/d\/([a-zA-Z0-9-_]+)/);
  return match ? match[1] : raw;
}
async function loadConfigFromForm() {
  const saved = await getSetting('googleConfig', {});
  return {
    currencyCode: elements.currencyCode?.value?.trim().toUpperCase() || saved.currencyCode || DEFAULT_CURRENCY,
    clientId: elements.clientId?.value?.trim() || saved.clientId || DEFAULT_CLIENT_ID,
    apiKey: elements.apiKey?.value?.trim() || saved.apiKey || DEFAULT_API_KEY,
    appId: elements.appId?.value?.trim() || saved.appId || DEFAULT_APP_ID,
    spreadsheetId: spreadsheetIdFrom(elements.spreadsheetInput?.dataset?.spreadsheetId || saved.spreadsheetId || ''),
    spreadsheetName: elements.spreadsheetInput?.dataset?.spreadsheetName || saved.spreadsheetName || '',
    responseTab: elements.responseTab?.value?.trim() || saved.responseTab || 'Form responses 1',
    dashboardTab: elements.dashboardTab?.value?.trim() || saved.dashboardTab || 'Dashboard'
  };
}
async function loadSavedConfig() {
  const config = await getSetting('googleConfig', {});
  const currencyCode = configureCurrency(config.currencyCode || await getSetting('currencyCode', DEFAULT_CURRENCY));
  if (elements.currencyCode) elements.currencyCode.value = currencyCode;
  if (elements.clientId) elements.clientId.value = config.clientId || DEFAULT_CLIENT_ID;
  if (elements.apiKey) elements.apiKey.value = config.apiKey || DEFAULT_API_KEY;
  if (elements.appId) elements.appId.value = config.appId || DEFAULT_APP_ID;
  const sheetId = config.spreadsheetId || '';
  const sheetName = config.spreadsheetName || '';
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
  const config = await loadConfigFromForm();
  try {
    await persistCurrencyCode(config.currencyCode);
    await saveSetting('googleConfig', config);
    setSetupStatus('Settings saved on this device. No Google access has been requested.');
    announce('Sync settings saved on this device.');
    await refreshView();
  } catch (error) {
    setSetupStatus(error.message || 'Could not save settings.', true);
  }
}
async function persistCurrencyCode(currencyCode) {
  let normalized;
  try {
    normalized = configureCurrency(currencyCode);
  } catch {
    throw new Error('Enter a three-letter ISO 4217 currency code supported by this browser, such as NPR, USD, EUR, or INR.');
  }
  const current = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  const records = await getAllTransactions();
  if (records.length && normalized !== current) {
    configureCurrency(current);
    elements.currencyCode.value = current;
    throw new Error(`This cashbook already has records in ${current}. Use a new Sheet to start in ${normalized}.`);
  }
  await saveSetting('currencyCode', normalized);
  return normalized;
}
function loadGoogleIdentity() {
  if (window.google?.accounts?.oauth2) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const existing = document.querySelector('script[data-google-identity]');
    if (existing) {
      existing.addEventListener('load', resolve, { once: true });
      existing.addEventListener('error', () => reject(new Error('Could not load Google sign-in. Check your internet connection.')), { once: true });
      return;
    }
    const script = document.createElement('script');
    script.src = 'https://accounts.google.com/gsi/client';
    script.async = true;
    script.defer = true;
    script.dataset.googleIdentity = 'true';
    script.onload = resolve;
    script.onerror = () => reject(new Error('Could not load Google sign-in. Check your internet connection.'));
    document.head.append(script);
  });
}
async function connectGoogle() {
  const config = await loadConfigFromForm();
  if (!config.clientId || !config.apiKey || !config.appId) {
    setSetupStatus('Google credentials missing. Please check settings.', true);
    elements.settingsPanel.open = true;
    return;
  }
  if (!config.spreadsheetId) {
    setSetupStatus('Choose your Google Sheet first, or tap “Create New Sheet”.', true);
    elements.settingsPanel.open = true;
    return;
  }
  if (!navigator.onLine) {
    setSetupStatus('Connect Google while online. Your offline entries are safe on this device.', true);
    return;
  }
  try {
    await persistCurrencyCode(config.currencyCode);
  } catch (error) {
    setSetupStatus(error.message || 'Check the currency code.', true);
    return;
  }
  await saveSetting('googleConfig', config);
  elements.connectGoogle.disabled = true;
  setSetupStatus('Requesting access to your Google Sheet…');
  try {
    accessToken = await requestGoogleToken(config);
    await syncToSheet();
  } catch (error) {
    clearSavedToken();
    setSetupStatus(error.message || 'Could not connect to Google Sheets.', true);
  } finally {
    elements.connectGoogle.disabled = false;
    await refreshView();
  }
}
function requestGoogleToken(config, promptMode = '') {
  return loadGoogleIdentity().then(() => new Promise((resolve, reject) => {
    const client = window.google.accounts.oauth2.initTokenClient({
      client_id: config.clientId,
      scope: DRIVE_FILE_SCOPE,
      callback: (response) => {
        if (response.error || !response.access_token) {
          reject(new Error(response.error_description || response.error || 'Google access was not granted.'));
          return;
        }
        saveToken(response.access_token, response.expires_in);
        resolve(response.access_token);
      },
      error_callback: (error) => reject(new Error(error.message || 'Google permission was closed.'))
    });
    client.requestAccessToken({ prompt: promptMode });
  }));
}
function loadGooglePicker() {
  return new Promise((resolve, reject) => {
    const finish = () => {
      if (!window.gapi?.load) {
        reject(new Error('Google Picker could not start.'));
        return;
      }
      window.gapi.load('picker', { callback: resolve });
    };
    if (window.gapi?.load) return finish();
    const existing = document.querySelector('script[data-google-picker]');
    if (existing) {
      existing.addEventListener('load', finish, { once: true });
      existing.addEventListener('error', () => reject(new Error('Could not load Google Picker.')), { once: true });
      return;
    }
    const script = document.createElement('script');
    script.src = 'https://apis.google.com/js/api.js';
    script.async = true;
    script.defer = true;
    script.dataset.googlePicker = 'true';
    script.onload = finish;
    script.onerror = () => reject(new Error('Could not load Google Picker. Check your internet connection.'));
    document.head.append(script);
  });
}
function showGoogleSheetPicker(config, token) {
  return loadGooglePicker().then(() => new Promise((resolve, reject) => {
    try {
      const view = new window.google.picker.DocsView(window.google.picker.ViewId.SPREADSHEETS);
      view.setIncludeFolders(true);
      view.setSelectFolderEnabled(false);
      const picker = new window.google.picker.PickerBuilder()
        .setAppId(config.appId)
        .setDeveloperKey(config.apiKey)
        .setOAuthToken(token)
        .setOrigin(window.location.origin)
        .setTitle('Choose a Sheet, or create a new one in My Cashbook')
        .addView(view)
        .setCallback((data) => {
          if (data.action === window.google.picker.Action.PICKED) resolve(data.docs?.[0] || null);
          if (data.action === window.google.picker.Action.CANCEL) resolve(null);
        })
        .build();
      picker.setVisible(true);
    } catch (error) {
      reject(error);
    }
  }));
}
async function chooseGoogleSheet() {
  if (!navigator.onLine) {
    setSetupStatus('Choose a Google Sheet while online. Offline entries will remain saved here.', true);
    return;
  }
  try {
    await ensureSignedIn();
  } catch (error) {
    setSetupStatus(error.message || 'Google sign-in was not completed.', true);
    return;
  }
  const config = await loadConfigFromForm();
  if (!config.clientId || !config.apiKey || !config.appId) {
    setSetupStatus('Google credentials missing. Please check settings.', true);
    elements.settingsPanel.open = true;
    return;
  }
  if (!navigator.onLine) {
    setSetupStatus('Choose a Google Sheet while online. Offline entries will remain saved here.', true);
    return;
  }
  try {
    await persistCurrencyCode(config.currencyCode);
  } catch (error) {
    setSetupStatus(error.message || 'Check the currency code.', true);
    return;
  }
  elements.chooseGoogleSheet.disabled = true;
  setSetupStatus('Opening Google Sheets picker…');
  try {
    await saveSetting('googleConfig', config);
    const selected = await showGoogleSheetPicker(config, accessToken);
    if (!selected) {
      setSetupStatus('No Sheet selected. If the picker looked empty, tap “Create New Sheet” to make a fresh cashbook Sheet.');
      return;
    }
    config.spreadsheetId = selected.id;
    config.spreadsheetName = selected.name || 'Selected Sheet';
    elements.spreadsheetInput.dataset.spreadsheetId = config.spreadsheetId;
    elements.spreadsheetInput.dataset.spreadsheetName = config.spreadsheetName;
    elements.spreadsheetInput.value = `${config.spreadsheetName} · ${config.spreadsheetId}`;
    await saveSetting('googleConfig', config);
    setSetupStatus(`Selected “${config.spreadsheetName}”. Syncing…`);
    await syncToSheet();
  } catch (error) {
    clearSavedToken();
    setSetupStatus(error.message || 'Could not select the Google Sheet.', true);
  } finally {
    elements.chooseGoogleSheet.disabled = false;
  }
}

function buildDashboardValues(config) {
  const tab = quoteSheetName(config.responseTab);
  const thisMonth = (column) => `=SUMIFS(${tab}!${column}:${column},${tab}!A:A,">="&EOMONTH(TODAY(),-1)+1,${tab}!A:A,"<"&EOMONTH(TODAY(),0)+1)`;
  return [
    ['MY MONEY DASHBOARD', ''],
    ['', ''],
    ['Total Money Came In', `=SUMIFS(${tab}!B:B,${tab}!A:A,">0")`],
    ['Total Money Went Out', `=SUMIFS(${tab}!C:C,${tab}!A:A,">0")`],
    ['Net money movement', '=B3-B4'],
    ['', ''],
    ['MONTHLY SUMMARY', ''],
    ['Money Came In This Month', thisMonth('B')],
    ['Money Went Out This Month', thisMonth('C')],
    ['Net Movement This Month', '=B8-B9'],
    ['', ''],
    ['Starting balance (set it in B13)', ''],
    ['', 0]
  ];
}
async function styleNewSheet(config, created) {
  const ids = new Map((created.sheets || []).map((sheet) => [sheet.properties.title, sheet.properties.sheetId]));
  const responseId = ids.get(config.responseTab);
  const dashboardId = ids.get(config.dashboardTab);
  if (responseId === undefined || dashboardId === undefined) return;
  const symbol = config.currencyCode === 'NPR' ? 'Rs' : config.currencyCode;
  const money = { type: 'NUMBER', pattern: `"${symbol} "#,##0.00` };
  const green = { red: 0.122, green: 0.42, blue: 0.314 };
  const white = { red: 1, green: 1, blue: 1 };
  const cells = (sheetId, r0, r1, c0, c1, userEnteredFormat, fields) => ({
    repeatCell: { range: { sheetId, startRowIndex: r0, endRowIndex: r1, startColumnIndex: c0, endColumnIndex: c1 }, cell: { userEnteredFormat }, fields }
  });
  const width = (sheetId, start, end, pixelSize) => ({
    updateDimensionProperties: { range: { sheetId, dimension: 'COLUMNS', startIndex: start, endIndex: end }, properties: { pixelSize }, fields: 'pixelSize' }
  });
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
function defaultSheetTitle(date = new Date()) {
  const pad = (number) => String(number).padStart(2, '0');
  return `My Cashbook ${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}${pad(date.getMinutes())}`;
}
async function createNewSpreadsheet() {
  if (!navigator.onLine) {
    setSetupStatus('You are offline. Creating a Sheet needs the internet. Your saved entries stay on this device.', true);
    return;
  }
  try {
    await ensureSignedIn();
  } catch (error) {
    setSetupStatus(error.message || 'Google sign-in was not completed.', true);
    return;
  }
  const config = await loadConfigFromForm();
  if (!config.clientId || !config.apiKey || !config.appId) {
    setSetupStatus('Google credentials missing. Please check settings.', true);
    elements.settingsPanel.open = true;
    return;
  }
  if (!navigator.onLine) {
    setSetupStatus('You are offline. Creating a Sheet needs the internet. Your saved entries stay on this device.', true);
    return;
  }
  try {
    await persistCurrencyCode(config.currencyCode);
  } catch (error) {
    setSetupStatus(error.message || 'Check the currency code.', true);
    return;
  }

  const existing = await getAllTransactions();
  if (existing.length) {
    const proceed = window.confirm(
      'Create a brand new Google Sheet?\n\n' +
      '• A new spreadsheet is created in your Google Drive.\n' +
      '• The Sheet is set up with the right headers and a Dashboard tab.\n' +
      '• Entries already saved on this device stay here; only entries that have not synced yet are uploaded to the new Sheet.\n\n' +
      'Continue?'
    );
    if (!proceed) {
      setSetupStatus('Cancelled. Nothing was created.');
      return;
    }
  }

  elements.createNewSheet.disabled = true;
  elements.chooseGoogleSheet.disabled = true;
  setSetupStatus('Checking Google access…');
  try {
    await saveSetting('googleConfig', config);

    const title = defaultSheetTitle();
    setSetupStatus('Creating a new spreadsheet in your Drive…');
    const createResponse = await fetch('https://sheets.googleapis.com/v4/spreadsheets', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        properties: { title },
        sheets: [
          { properties: { title: config.responseTab } },
          { properties: { title: config.dashboardTab } }
        ]
      })
    });
    const created = await createResponse.json().catch(() => ({}));
    if (!createResponse.ok) {
      if (createResponse.status === 401) clearSavedToken();
      throw new Error(created.error?.message || `Google returned ${createResponse.status}.`);
    }
    const spreadsheetId = created.spreadsheetId;
    if (!spreadsheetId) throw new Error('Google did not return the new spreadsheet ID.');

    config.spreadsheetId = spreadsheetId;
    config.spreadsheetName = created.properties?.title || title;
    elements.spreadsheetInput.dataset.spreadsheetId = config.spreadsheetId;
    elements.spreadsheetInput.dataset.spreadsheetName = config.spreadsheetName;
    elements.spreadsheetInput.value = `${config.spreadsheetName} · ${config.spreadsheetId}`;
    await saveSetting('googleConfig', config);

    setSetupStatus('Writing the response headers and dashboard…');
    const headers = [
      'Timestamp',
      `Money Came In (${config.currencyCode})`,
      `Money Went Out (${config.currencyCode})`,
      'Remarks'
    ];
    await sheetsRequest(sheetValuesUrl(spreadsheetId, `${quoteSheetName(config.responseTab)}!A1:D1`, 'valueInputOption=RAW'), {
      method: 'PUT',
      body: JSON.stringify({ majorDimension: 'ROWS', values: [headers] })
    });
    await sheetsRequest(sheetValuesUrl(spreadsheetId, `${quoteSheetName(config.dashboardTab)}!A1:B13`, 'valueInputOption=USER_ENTERED'), {
      method: 'PUT',
      body: JSON.stringify({ majorDimension: 'ROWS', values: buildDashboardValues(config) })
    });
    try { await styleNewSheet(config, created); } catch { /* cosmetic only */ }

    setSetupStatus(`Created “${config.spreadsheetName}”. Syncing your saved entries…`);
    await syncToSheet();
    announce('New Google Sheet created and connected.');
    setSetupStatus(`Created “${config.spreadsheetName}”. It is now your cashbook Sheet.`);
  } catch (error) {
    setSetupStatus(error.message || 'Could not create the Google Sheet.', true);
  } finally {
    elements.createNewSheet.disabled = false;
    elements.chooseGoogleSheet.disabled = false;
    await refreshView();
  }
}

function quoteSheetName(name) {
  return `'${String(name).replace(/'/g, "''")}'`;
}
function formatSheetTimestamp(timestamp, timeZone) {
  const date = new Date(timestamp);
  if (Number.isNaN(date.getTime())) throw new Error('This entry has an invalid saved date and time.');
  const parts = {};
  for (const part of new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  }).formatToParts(date)) {
    if (part.type !== 'literal') parts[part.type] = part.value;
  }
  return `${parts.year}-${parts.month}-${parts.day} ${parts.hour}:${parts.minute}:${parts.second}`;
}
function sheetSerialToIso(serial, timeZone) {
  const wallMs = Math.round(((Number(serial) - 25569) * 86400000) / 1000) * 1000;
  if (!Number.isFinite(wallMs)) return null;
  if (!timeZone) return new Date(wallMs + new Date(wallMs).getTimezoneOffset() * 60000).toISOString();
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  });
  const offsetAt = (utcMs) => {
    const parts = {};
    for (const part of formatter.formatToParts(new Date(utcMs))) {
      if (part.type !== 'literal') parts[part.type] = Number(part.value);
    }
    return Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second) - Math.floor(utcMs / 1000) * 1000;
  };
  let utcMs = wallMs - offsetAt(wallMs);
  utcMs = wallMs - offsetAt(utcMs);
  return new Date(utcMs).toISOString();
}
function columnName(number) {
  let value = number;
  let result = '';
  while (value > 0) {
    const remainder = (value - 1) % 26;
    result = String.fromCharCode(65 + remainder) + result;
    value = Math.floor((value - 1) / 26);
  }
  return result;
}
function safeSheetText(value) {
  const text = String(value ?? '');
  if (!text) return '';
  return /^[=+\-@\t\r\n]/.test(text) ? `'${text}` : text;
}
async function sheetsRequest(url, options = {}) {
  if (!accessToken || tokenExpiresAt <= Date.now() + 5000) {
    throw new Error('Google access expired. Tap “Sync now” to sign in again.');
  }
  const response = await fetch(url, {
    ...options,
    headers: {
      Authorization: `Bearer ${accessToken}`,
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {})
    }
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401) clearSavedToken();
    throw new Error(body.error?.message || `Google Sheets returned ${response.status}.`);
  }
  return body;
}
async function readSpreadsheetTimeZone(config) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}?fields=properties.timeZone`;
  const data = await sheetsRequest(url);
  return data.properties?.timeZone || undefined;
}
function sheetValuesUrl(spreadsheetId, range, query = '') {
  const base = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(spreadsheetId)}/values/${encodeURIComponent(range)}`;
  return query ? `${base}?${query}` : base;
}
function findHeaderIndex(headers, pattern) {
  return headers.findIndex((item) => pattern.test(String(item || '').toLowerCase().replace(/[()]/g, '')));
}
async function ensureResponseHeader(config) {
  const range = `${quoteSheetName(config.responseTab)}!A1:Z1`;
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, range, 'valueRenderOption=FORMATTED_VALUE'));
  const headers = data.values?.[0] || [];
  const timestampIndex = findHeaderIndex(headers, /timestamp|date\s*(and|&)\s*time/);
  const incomeIndex = findHeaderIndex(headers, /money\s*came\s*in/);
  const expenseIndex = findHeaderIndex(headers, /money\s*went\s*out/);
  const remarksIndex = findHeaderIndex(headers, /remarks?/);
  if ([timestampIndex, incomeIndex, expenseIndex, remarksIndex].some((index) => index < 0)) {
    throw new Error(`The first row in “${config.responseTab}” must include Timestamp, Money Came In, Money Went Out, and Remarks. The app has not changed the Sheet.`);
  }
  for (const index of [incomeIndex, expenseIndex]) {
    const currencyInHeader = String(headers[index] || '').match(/\(([A-Z]{3})\)/i)?.[1]?.toUpperCase();
    if (currencyInHeader && currencyInHeader !== config.currencyCode) {
      throw new Error(`The response tab is labeled ${currencyInHeader}. Set the app to ${currencyInHeader}, or use a Sheet labeled ${config.currencyCode}.`);
    }
  }

  let idIndex = headers.findIndex((item) => String(item || '').trim().toLowerCase() === 'offline entry id');
  if (idIndex < 0) {
    idIndex = Math.max(timestampIndex, incomeIndex, expenseIndex, remarksIndex) + 1;
    const idColumn = columnName(idIndex + 1);
    const idCellRange = `${quoteSheetName(config.responseTab)}!${idColumn}1`;
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, idCellRange, 'valueInputOption=RAW'), {
      method: 'PUT',
      body: JSON.stringify({ values: [['Offline Entry ID']] })
    });
    headers[idIndex] = 'Offline Entry ID';
  }
  return { headers, timestampIndex, incomeIndex, expenseIndex, remarksIndex, idIndex };
}

function isSummaryRow(row) {
  const label = String(row[0] ?? '').trim().toUpperCase();
  return label.startsWith('TOTAL') || label.startsWith('REMAINING');
}
function parseSheetRow(row, rowIndex, indexes, currencyCode, timeZone) {
  const rawId = String(row[indexes.idIndex] || '').trim();
  const rawTimestamp = row[indexes.timestampIndex];
  const timestamp = String(rawTimestamp ?? '').trim();
  if (!timestamp && !row[indexes.incomeIndex] && !row[indexes.expenseIndex] && !row[indexes.remarksIndex]) return null;

  if (isSummaryRow(row) || timestamp.toUpperCase().startsWith('TOTAL')) {
    return null;
  }

  const id = rawId || `sheet-row-${rowIndex + 2}`;
  let createdAt = null;
  if (typeof rawTimestamp === 'number') {
    createdAt = sheetSerialToIso(rawTimestamp, timeZone);
  } else if (timestamp) {
    const parsedDate = Date.parse(timestamp);
    createdAt = Number.isNaN(parsedDate) ? null : new Date(parsedDate).toISOString();
  }
  return {
    id,
    createdAt,
    sheetTimestamp: typeof rawTimestamp === 'number' ? '' : timestamp,
    currencyCode,
    moneyInMinor: parseMoney(row[indexes.incomeIndex], currencyCode),
    moneyOutMinor: parseMoney(row[indexes.expenseIndex], currencyCode),
    remarks: String(row[indexes.remarksIndex] || ''),
    syncState: rawId ? 'synced' : 'sheet',
    source: rawId ? 'cashbook' : 'sheet'
  };
}
async function readResponseSheet(config, indexes, timeZone) {
  const lastIndex = Math.max(indexes.timestampIndex, indexes.incomeIndex, indexes.expenseIndex, indexes.remarksIndex, indexes.idIndex);
  const lastColumn = columnName(lastIndex + 1);
  const range = `${quoteSheetName(config.responseTab)}!A2:${lastColumn}`;
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, range, 'valueRenderOption=UNFORMATTED_VALUE&dateTimeRenderOption=SERIAL_NUMBER'));
  const records = [];
  const summaryRows = [];
  let lastEntryRow = 1;
  (data.values || []).forEach((row, index) => {
    const rowNumber = index + 2;
    if (isSummaryRow(row)) {
      summaryRows.push(rowNumber);
      return;
    }
    const record = parseSheetRow(row, index, indexes, config.currencyCode, timeZone);
    if (record) {
      records.push(record);
      lastEntryRow = rowNumber;
    }
  });
  return { records, lastEntryRow, summaryRows };
}
async function readResponseRows(config, indexes, timeZone) {
  return (await readResponseSheet(config, indexes, timeZone)).records;
}

const TOTALS_COLORS = {
  dark: { red: 0.1215, green: 0.4196, blue: 0.3137 },
  light: { red: 0.9098, green: 0.9490, blue: 0.9254 },
  ink: { red: 0.1215, green: 0.4196, blue: 0.3137 },
  white: { red: 1, green: 1, blue: 1 }
};

async function responseSheetId(config) {
  const tabs = await readSheetTabs(config);
  const tab = tabs.find((item) => item.title === config.responseTab);
  return tab ? tab.sheetId : null;
}
const HEADER_STYLE_VERSION = 1;
async function styleHeaderRow(config, indexes) {
  const styledKey = `headerStyled:v${HEADER_STYLE_VERSION}:${config.spreadsheetId}`;
  if (await getSetting(styledKey, false)) return;
  const sheetId = await responseSheetId(config);
  if (sheetId === null) return;
  const { dark, white } = TOTALS_COLORS;
  const endColIndex = indexes.remarksIndex + 1;

  await sheetsBatchUpdate(config, [
    {
      repeatCell: {
        range: {
          sheetId, startRowIndex: 0, endRowIndex: 1, startColumnIndex: 0, endColumnIndex: endColIndex
        },
        cell: { userEnteredFormat: {
          backgroundColor: dark,
          verticalAlignment: 'MIDDLE',
          horizontalAlignment: 'LEFT',
          textFormat: { bold: true, fontSize: 10, foregroundColor: white }
        } },
        fields: 'userEnteredFormat(backgroundColor,verticalAlignment,horizontalAlignment,textFormat)'
      }
    },
    {
      updateDimensionProperties: {
        range: { sheetId, dimension: 'ROWS', startIndex: 0, endIndex: 1 },
        properties: { pixelSize: 30 },
        fields: 'pixelSize'
      }
    }
  ]);
  await saveSetting(styledKey, true);
}
async function resetSummaryFormatting(config, summaryRows, endCol) {
  if (!summaryRows.length) return;
  const sheetId = await responseSheetId(config);
  if (sheetId === null) return;
  const requests = [];
  for (const row of summaryRows) {
    requests.push({
      repeatCell: {
        range: { sheetId, startRowIndex: row - 1, endRowIndex: row, startColumnIndex: 0, endColumnIndex: endCol },
        cell: { userEnteredFormat: {} },
        fields: 'userEnteredFormat'
      }
    });
    requests.push({
      updateDimensionProperties: {
        range: { sheetId, dimension: 'ROWS', startIndex: row - 1, endIndex: row },
        properties: { pixelSize: 21 },
        fields: 'pixelSize'
      }
    });
  }
  await sheetsBatchUpdate(config, requests);
}
async function styleTotalsBlock(config, indexes, totalsRow) {
  const sheetId = await responseSheetId(config);
  if (sheetId === null) return;
  const { dark, light, ink, white } = TOTALS_COLORS;
  const symbol = config.currencyCode === 'NPR' ? 'Rs' : config.currencyCode;
  
  const endColIndex = indexes.idIndex + 1; 
  
  const rowRange = (row, startColumnIndex = 0, endColumnIndex = endColIndex) => ({
    sheetId, startRowIndex: row - 1, endRowIndex: row, startColumnIndex, endColumnIndex
  });
  
  const remainingRow = totalsRow + 1;
  await sheetsBatchUpdate(config, [
    {
      repeatCell: {
        range: rowRange(totalsRow),
        cell: { userEnteredFormat: {
          backgroundColor: dark,
          verticalAlignment: 'MIDDLE',
          textFormat: { bold: false, fontSize: 10, foregroundColor: white }
        } },
        fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat)'
      }
    },
    {
      repeatCell: {
        range: rowRange(remainingRow),
        cell: { userEnteredFormat: {
          backgroundColor: light,
          verticalAlignment: 'MIDDLE',
          textFormat: { bold: false, fontSize: 10, foregroundColor: ink },
          borders: { bottom: { style: 'SOLID_MEDIUM', color: ink } }
        } },
        fields: 'userEnteredFormat(backgroundColor,verticalAlignment,textFormat,borders)'
      }
    },
    {
      repeatCell: {
        range: {
          sheetId, startRowIndex: totalsRow - 1, endRowIndex: remainingRow,
          startColumnIndex: indexes.incomeIndex, endColumnIndex: indexes.expenseIndex + 1
        },
        cell: { userEnteredFormat: {
          numberFormat: { type: 'NUMBER', pattern: `"${symbol} "#,##0.00` },
          horizontalAlignment: 'RIGHT'
        } },
        fields: 'userEnteredFormat(numberFormat,horizontalAlignment)'
      }
    },
    {
      repeatCell: {
        range: rowRange(remainingRow, indexes.remarksIndex, indexes.remarksIndex + 1),
        cell: { userEnteredFormat: { textFormat: { bold: false, italic: true, fontSize: 9, foregroundColor: ink } } },
        fields: 'userEnteredFormat.textFormat'
      }
    },
    {
      updateDimensionProperties: {
        range: { sheetId, dimension: 'ROWS', startIndex: totalsRow - 1, endIndex: remainingRow },
        properties: { pixelSize: 28 },
        fields: 'pixelSize'
      }
    }
  ]);
}

async function appendPending(config, indexes, remoteSheet, timeZone) {
  const remoteIds = new Set(remoteSheet.records.map((row) => row.id));
  const allLocal = await getAllTransactions();
  const pending = allLocal.filter((record) => record.syncState === 'pending');
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
    if (record.currencyCode && record.currencyCode !== config.currencyCode) {
      throw new Error(`A saved entry uses ${record.currencyCode}, but this Sheet uses ${config.currencyCode}. The entry remains saved on this device.`);
    }
    if (remoteIds.has(record.id)) {
      await putTransaction({ ...record, syncState: 'synced' });
      continue;
    }
    const row = Array(coreCols).fill('');
    row[indexes.timestampIndex] = formatSheetTimestamp(record.createdAt, timeZone);
    row[indexes.incomeIndex] = (Number(record.moneyInMinor) || 0) / currencyScale(record.currencyCode || config.currencyCode);
    row[indexes.expenseIndex] = (Number(record.moneyOutMinor) || 0) / currencyScale(record.currencyCode || config.currencyCode);
    row[indexes.remarksIndex] = safeSheetText(record.remarks);
    row[indexes.idIndex] = record.id;
    rowsToUpload.push(row);
    recordsToUpdate.push(record);
    remoteIds.add(record.id);
  }

  if (remoteSheet.summaryRows.length) {
    const ranges = remoteSheet.summaryRows.map((rowNumber) => `${tab}!A${rowNumber}:${endColLetter}${rowNumber}`);
    await sheetsRequest(`https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}/values:batchClear`, {
      method: 'POST',
      body: JSON.stringify({ ranges })
    });
    try { await resetSummaryFormatting(config, remoteSheet.summaryRows, indexes.idIndex + 1); } catch { /* cosmetic only */ }
  }

  if (rowsToUpload.length) {
    const startRow = lastEntryRow + 1;
    const endRow = startRow + rowsToUpload.length - 1;
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${tab}!A${startRow}:${endColLetter}${endRow}`, 'valueInputOption=USER_ENTERED'), {
      method: 'PUT',
      body: JSON.stringify({ majorDimension: 'ROWS', values: rowsToUpload })
    });
    for (const record of recordsToUpdate) await putTransaction({ ...record, syncState: 'synced' });
    lastEntryRow = endRow;
  }

  if (lastEntryRow <= 1) return '';
  try {
    const totalsRow = lastEntryRow + 2; 
    const sumEnd = totalsRow - 1;       
    const totalLine = Array(coreCols).fill('');
    totalLine[indexes.timestampIndex] = 'TOTAL';
    totalLine[indexes.incomeIndex] = `=SUM(${inCol}2:${inCol}${sumEnd})`;
    totalLine[indexes.expenseIndex] = `=SUM(${outCol}2:${outCol}${sumEnd})`;
    const remainingLine = Array(coreCols).fill('');
    remainingLine[indexes.timestampIndex] = 'REMAINING';
    remainingLine[indexes.incomeIndex] = `=${inCol}${totalsRow}-${outCol}${totalsRow}+N(${dashTab}!B13)`;
    remainingLine[indexes.remarksIndex] = 'Money in − money out + starting balance';
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${tab}!A${totalsRow}:${endColLetter}${totalsRow + 1}`, 'valueInputOption=USER_ENTERED'), {
      method: 'PUT',
      body: JSON.stringify({ majorDimension: 'ROWS', values: [totalLine, remainingLine] })
    });
    try { await styleTotalsBlock(config, indexes, totalsRow); } catch { /* cosmetic only */ }
    return '';
  } catch (error) {
    return `the totals under your entries could not be written (${error.message || 'unknown reason'}).`;
  }
}

async function readStartingBalance(config) {
  const range = `${quoteSheetName(config.dashboardTab)}!B13`;
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, range, 'valueRenderOption=UNFORMATTED_VALUE'));
  const value = data.values?.[0]?.[0];
  if (value === undefined || value === null || value === '') return null;
  return typeof value === 'number' ? Math.round(value * currencyScale(config.currencyCode)) : parseMoney(value, config.currencyCode);
}
function archiveStamp(date) {
  const pad = (number) => String(number).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}${pad(date.getMinutes())}`;
}
async function readSheetTabs(config) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}?fields=sheets.properties(sheetId,title)`;
  const data = await sheetsRequest(url);
  return (data.sheets || []).map((sheet) => sheet.properties);
}
function sheetsBatchUpdate(config, requests) {
  const url = `https://sheets.googleapis.com/v4/spreadsheets/${encodeURIComponent(config.spreadsheetId)}:batchUpdate`;
  return sheetsRequest(url, { method: 'POST', body: JSON.stringify({ requests }) });
}
async function copySpreadsheetToDrive(config, name) {
  try {
    const url = `https://www.googleapis.com/drive/v3/files/${encodeURIComponent(config.spreadsheetId)}/copy`;
    await sheetsRequest(url, { method: 'POST', body: JSON.stringify({ name }) });
    return true;
  } catch {
    return false;
  }
}
async function archiveResponseTab(config, tabs, archiveName) {
  const source = tabs.find((tab) => tab.title === config.responseTab);
  if (!source) throw new Error(`Could not find the “${config.responseTab}” tab in your Sheet.`);
  await sheetsBatchUpdate(config, [{ duplicateSheet: { sourceSheetId: source.sheetId, newSheetName: archiveName } }]);
}
async function archiveDashboardTab(config, tabs, dashboardArchiveName) {
  const source = tabs.find((tab) => tab.title === (config.dashboardTab || 'Dashboard'));
  if (!source) throw new Error(`Could not find the “${config.dashboardTab || 'Dashboard'}” tab in your Sheet.`);

  const dupResult = await sheetsBatchUpdate(config, [
    { duplicateSheet: { sourceSheetId: source.sheetId, newSheetName: dashboardArchiveName } }
  ]);
  const dupProps = dupResult.replies?.[0]?.duplicateSheet?.properties;
  const newSheetId = dupProps?.sheetId;
  const rowCount = dupProps?.gridProperties?.rowCount || 1000;
  const colCount = dupProps?.gridProperties?.columnCount || 26;

  if (typeof newSheetId !== 'number') {
    throw new Error('Could not duplicate the dashboard tab.');
  }

  await sheetsBatchUpdate(config, [
    {
      copyPaste: {
        source: {
          sheetId: newSheetId,
          startRowIndex: 0,
          endRowIndex: rowCount,
          startColumnIndex: 0,
          endColumnIndex: colCount
        },
        destination: {
          sheetId: newSheetId,
          startRowIndex: 0,
          endRowIndex: rowCount,
          startColumnIndex: 0,
          endColumnIndex: colCount
        },
        pasteType: 'PASTE_VALUES',
        pasteOrientation: 'NORMAL'
      }
    }
  ]);
}
async function usedRowCount(config, tabName) {
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(tabName)}!A:A`));
  return (data.values || []).length;
}
async function deleteOldRows(config, tabs, lastRowNumber) {
  if (lastRowNumber <= 1) return;
  const source = tabs.find((tab) => tab.title === config.responseTab);
  if (!source) throw new Error(`Could not find the “${config.responseTab}” tab.`);
  await sheetsBatchUpdate(config, [{
    deleteDimension: { range: { sheetId: source.sheetId, dimension: 'ROWS', startIndex: 1, endIndex: lastRowNumber } }
  }]);
}
async function ensurePeriodsTab(config, tabs) {
  if (tabs.some((tab) => tab.title === PERIODS_TAB)) return;
  await sheetsBatchUpdate(config, [{ addSheet: { properties: { title: PERIODS_TAB } } }]);
  const range = `${quoteSheetName(PERIODS_TAB)}!A1:C1`;
  await sheetsRequest(sheetValuesUrl(config.spreadsheetId, range, 'valueInputOption=RAW'), {
    method: 'PUT',
    body: JSON.stringify({ values: [['Period started (UTC)', 'Starting balance', 'Archive tab']] })
  });
}
async function readPeriodStart(config) {
  const range = `${quoteSheetName(PERIODS_TAB)}!A2:A`;
  const data = await sheetsRequest(sheetValuesUrl(config.spreadsheetId, range, 'valueRenderOption=UNFORMATTED_VALUE'));
  const starts = (data.values || []).map((row) => String(row[0] || '').trim()).filter((value) => !Number.isNaN(Date.parse(value)));
  return starts.length ? starts[starts.length - 1] : null;
}
async function applySheetPeriod(config) {
  try {
    const sheetStart = await readPeriodStart(config);
    if (!sheetStart) return;
    const localStart = Date.parse(await getSetting('periodStartIso', '') || '');
    if (Number.isNaN(localStart) || Date.parse(sheetStart) > localStart) await saveSetting('periodStartIso', sheetStart);
  } catch {
    // The Cashbook Periods tab does not exist yet, so nothing has been reset.
  }
}

async function archiveAndStartFresh() {
  const config = await getSetting('googleConfig', {});
  if (!config.spreadsheetId || !config.responseTab) {
    setArchiveStatus('Choose your Sheet and tap Connect & sync first.', true);
    return;
  }
  if (!navigator.onLine) {
    setArchiveStatus('You are offline. Archiving needs the internet so the copy can be saved.', true);
    return;
  }
  if (!accessToken || tokenExpiresAt <= Date.now() + 60000) {
    setArchiveStatus('Tap Connect & sync above first, then try again.', true);
    return;
  }

  elements.archiveNow.disabled = true;
  try {
    setArchiveStatus('Syncing your latest entries first…');
    await syncToSheet();
    const all = await getAllTransactions();
    if (all.some((record) => record.syncState === 'pending')) {
      throw new Error('Some entries are not on your Sheet yet. Fix the sync problem, then try again.');
    }

    const active = await getActiveRecords();
    const income = active.reduce((sum, item) => sum + (Number(item.moneyInMinor) || 0), 0);
    const expense = active.reduce((sum, item) => sum + (Number(item.moneyOutMinor) || 0), 0);
    const startingBalance = Number(await getSetting('startingBalanceMinor', 0)) || 0;
    const carry = elements.carryBalance?.checked ? startingBalance + income - expense : 0;

    const nameForConfirm = (elements.archiveName?.value || '').trim();
    const dashboardArchiveNameForConfirm = nameForConfirm ? `${nameForConfirm} - Dashboard` : '';
    const proceed = window.confirm(
      'Archive and start fresh?\n\n' +
      (nameForConfirm ? `• The archive tabs will be named “${nameForConfirm}” and “${dashboardArchiveNameForConfirm}”.\n` : '• Archive tabs will be created for your entries and dashboard.\n') +
      '• A copy of your Sheet is saved in Drive first (if enabled).\n' +
      '• Your old entries and a frozen snapshot of your Dashboard are saved to archive tabs.\n' +
      '• The old entries are then removed from the main response tab.\n' +
      `• The app starts counting again from ${formatMoney(carry)}.\n\nContinue?`
    );
    if (!proceed) {
      setArchiveStatus('Cancelled. Nothing was changed.');
      return;
    }

    const now = new Date();
    const stamp = archiveStamp(now);
    const typedName = (elements.archiveName?.value || '').replace(/[\[\]*?:\/\\]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 60);
    const archiveName = typedName || `Archive ${stamp}`;
    const dashboardArchiveName = `${archiveName} - Dashboard`;
    const scale = currencyScale(config.currencyCode || activeCurrencyCode);

    setArchiveStatus('Saving a copy of your Sheet…');
    const tabs = await readSheetTabs(config);
    if (tabs.some((tab) => tab.title.toLowerCase() === archiveName.toLowerCase())) {
      throw new Error(`A tab called “${archiveName}” already exists. Choose a different archive name.`);
    }
    if (tabs.some((tab) => tab.title.toLowerCase() === dashboardArchiveName.toLowerCase())) {
      throw new Error(`A tab called “${dashboardArchiveName}” already exists. Choose a different archive name.`);
    }
    const driveCopied = await copySpreadsheetToDrive(config, `${config.spreadsheetName || 'Cashbook'} - ${archiveName}`);
    const sourceRows = await usedRowCount(config, config.responseTab);

    setArchiveStatus('Archiving responses and dashboard…');
    await archiveResponseTab(config, tabs, archiveName);
    await archiveDashboardTab(config, tabs, dashboardArchiveName);

    setArchiveStatus('Moving old entries into the archive…');
    let cleared = false;
    let clearProblem = '';
    try {
      const archivedRows = await usedRowCount(config, archiveName);
      if (archivedRows !== sourceRows) throw new Error('the archive copy did not match the original');
      await deleteOldRows(config, tabs, sourceRows);
      cleared = true;
    } catch (error) {
      clearProblem = error.message || 'unknown reason';
    }

    setArchiveStatus('Starting the new period…');
    await ensurePeriodsTab(config, tabs);
    const balanceCell = `${quoteSheetName(config.dashboardTab || 'Dashboard')}!B13`;
    await sheetsRequest(sheetValuesUrl(config.spreadsheetId, balanceCell, 'valueInputOption=RAW'), {
      method: 'PUT',
      body: JSON.stringify({ values: [[carry / scale]] })
    });
    const periodStart = new Date(Math.floor(now.getTime() / 1000) * 1000).toISOString();
    const appendUrl = `${sheetValuesUrl(config.spreadsheetId, `${quoteSheetName(PERIODS_TAB)}!A:C`)}:append?valueInputOption=RAW&insertDataOption=INSERT_ROWS`;
    await sheetsRequest(appendUrl, {
      method: 'POST',
      body: JSON.stringify({ majorDimension: 'ROWS', values: [[periodStart, carry / scale, `${archiveName}, ${dashboardArchiveName}`]] })
    });

    await saveSetting('periodStartIso', periodStart);
    await saveSetting('startingBalanceMinor', carry);
    if (elements.archiveName) elements.archiveName.value = '';
    await refreshView();
    const where = driveCopied
      ? `the “${archiveName}” and “${dashboardArchiveName}” tabs and a full copy in your Google Drive`
      : `the “${archiveName}” and “${dashboardArchiveName}” tabs of your Sheet (the Drive copy was skipped)`;
    const clearNote = cleared
      ? ' The main tab is now empty, ready for new entries.'
      : ` The old rows could not be removed from the main tab (${clearProblem}), so they are still there. Your data is safe.`;
    setArchiveStatus(`Done. Your old entries and dashboard are saved in ${where}.${clearNote}`);
    announce('New period started.');
  } catch (error) {
    setArchiveStatus(error.message || 'Could not archive. Nothing was deleted.', true);
  } finally {
    elements.archiveNow.disabled = false;
  }
}

async function cleanupOldRightSummary(config) {
  try {
    const range = `${quoteSheetName(config.responseTab)}!G1:Z1`;
    const clearUrl = `${sheetValuesUrl(config.spreadsheetId, range)}:clear`;
    await sheetsRequest(clearUrl, { method: 'POST' });
  } catch {
    // Non-blocking cleanup
  }
}

async function syncToSheet() {
  if (isSyncing) return;
  if (!cryptoKey) return; // App is locked
  if (!navigator.onLine) {
    setSyncStatus('Saved offline', 'Your entries are queued on this device for when you are online.', 'offline');
    return;
  }
  if (!tokenIsValid()) {
    setSyncStatus('Waiting to sync', 'Tap “Sync now” to sign in and send your entries.', 'pending');
    return;
  }
  isSyncing = true;
  elements.syncNow.disabled = true;
  setSyncStatus('Syncing', 'Checking the response tab and sending saved entries…', 'ready');
  try {
    const config = await getSetting('googleConfig', {});
    if (!config.spreadsheetId || !config.responseTab) throw new Error('Save the Google Sheet link and response tab first.');
    const indexes = await ensureResponseHeader(config);
    try { await styleHeaderRow(config, indexes); } catch { /* cosmetic only */ }
    await cleanupOldRightSummary(config);
    const timeZone = await readSpreadsheetTimeZone(config);
    const before = await readResponseSheet(config, indexes, timeZone);
    const totalsWarning = await appendPending(config, indexes, before, timeZone);
    const after = await readResponseRows(config, indexes, timeZone);
    await mergeSheetRecords(after);
    const startingBalance = await readStartingBalance(config).catch(() => null);
    if (startingBalance !== null) await saveSetting('startingBalanceMinor', startingBalance);
    await applySheetPeriod(config);
    if (totalsWarning) setSetupStatus(`Sheet synced, but ${totalsWarning}`, true);
    else setSetupStatus('Sheet synced. Your transaction dates and times remain the original save times.');
    const pendingCount = (await getAllTransactions()).filter((row) => row.syncState === 'pending').length;
    setSyncStatus('Google Sheet connected', pendingCount ? `${pendingCount} entries still need syncing.` : 'All saved entries are on your Sheet.', pendingCount ? 'pending' : 'ready');
    await refreshView();
    lastSyncFinishedAt = Date.now();
    return true;
  } catch (error) {
    setSyncStatus('Sync needs attention', error.message || 'Could not sync. Your saved entries are still on this device.', 'error');
    setSetupStatus(error.message || 'Could not sync to Google Sheets.', true);
    return false;
  } finally {
    isSyncing = false;
    elements.syncNow.disabled = false;
  }
}

async function oneTapSync() {
  if (!cryptoKey) return; // App is locked
  if (!cachedConfig?.spreadsheetId) {
    updateOnboarding();
    elements.onboardingCard?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    announce('Create or choose your Google Sheet first.');
    return;
  }
  if (!navigator.onLine) {
    announce('You are offline. Your entries are safe on this device.');
    return;
  }
  try {
    await ensureSignedIn();
  } catch (error) {
    setSyncStatus('Sign-in needed', error.message || 'Google sign-in was not completed.', 'error');
    return;
  }
  await syncToSheet();
}

async function autoSync() {
  if (isSyncing || !cryptoKey || !navigator.onLine || !cachedConfig?.spreadsheetId) return;
  const hasPending = (await getAllTransactions()).some((record) => record.syncState === 'pending');
  if (!hasPending && Date.now() - lastSyncFinishedAt < 120000) return;
  if (!tokenIsValid()) {
    await refreshView();
    return;
  }
  await syncToSheet();
}

async function mergeSheetRecords(remoteRecords) {
  const local = await getAllTransactions();
  const localById = new Map(local.map((record) => [record.id, record]));
  for (const remote of remoteRecords) {
    const current = localById.get(remote.id);
    if (current?.syncState === 'pending') continue;
    await putTransaction(current ? { ...current, ...remote, createdAt: current.createdAt || remote.createdAt, syncState: 'synced' } : remote);
  }
}

// ===== INITIALIZATION & UNLOCK FLOW =====
function showLockScreen(mode) {
  elements.lockScreen.style.display = 'flex';
  elements.appShell.style.display = 'none';
  const hasPassword = mode === 'password' || mode === 'both';
  const hasBiometrics = mode === 'biometrics' || mode === 'both';
  elements.unlockForm.style.display = hasPassword ? 'flex' : 'none';
  elements.biometricBtn.style.display = hasBiometrics ? 'flex' : 'none';
  elements.forgotPasswordBtn.style.display = 'inline-block';
  elements.forgotPasswordBtn.textContent = hasPassword ? 'Forgot password?' : 'Can’t unlock? Erase this device';
  elements.unlockPassword.value = '';
  elements.unlockBtn.textContent = 'Unlock Cashbook';
}

function lockApp() {
  cryptoKey = null;
  masterKeyRaw = null;
  clearTimeout(idleTimeout);
  const state = securityState();
  showLockScreen(state.hasPassword && state.hasBiometrics ? 'both' : state.hasPassword ? 'password' : 'biometrics');
  elements.lockMessage.textContent = state.hasPassword
    ? 'Enter your master password to unlock your encrypted cashbook.'
    : 'Use Face ID / fingerprint to unlock your cashbook.';
}

function resetIdleTimer() {
  clearTimeout(idleTimeout);
  if (!cryptoKey) return; // App already locked
  if (!isProtected()) return; // No lock configured
  idleTimeout = setTimeout(() => lockApp(), 5 * 60 * 1000); // 5 minutes
}

async function startApp() {
  elements.lockScreen.style.display = 'none';
  elements.appShell.style.display = 'block';

  updateSecurityUi();

  await loadSavedConfig();
  activeCurrencyCode = await getSetting('currencyCode', DEFAULT_CURRENCY) || DEFAULT_CURRENCY;
  loadSavedToken();
  cachedConfig = await getSetting('googleConfig', {});
  if (elements.onboardCurrency) elements.onboardCurrency.value = cachedConfig.currencyCode || activeCurrencyCode || DEFAULT_CURRENCY;
  await refreshView();
  if (navigator.onLine) void loadGoogleIdentity().catch(() => {});

  void autoSync();
  resetIdleTimer(); // Start the inactivity timer
}

async function readAllRaw(storeName) {
  const db = await openDatabase();
  const tx = db.transaction(storeName, 'readonly');
  return new Promise((resolve, reject) => {
    const request = tx.objectStore(storeName).getAll();
    request.onsuccess = () => resolve(request.result || []);
    request.onerror = () => reject(request.error);
  });
}

async function migrateFromLegacy(legacyKey) {
  // Switch to a random master key and re-encrypt everything under it.
  await generateMasterKey();
  const transactions = await readAllRaw(STORE_TRANSACTIONS);
  for (const record of transactions) {
    let payload = record;
    if (record.encrypted) {
      const plaintext = await decryptText(record.encrypted, legacyKey);
      if (plaintext == null) continue;
      try { payload = JSON.parse(plaintext); } catch { continue; }
      payload.id = record.id; // keyPath lives outside the encrypted payload
    }
    await putTransaction(payload);
  }
  const settings = await readAllRaw(STORE_SETTINGS);
  for (const setting of settings) {
    let value;
    if (setting.encrypted) {
      const plaintext = await decryptText(setting.encrypted, legacyKey);
      if (plaintext == null) continue;
      try { value = JSON.parse(plaintext); } catch { continue; }
    } else if (setting.value !== undefined) {
      value = setting.value;
    } else {
      continue;
    }
    await saveSetting(setting.key, value);
  }
  const wrapped = await wrapMasterKeyWith(legacyKey);
  localStorage.setItem('cb_key_wrapped', JSON.stringify(wrapped));
  localStorage.setItem('cb_has_password', 'true');
}

async function unlockWithPassword(password) {
  const hasWrapped = localStorage.getItem('cb_key_wrapped');
  const hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const salt = localStorage.getItem('cb_salt');
  const isLegacy = !!salt && !hasWrapped && !hasPrf && !localStorage.getItem('cb_key_raw');

  if (isLegacy) {
    // Old scheme: data was encrypted directly with the PBKDF2 key.
    const legacyKey = await derivePasswordKek(password, salt);
    cryptoKey = legacyKey;
    await openDatabase();
    const check = await getSetting('__auth_check__', null);
    if (check !== 'valid') {
      cryptoKey = null;
      masterKeyRaw = null;
      throw new Error('Incorrect password.');
    }
    await migrateFromLegacy(legacyKey);
  } else if (hasWrapped) {
    const kek = await derivePasswordKek(password, salt);
    try {
      await unwrapMasterKey(JSON.parse(hasWrapped), kek);
    } catch {
      cryptoKey = null;
      masterKeyRaw = null;
      throw new Error('Incorrect password.');
    }
    await openDatabase();
    const check = await getSetting('__auth_check__', null);
    if (check !== 'valid') {
      cryptoKey = null;
      masterKeyRaw = null;
      throw new Error('Incorrect password.');
    }
  } else {
    throw new Error('No master password is set. Use Face ID / fingerprint to unlock.');
  }
  await startApp();
}

async function forgotPassword() {
  const message = [
    'Forgot your password?',
    '',
    'Your entries on this device are encrypted and cannot be recovered without the password.',
    'If you synced to a Google Sheet, those entries are safe there and can be brought back by connecting the Sheet again.',
    '',
    'Type ERASE to erase this device\u2019s data and start fresh.'
  ].join('\n');
  const input = window.prompt(message);
  if (input === null) return;
  if (input.trim() !== 'ERASE') {
    alert('Nothing was erased. Type ERASE exactly to confirm.');
    return;
  }
  try {
    await new Promise((resolve) => {
      const request = indexedDB.deleteDatabase(DB_NAME);
      request.onsuccess = request.onerror = request.onblocked = () => resolve();
    });
  } catch {}
  ['cb_salt', 'cb_key_wrapped', 'cb_key_raw', 'cb_prf_salt', 'cb_prf_cred_id', 'cb_prf_key_wrapped', 'cb_has_password', 'cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach((key) => localStorage.removeItem(key));
  location.reload();
}

async function setPasswordHandler() {
  const password = elements.passwordInput.value;
  if (!password) {
    setSetupStatus('Enter a password first.', true);
    return;
  }
  if (password.length < 10) {
    setSetupStatus('Password must be at least 10 characters.', true);
    return;
  }
  try {
    const salt = localStorage.getItem('cb_salt') || randomSaltB64();
    const kek = await derivePasswordKek(password, salt);
    const wrapped = await wrapMasterKeyWith(kek);
    localStorage.setItem('cb_salt', salt);
    localStorage.setItem('cb_key_wrapped', JSON.stringify(wrapped));
    localStorage.setItem('cb_has_password', 'true');
    localStorage.removeItem('cb_key_raw');
    elements.passwordInput.value = '';
    setSetupStatus('Master password saved.');
    announce('Master password set.');
    updateSecurityUi();
  } catch (error) {
    setSetupStatus(error.message || 'Could not set the password.', true);
  }
}

async function removePasswordHandler() {
  if (!localStorage.getItem('cb_key_wrapped')) {
    setSetupStatus('No master password is set.', true);
    return;
  }
  if (!securityState().hasBiometrics) {
    const ok = window.confirm('Remove your master password?\n\nYour cashbook will then open without any lock on this device, so anyone using this device could see your entries.');
    if (!ok) return;
  }
  localStorage.removeItem('cb_key_wrapped');
  localStorage.removeItem('cb_has_password');
  if (!securityState().hasBiometrics && masterKeyRaw) {
    localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
  }
  setSetupStatus('Master password removed.');
  announce('Master password removed.');
  updateSecurityUi();
}

function bindEvents() {
  elements.biometricBtn.addEventListener('click', async () => {
    elements.lockError.textContent = 'Waiting for Face ID / fingerprint…';
    const success = await authenticateWithBiometrics();
    if (success) {
      elements.lockError.textContent = '';
      await startApp();
    } else {
      elements.lockError.textContent = 'Face ID / fingerprint failed or was cancelled.';
    }
  });

  elements.forgotPasswordBtn.addEventListener('click', () => void forgotPassword());

  elements.unlockForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    elements.unlockBtn.disabled = true;
    elements.lockError.textContent = '';
    try {
      await unlockWithPassword(elements.unlockPassword.value);
    } catch (error) {
      elements.lockError.textContent = error.message || 'Failed to unlock.';
      elements.unlockPassword.value = '';
    } finally {
      elements.unlockBtn.disabled = false;
    }
  });

  elements.biometricToggle?.addEventListener('change', async (event) => {
    if (event.target.checked) {
      try {
        await enableBiometrics();
        event.target.checked = true;
        setSetupStatus('Face ID / fingerprint enabled.');
        announce('Face ID / fingerprint enabled.');
      } catch (error) {
        event.target.checked = false;
        alert(error.message || 'Could not enable Face ID / fingerprint.');
      }
    } else {
      disableBiometrics();
      setSetupStatus('Face ID / fingerprint disabled.');
      announce('Face ID / fingerprint disabled.');
    }
    updateSecurityUi();
  });

  elements.setPasswordBtn?.addEventListener('click', () => void setPasswordHandler());
  elements.removePasswordBtn?.addEventListener('click', () => void removePasswordHandler());

  elements.signOutGoogle?.addEventListener('click', async () => {
    const ok = window.confirm('Sign out of Google?\n\nYour entries stay on this device. The connected Sheet is kept, but you will need to sign in again (or pick a different Sheet to switch accounts) to keep syncing.');
    if (!ok) return;
    clearSavedToken();
    setSetupStatus('Signed out of Google. Sign in again to sync, or pick another Sheet to switch accounts.');
    announce('Signed out of Google.');
  });

  elements.resetGoogleCreds?.addEventListener('click', async () => {
    if (elements.clientId) elements.clientId.value = DEFAULT_CLIENT_ID;
    if (elements.apiKey) elements.apiKey.value = DEFAULT_API_KEY;
    if (elements.appId) elements.appId.value = DEFAULT_APP_ID;
    await saveConfig();
    setSetupStatus('Google credentials reset to the app defaults. Reconnect Google to apply them.');
    announce('Google credentials reset.');
  });

  elements.lockNowBtn?.addEventListener('click', lockApp);

  // Setup other event listeners
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
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && navigator.onLine) void autoSync();
  });

  // Reset idle timer on user activity
  ['click', 'keydown', 'mousemove', 'touchstart'].forEach((evt) =>
    document.addEventListener(evt, resetIdleTimer)
  );

  if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
    navigator.serviceWorker.register('./sw.js').catch(() => {
      elements.storageStatus.textContent = 'Local storage ready · offline app shell not installed yet';
    });
  }
}

async function initialize() {
  // Always clear the old insecure biometric password left by previous versions.
  ['cb_bio_id', 'cb_bio_pwd', 'cb_bio_enabled'].forEach((key) => localStorage.removeItem(key));

  bindEvents();

  const salt = localStorage.getItem('cb_salt');
  const hasWrapped = localStorage.getItem('cb_key_wrapped');
  const hasRaw = localStorage.getItem('cb_key_raw');
  const hasPrf = localStorage.getItem('cb_prf_key_wrapped');
  const isLegacy = !!salt && !hasWrapped && !hasRaw && !hasPrf;

  if (isLegacy) {
    elements.lockMessage.textContent = 'Enter your master password to unlock your encrypted cashbook.';
    showLockScreen('password');
    return;
  }

  if (hasWrapped || hasPrf) {
    elements.lockMessage.textContent = hasWrapped
      ? 'Enter your master password to unlock your encrypted cashbook.'
      : 'Use Face ID / fingerprint to unlock your cashbook.';
    showLockScreen(hasWrapped && hasPrf ? 'both' : hasWrapped ? 'password' : 'biometrics');
    return;
  }

  if (hasRaw) {
    // Unprotected device: open straight to the cashbook.
    try {
      await setMasterKeyFromBytes(b64ToBytes(hasRaw));
      await openDatabase();
      await startApp();
    } catch (error) {
      console.error('Could not open the local cashbook', error);
      elements.storageStatus.textContent = 'Could not read local data.';
    }
    return;
  }

  // Brand-new device: create a random key and open without a password.
  try {
    await generateMasterKey();
    localStorage.setItem('cb_key_raw', bytesToB64(masterKeyRaw));
    await openDatabase();
    await saveSetting('__auth_check__', 'valid');
    await startApp();
  } catch (error) {
    console.error('Setup failed', error);
    elements.lockMessage.textContent = 'Could not initialize local storage.';
  }
}

void initialize();