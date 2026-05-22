/**
 * secretvoid-crypto
 *
 * Client-side zero-knowledge AES-256-GCM encryption module.
 * Uses the Web Crypto API — no dependencies, works in browsers and Node.js 18+.
 *
 * Two functions from this module are used in the URL-based key exchange:
 *   generateShareUrl — puts the client key in the URL fragment (#), never sent to server
 *   extractKeyFromUrl — reads the key back from the fragment on the recipient side
 *
 * Zero-knowledge guarantee: the server only ever receives the client-encrypted blob.
 * The client key lives exclusively in the URL fragment, which the HTTP spec guarantees
 * is never transmitted.
 */

// ---------------------------------------------------------------------------
// Core AES-256-GCM
// ---------------------------------------------------------------------------

/**
 * Generate a random 256-bit AES-GCM encryption key.
 * @returns {Promise<CryptoKey>}
 */
export async function generateKey() {
  return crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a plaintext string with an AES-GCM key.
 * A random 12-byte IV is generated for every call.
 *
 * @param {string} text - Plaintext secret to encrypt
 * @param {CryptoKey} key - AES-GCM key from generateKey() or importKey()
 * @returns {Promise<{ payload: string, iv: string }>} base64url ciphertext and IV
 */
export async function encrypt(text, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(text);

  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );

  return {
    payload: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv)
  };
}

/**
 * Decrypt an AES-GCM ciphertext back to plaintext.
 *
 * @param {string} payload - base64url ciphertext (from encrypt)
 * @param {string} iv - base64url IV (from encrypt)
 * @param {CryptoKey} key - AES-GCM key
 * @returns {Promise<string>} Plaintext secret
 * @throws {Error} If decryption fails (wrong key, tampered data, etc.)
 */
export async function decrypt(payload, iv, key) {
  const ciphertext = base64ToArrayBuffer(payload);
  const ivBuffer = base64ToArrayBuffer(iv);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: ivBuffer },
      key,
      ciphertext
    );
    return new TextDecoder().decode(decrypted);
  } catch {
    throw new Error('Decryption failed. Invalid key or corrupted data.');
  }
}

// ---------------------------------------------------------------------------
// Key export / import
// ---------------------------------------------------------------------------

/**
 * Export a CryptoKey to a base64url string suitable for a URL fragment.
 *
 * @param {CryptoKey} key
 * @returns {Promise<string>} base64url-encoded raw key bytes
 */
export async function exportKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(raw);
}

/**
 * Import a base64url key string (from the URL fragment) back to a CryptoKey.
 *
 * @param {string} base64Key - base64url-encoded key from exportKey()
 * @returns {Promise<CryptoKey>}
 */
export async function importKey(base64Key) {
  const keyBuffer = base64ToArrayBuffer(base64Key);
  return crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------------------
// Passphrase protection (PBKDF2 + AES-KW)
// ---------------------------------------------------------------------------

/**
 * Derive an AES-256-KW key from a user passphrase using PBKDF2.
 * Uses 100,000 iterations with SHA-256. The salt must be stored alongside
 * the wrapped key so the recipient can re-derive the same key.
 *
 * @param {string} passphrase - User-supplied passphrase
 * @param {Uint8Array|ArrayBuffer|string} salt - Random salt (or base64url string)
 * @returns {Promise<CryptoKey>} AES-KW key for wrapKey / unwrapKey
 */
export async function deriveKeyFromPassphrase(passphrase, salt) {
  const rawSalt = typeof salt === 'string' ? base64ToArrayBuffer(salt) : salt;

  const baseKey = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(passphrase),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: rawSalt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-KW', length: 256 },
    false,
    ['wrapKey', 'unwrapKey']
  );
}

/**
 * Wrap (encrypt) a content key with a passphrase-derived AES-KW key.
 * The wrapped key can be safely placed in the URL fragment alongside the salt.
 *
 * @param {CryptoKey} contentKey - AES-GCM content key to protect
 * @param {CryptoKey} passphraseKey - AES-KW key from deriveKeyFromPassphrase()
 * @returns {Promise<string>} base64url-encoded wrapped key
 */
export async function wrapKey(contentKey, passphraseKey) {
  const wrapped = await crypto.subtle.wrapKey('raw', contentKey, passphraseKey, 'AES-KW');
  return arrayBufferToBase64(wrapped);
}

/**
 * Unwrap (decrypt) a wrapped content key using a passphrase-derived AES-KW key.
 * Throws if the passphrase is wrong.
 *
 * @param {string} wrappedKeyBase64 - base64url-encoded wrapped key from wrapKey()
 * @param {CryptoKey} passphraseKey - AES-KW key from deriveKeyFromPassphrase()
 * @returns {Promise<CryptoKey>} Unwrapped AES-GCM content key
 * @throws {Error} If the passphrase is incorrect
 */
export async function unwrapKey(wrappedKeyBase64, passphraseKey) {
  const wrappedKey = base64ToArrayBuffer(wrappedKeyBase64);
  return crypto.subtle.unwrapKey(
    'raw',
    wrappedKey,
    passphraseKey,
    'AES-KW',
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

/**
 * Build the shareable URL. The client key goes in the fragment (#), which the
 * HTTP spec guarantees is never transmitted to the server.
 *
 * @param {string} id - Secret ID returned by the server
 * @param {string} exportedKey - base64url key from exportKey()
 * @returns {string} e.g. https://secretvoid.com/s/abc123#clientKey
 */
export function generateShareUrl(id, exportedKey) {
  const origin =
    typeof window !== 'undefined' && window.location
      ? window.location.origin
      : 'https://secretvoid.com';
  return `${origin}/s/${id}#${exportedKey}`;
}

/**
 * Read the client key from the current page's URL fragment.
 * Call this on the recipient side before decrypting.
 *
 * @returns {string|null} base64url key string, or null if the fragment is absent
 */
export function extractKeyFromUrl() {
  if (typeof window === 'undefined') return null;
  const hash = window.location.hash;
  return hash ? hash.substring(1) : null;
}

/**
 * Remove the key from the browser's URL bar and history after decryption so it
 * does not linger in browser history or referrer headers.
 */
export function clearKeyFromUrl() {
  if (typeof window !== 'undefined' && typeof history !== 'undefined') {
    history.replaceState(null, '', window.location.pathname);
  }
}

// ---------------------------------------------------------------------------
// Base64url helpers (exported for testing and external use)
// ---------------------------------------------------------------------------

/**
 * Convert an ArrayBuffer to a base64url string (URL-safe, no padding).
 * @param {ArrayBuffer} buffer
 * @returns {string}
 */
export function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

/**
 * Convert a base64url string back to an ArrayBuffer.
 * Accepts standard base64 or base64url (with or without padding).
 * @param {string} base64
 * @returns {ArrayBuffer}
 */
export function base64ToArrayBuffer(base64) {
  let standard = base64.replace(/-/g, '+').replace(/_/g, '/');
  while (standard.length % 4) standard += '=';
  const binary = atob(standard);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ---------------------------------------------------------------------------
// Browser global (for script-tag usage without a bundler)
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined') {
  window.SecretVoidCrypto = {
    generateKey,
    encrypt,
    decrypt,
    exportKey,
    importKey,
    deriveKeyFromPassphrase,
    wrapKey,
    unwrapKey,
    generateShareUrl,
    extractKeyFromUrl,
    clearKeyFromUrl,
    arrayBufferToBase64,
    base64ToArrayBuffer
  };
}
