/**
 * Tests for secretvoid-crypto
 *
 * Node 18+ exposes the Web Crypto API as a global `crypto` object, so no
 * polyfills or jsdom are needed for the crypto functions themselves.
 * window / history are mocked for the URL helper tests.
 */

import { jest } from '@jest/globals';
import {
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
  arrayBufferToBase64
} from '../src/index.js';

// ---------------------------------------------------------------------------
// Browser globals required by the URL helpers
// Set up in beforeAll so jest.fn() is available (ESM modules evaluate before
// Jest injects globals into the module scope).
// ---------------------------------------------------------------------------

beforeAll(() => {
  global.window = {
    location: {
      origin: 'https://secretvoid.com',
      hash: '',
      pathname: '/s/testid123'
    }
  };
  global.history = {
    replaceState: jest.fn()
  };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

// ---------------------------------------------------------------------------
// Core encrypt / decrypt
// ---------------------------------------------------------------------------

describe('encrypt / decrypt', () => {
  test('encrypt then decrypt returns original plaintext', async () => {
    const key = await generateKey();
    const plaintext = 'super secret value';
    const { payload, iv } = await encrypt(plaintext, key);
    const result = await decrypt(payload, iv, key);
    expect(result).toBe(plaintext);
  });

  test('two encryptions of the same plaintext produce different ciphertext', async () => {
    const key = await generateKey();
    const first = await encrypt('same plaintext', key);
    const second = await encrypt('same plaintext', key);
    expect(first.payload).not.toBe(second.payload);
  });

  test('IV is unique on every encrypt call', async () => {
    const key = await generateKey();
    const { iv: iv1 } = await encrypt('a', key);
    const { iv: iv2 } = await encrypt('a', key);
    expect(iv1).not.toBe(iv2);
  });

  test('wrong key fails and throws', async () => {
    const key1 = await generateKey();
    const key2 = await generateKey();
    const { payload, iv } = await encrypt('secret', key1);
    await expect(decrypt(payload, iv, key2)).rejects.toThrow();
  });

  test('tampered ciphertext throws an authentication error', async () => {
    const key = await generateKey();
    const { payload, iv } = await encrypt('secret', key);
    const tampered = payload.slice(0, -1) + (payload.slice(-1) === 'A' ? 'B' : 'A');
    await expect(decrypt(tampered, iv, key)).rejects.toThrow();
  });

  test('encrypts and decrypts a multiline secret correctly', async () => {
    const key = await generateKey();
    const secret = 'DB_PASSWORD=hunter2\nAPI_KEY=abc123\nSECRET_KEY=xyz789';
    const { payload, iv } = await encrypt(secret, key);
    expect(await decrypt(payload, iv, key)).toBe(secret);
  });

  test('encrypt returns payload and iv as strings', async () => {
    const key = await generateKey();
    const result = await encrypt('test', key);
    expect(typeof result.payload).toBe('string');
    expect(typeof result.iv).toBe('string');
  });
});

// ---------------------------------------------------------------------------
// Key export / import
// ---------------------------------------------------------------------------

describe('exportKey / importKey', () => {
  test('exported key reimports and decrypts correctly', async () => {
    const key = await generateKey();
    const plaintext = 'round-trip test';
    const { payload, iv } = await encrypt(plaintext, key);

    const exported = await exportKey(key);
    const reimported = await importKey(exported);
    expect(await decrypt(payload, iv, reimported)).toBe(plaintext);
  });

  test('exportKey returns a non-empty base64url string without +, /, or =', async () => {
    const exported = await exportKey(await generateKey());
    expect(typeof exported).toBe('string');
    expect(exported.length).toBeGreaterThan(0);
    expect(exported).not.toMatch(/[+/=]/);
  });

  test('two generated keys export to different strings', async () => {
    const k1 = await exportKey(await generateKey());
    const k2 = await exportKey(await generateKey());
    expect(k1).not.toBe(k2);
  });
});

// ---------------------------------------------------------------------------
// Passphrase protection — PBKDF2 + AES-KW
// ---------------------------------------------------------------------------

describe('deriveKeyFromPassphrase / wrapKey / unwrapKey', () => {
  test('correct passphrase unwraps the content key and decrypts successfully', async () => {
    const contentKey = await generateKey();
    const plaintext = 'passphrase-protected secret';
    const { payload, iv } = await encrypt(plaintext, contentKey);

    const salt = randomSalt();
    const passphraseKey = await deriveKeyFromPassphrase('correct-pass', salt);
    const wrapped = await wrapKey(contentKey, passphraseKey);

    const passphraseKey2 = await deriveKeyFromPassphrase('correct-pass', salt);
    const unwrapped = await unwrapKey(wrapped, passphraseKey2);
    expect(await decrypt(payload, iv, unwrapped)).toBe(plaintext);
  });

  test('wrong passphrase fails to unwrap the content key', async () => {
    const salt = randomSalt();
    const passphraseKey = await deriveKeyFromPassphrase('correct-pass', salt);
    const wrapped = await wrapKey(await generateKey(), passphraseKey);

    const wrongKey = await deriveKeyFromPassphrase('wrong-pass', salt);
    await expect(unwrapKey(wrapped, wrongKey)).rejects.toThrow();
  });

  test('wrapKey returns a non-empty base64url string without +, /, or =', async () => {
    const passphraseKey = await deriveKeyFromPassphrase('pass', randomSalt());
    const wrapped = await wrapKey(await generateKey(), passphraseKey);
    expect(typeof wrapped).toBe('string');
    expect(wrapped.length).toBeGreaterThan(0);
    expect(wrapped).not.toMatch(/[+/=]/);
  });

  test('base64url salt is accepted by deriveKeyFromPassphrase', async () => {
    const rawSalt = randomSalt();
    const saltB64 = arrayBufferToBase64(rawSalt.buffer);

    const passphraseKey = await deriveKeyFromPassphrase('pass', saltB64);
    const wrapped = await wrapKey(await generateKey(), passphraseKey);

    const passphraseKey2 = await deriveKeyFromPassphrase('pass', saltB64);
    const unwrapped = await unwrapKey(wrapped, passphraseKey2);
    expect(unwrapped).toBeTruthy();
  });

  test('different passphrases produce different derived keys', async () => {
    const salt = randomSalt();
    const contentKey = await generateKey();
    const k1 = await deriveKeyFromPassphrase('pass-one', salt);
    const wrapped = await wrapKey(contentKey, k1);

    const k2 = await deriveKeyFromPassphrase('pass-two', salt);
    await expect(unwrapKey(wrapped, k2)).rejects.toThrow();
  });
});

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

describe('generateShareUrl', () => {
  test('produces correct URL with id and key in fragment', async () => {
    const exported = await exportKey(await generateKey());
    const url = generateShareUrl('abc123', exported);
    expect(url).toBe(`https://secretvoid.com/secret/abc123#${exported}`);
  });

  test('fragment contains the exported key exactly', async () => {
    const exported = await exportKey(await generateKey());
    const url = generateShareUrl('xyz', exported);
    expect(url.split('#')[1]).toBe(exported);
  });
});

describe('extractKeyFromUrl', () => {
  test('reads hash from window.location correctly', () => {
    global.window.location.hash = '#abc123keyvalue';
    expect(extractKeyFromUrl()).toBe('abc123keyvalue');
  });

  test('returns null when hash is empty', () => {
    global.window.location.hash = '';
    expect(extractKeyFromUrl()).toBeNull();
  });
});

describe('clearKeyFromUrl', () => {
  test('calls history.replaceState with the current pathname', () => {
    global.history.replaceState.mockClear();
    global.window.location.pathname = '/s/testid123';
    clearKeyFromUrl();
    expect(global.history.replaceState).toHaveBeenCalledWith(null, '', '/s/testid123');
  });
});
