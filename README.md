# secretvoid-crypto

Client-side zero-knowledge AES-256-GCM encryption module. Web Crypto API only — no dependencies, works in any modern browser and Node.js 18+.

Part of [**SecretVoid**](https://secretvoid.com) — self-destructing secret sharing with dual-layer encryption. Share passwords, API keys, and credentials via links that destroy themselves. **[Try it at secretvoid.com →](https://secretvoid.com)**

## How it works

Secrets are encrypted entirely in the browser before touching the server. The encryption key lives only in the URL fragment (`#key`) — the HTTP spec guarantees fragments are never transmitted, so the server receives only encrypted gibberish and is mathematically incapable of decrypting it.

```text
Sender browser                          Server                    Recipient browser
──────────────────────────────────────────────────────────────────────────────────
generate key (never leaves browser)
encrypt(secret, key) → ciphertext
POST { ciphertext }              →      store ciphertext
                                        return { id }
construct URL: /s/{id}#{key}
share URL out-of-band            →                        →      open /s/{id}#{key}
                                        GET /s/{id}       →
                                 ←      return ciphertext
                                                                 key = fragment (#key)
                                                                 decrypt(ciphertext, key)
                                                                 → plaintext ✓
```

## Installation

```bash
npm install secretvoid-crypto
```

## Usage

### ES module (browser or Node.js 18+)

```js
import { generateKey, encrypt, decrypt, exportKey, importKey, generateShareUrl, extractKeyFromUrl, clearKeyFromUrl } from 'secretvoid-crypto';

// --- Sender side ---

// 1. Generate a random AES-256-GCM key
const key = await generateKey();

// 2. Encrypt the secret locally
const { payload, iv } = await encrypt('my API key: sk-abc123', key);

// 3. POST { payload, iv } to your server — server stores the blob, returns an id
const { id } = await fetch('/api/secrets', {
  method: 'POST',
  body: JSON.stringify({ payload, iv, expiresIn: 86400 })
}).then(r => r.json());

// 4. Export key to base64url and build the share URL
const exportedKey = await exportKey(key);
const shareUrl = generateShareUrl(id, exportedKey);
// → https://secretvoid.com/s/abc123#base64urlKey
// The fragment (#base64urlKey) is never sent to the server


// --- Recipient side ---

// 1. Extract the key from the URL fragment
const keyStr = extractKeyFromUrl();  // reads window.location.hash
const key = await importKey(keyStr);

// 2. Fetch the encrypted blob from the server (fragment not transmitted)
const { payload, iv } = await fetch(`/api/secrets/${id}`).then(r => r.json());

// 3. Decrypt entirely in the browser
const plaintext = await decrypt(payload, iv, key);

// 4. Clear the key from browser history
clearKeyFromUrl();
```

### Script tag (no bundler)

```html
<script type="module">
  import { generateKey, encrypt } from 'https://cdn.jsdelivr.net/npm/secretvoid-crypto/src/index.js';

  const key = await generateKey();
  const { payload, iv } = await encrypt('secret', key);
</script>
```

Or load it as a classic script for `window.SecretVoidCrypto` access — see [Browser global](#browser-global) below.

### Password protection

Add a second layer: the content key is wrapped with a password-derived key (PBKDF2, 100,000 iterations, SHA-256). The password is never sent anywhere.

```js
import {
  generateKey, encrypt, decrypt,
  exportKey, wrapKey, unwrapKey,
  deriveKeyFromPassword
} from 'secretvoid-crypto';

// --- Sender side ---
const contentKey = await generateKey();
const { payload, iv } = await encrypt('secret', contentKey);

// Derive a wrapping key from the password
const salt = crypto.getRandomValues(new Uint8Array(16));
const passwordKey = await deriveKeyFromPassword('correct-horse-battery', salt);
const wrappedKey = await wrapKey(contentKey, passwordKey);

// Store: { payload, iv, wrappedKey, salt } on the server
// The recipient needs the password to unwrap the content key


// --- Recipient side ---
const passwordKey = await deriveKeyFromPassword('correct-horse-battery', salt);
const contentKey = await unwrapKey(wrappedKey, passwordKey);
const plaintext = await decrypt(payload, iv, contentKey);
```

## API

### Core encryption

#### `generateKey() → Promise<CryptoKey>`

Generates a random extractable AES-256-GCM key. This key should be exported and placed in the URL fragment — never sent to the server.

#### `encrypt(text, key) → Promise<{ payload: string, iv: string }>`

Encrypts a plaintext string. Returns `payload` (ciphertext) and `iv` as base64url strings. A fresh random 12-byte IV is generated on every call.

| Param | Type | Description |
| --- | --- | --- |
| `text` | `string` | Plaintext to encrypt |
| `key` | `CryptoKey` | AES-GCM key from `generateKey()` or `importKey()` |

#### `decrypt(payload, iv, key) → Promise<string>`

Decrypts ciphertext back to plaintext. Throws if the key is wrong or the data is tampered.

| Param | Type | Description |
| --- | --- | --- |
| `payload` | `string` | base64url ciphertext from `encrypt()` |
| `iv` | `string` | base64url IV from `encrypt()` |
| `key` | `CryptoKey` | AES-GCM key |

### Key serialisation

#### `exportKey(key) → Promise<string>`

Exports a `CryptoKey` to a base64url string — safe to embed in a URL fragment. No `+`, `/`, or `=` characters.

#### `importKey(base64Key) → Promise<CryptoKey>`

Imports a base64url key string back to a `CryptoKey` for decryption.

### URL helpers

#### `generateShareUrl(id, exportedKey) → string`

Builds the share URL. The key goes in the fragment (`#`) so it is never transmitted to the server.

```text
https://secretvoid.com/s/{id}#{exportedKey}
```

Falls back to `https://secretvoid.com` as origin when called outside a browser.

#### `extractKeyFromUrl() → string | null`

Reads the key from `window.location.hash`. Returns `null` if the fragment is absent.

#### `clearKeyFromUrl()`

Calls `history.replaceState` to remove the key from the URL bar and browser history after decryption. Prevents the key from appearing in referrer headers or history sniffing.

### Password derivation

#### `deriveKeyFromPassword(password, salt) → Promise<CryptoKey>`

Derives an AES-256-KW key from a password using PBKDF2 (100,000 iterations, SHA-256). The salt must be stored alongside the wrapped key so the recipient can re-derive the same wrapping key.

| Param | Type | Description |
| --- | --- | --- |
| `password` | `string` | User-supplied password |
| `salt` | `Uint8Array \| ArrayBuffer \| string` | Random salt (or base64url string) |

#### `wrapKey(contentKey, passwordKey) → Promise<string>`

Wraps (encrypts) a content key using an AES-KW password-derived key. Returns a base64url string.

#### `unwrapKey(wrappedKeyBase64, passwordKey) → Promise<CryptoKey>`

Unwraps a content key. Throws if the password is incorrect.

### Utilities

#### `arrayBufferToBase64(buffer) → string`

Converts an `ArrayBuffer` to a base64url string (URL-safe, no padding).

#### `base64ToArrayBuffer(base64) → ArrayBuffer`

Converts a base64url string back to an `ArrayBuffer`. Accepts standard base64 or base64url, with or without padding.

## Browser global

When loaded via a classic `<script>` tag (no bundler), all functions are available on `window.SecretVoidCrypto`:

```html
<script src="node_modules/secretvoid-crypto/src/index.js" type="module"></script>
<script>
  // Only available after the module loads — use defer or DOMContentLoaded
  const key = await window.SecretVoidCrypto.generateKey();
</script>
```

## Security properties

- **AES-256-GCM** — authenticated encryption. Tampered ciphertext throws before any data is returned.
- **Zero knowledge** — the server receives only the encrypted blob. The key lives exclusively in the URL fragment, which the HTTP spec (`RFC 7230`) guarantees is never transmitted.
- **Unique IV per encryption** — random 12-byte IV generated for every `encrypt()` call. Reusing an IV with the same key is catastrophic for AES-GCM; this module never does it.
- **Password derivation** — PBKDF2 with 100,000 iterations and SHA-256. The password never leaves the browser.
- **No dependencies** — the Web Crypto API is built into every modern browser and Node.js 18+. No supply chain to compromise.
- **Fragment cleared after decrypt** — call `clearKeyFromUrl()` after decryption to prevent the key lingering in browser history or referrer headers.

### Honest limitations

This module cannot protect against:

- A device compromised by malware or a keylogger — the secret is captured before encryption occurs
- Someone watching the screen when the secret is displayed
- The recipient's device being compromised

These limitations apply to every encryption tool. If the device is infected, no software can help.

## Requirements

- **Browser:** any browser with [Web Crypto API support](https://caniuse.com/cryptography) (all modern browsers)
- **Node.js:** 18+ (Web Crypto API available as a global `crypto` object)

## License

MIT — see [LICENSE](LICENSE)
