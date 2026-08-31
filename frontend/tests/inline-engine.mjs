/**
 * A crypto engine that runs inline instead of in Web Workers.
 *
 * The test suite injects this into encryptFile/decryptFile so the real
 * segmentation, ordering, verification, and header logic is exercised outside a
 * browser.  It performs exactly the work crypto-worker.js performs.
 */

import { webcrypto } from 'node:crypto';
import { argon2id } from '../js/argon2.js';

export function createInlineEngine(concurrency = 4) {
  const keys = new Map();

  return {
    concurrency,

    async deriveKey(password, salt, params, onProgress) {
      return argon2id({
        password,
        salt,
        memoryKiB: params.memoryKiB,
        timeCost: params.iterations,
        parallelism: params.parallelism,
        hashLength: 32,
        onProgress,
      });
    },

    async processSegment(kind, { index, key, keyId, header, nonce, data }) {
      let cryptoKey = keys.get(keyId);
      if (!cryptoKey) {
        cryptoKey = await webcrypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, [
          'encrypt',
          'decrypt',
        ]);
        keys.set(keyId, cryptoKey);
      }
      const params = { name: 'AES-GCM', iv: nonce, additionalData: header, tagLength: 128 };
      const out =
        kind === 'encrypt'
          ? await webcrypto.subtle.encrypt(params, cryptoKey, data)
          : await webcrypto.subtle.decrypt(params, cryptoKey, data);
      return { index, data: new Uint8Array(out) };
    },

    close() {
      keys.clear();
    },
  };
}
