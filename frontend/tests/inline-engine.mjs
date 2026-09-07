/**
 * A crypto engine that runs inline instead of in Web Workers.
 *
 * The test suite injects this into encryptFile/decryptFile so the real
 * segmentation, ordering, verification, and header logic is exercised outside a
 * browser.  It performs exactly the work crypto-worker.js performs.
 */

import { webcrypto } from 'node:crypto';
import { argon2id } from '../js/argon2.js';

/**
 * Test-scale client configuration.
 *
 * The KDF cost is deliberately tiny: the RFC vectors pin the algorithm itself,
 * so the round-trip and performance suites only need *a* key, not an expensive
 * one.  Shared by every frontend suite so they cannot drift apart.
 */
export const CONFIG = {
  max_upload_bytes: 50 * 1024 * 1024,
  segment_size: 64 * 1024,
  allowed_extensions: ['txt', 'png', 'jpg', 'jpeg', 'pdf'],
  allowed_mime_types: ['text/plain', 'image/png', 'image/jpeg', 'application/pdf'],
  argon2_memory_kib: 64,
  argon2_iterations: 1,
  argon2_parallelism: 1,
};

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
