/**
 * Crypto worker.
 *
 * Runs the two expensive jobs off the main thread: the Argon2id key
 * derivation (module 0.2) and per-segment AES-256-GCM (modules 0.3 and 0.5).
 * Key material exists only inside worker memory for the life of one operation
 * and is never posted anywhere except back to the page that spawned it.
 */

import { argon2id } from './argon2.js';

let cachedKey = null;      // CryptoKey, reused across the segments of one job
let cachedKeyId = null;

async function importKey(raw, keyId) {
  if (cachedKey && cachedKeyId === keyId) return cachedKey;
  cachedKey = await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [
    'encrypt',
    'decrypt',
  ]);
  cachedKeyId = keyId;
  return cachedKey;
}

self.onmessage = async (event) => {
  const job = event.data;
  const { id, type } = job;

  try {
    if (type === 'derive') {
      const key = argon2id({
        password: job.password,
        salt: job.salt,
        memoryKiB: job.memoryKiB,
        timeCost: job.iterations,
        parallelism: job.parallelism,
        hashLength: 32,
        onProgress: (fraction) => self.postMessage({ id, type: 'progress', fraction }),
      });
      // The password bytes were transferred in; overwrite them before the
      // buffer is garbage collected.
      job.password.fill(0);
      self.postMessage({ id, type: 'result', key }, [key.buffer]);
      return;
    }

    if (type === 'encrypt' || type === 'decrypt') {
      const key = await importKey(job.key, job.keyId);
      const params = { name: 'AES-GCM', iv: job.nonce, additionalData: job.header, tagLength: 128 };
      const out =
        type === 'encrypt'
          ? await crypto.subtle.encrypt(params, key, job.data)
          : await crypto.subtle.decrypt(params, key, job.data);
      const bytes = new Uint8Array(out);
      self.postMessage({ id, type: 'result', index: job.index, data: bytes }, [bytes.buffer]);
      return;
    }

    if (type === 'release') {
      cachedKey = null;
      cachedKeyId = null;
      self.postMessage({ id, type: 'result' });
      return;
    }

    throw new Error(`Unknown job type: ${type}`);
  } catch (error) {
    // A failed AES-GCM decrypt means the tag did not verify.  The reason is
    // deliberately not distinguished here — see F.8.
    self.postMessage({
      id,
      type: 'error',
      message: error && error.message ? error.message : 'Worker job failed',
      failedIndex: job.index,
    });
  }
};
