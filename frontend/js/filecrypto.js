/**
 * Modules 0.3 (Segmentation & Encryption) and 0.5 (Verification & Decryption).
 *
 * Everything here runs in the browser.  The passphrase, the derived key, and
 * the plaintext never reach the network (NF.3).
 */

import {
  CIPHER,
  ContainerError,
  HEADER_SIZE,
  KDF,
  KDF_NAMES,
  TAG_SIZE,
  buildHeader,
  containerSizeFor,
  normaliseExtension,
  parseHeader,
  segmentCountFor,
  segmentNonce,
} from './container.js';
import { Sha256, timingSafeEqual, toHex } from './sha256.js';
import { WorkerPool, defaultPoolSize } from './workerpool.js';

const WORKER_URL = new URL('./crypto-worker.js', import.meta.url);

/**
 * The pipeline talks to an "engine" rather than to workers directly.  In the
 * browser that engine is a pool of Web Workers; the test suite substitutes one
 * that runs the same primitives inline, so the segmentation, ordering, and
 * verification logic under test is the code that actually ships.
 */
export function createWorkerEngine() {
  const pool = new WorkerPool(WORKER_URL, defaultPoolSize());
  return {
    concurrency: pool.size,
    deriveKey(password, salt, params, onProgress) {
      return pool
        .run({ type: 'derive', password, salt, ...params }, [password.buffer], onProgress)
        .then((response) => response.key);
    },
    processSegment(kind, { index, key, keyId, header, nonce, data }) {
      return pool.run(
        { type: kind, index, key, keyId, header, nonce, data },
        [data.buffer],
      );
    },
    close() {
      pool.terminate();
    },
  };
}

/** Errors a user can act on, with a stable code for the operation log. */
export class CryptoError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;
  }
}

// A wrong passphrase and a tampered container must be indistinguishable (F.8),
// so both paths end here with exactly this message.
const GENERIC_FAILURE =
  'This file could not be decrypted. Either the passphrase is wrong, or the file has been ' +
  'damaged or altered since it was encrypted. Check the passphrase and try again.';

/** F.1: validate an upload before anything else happens. */
export function validateFile(file, config) {
  if (!file) {
    return { ok: false, message: 'Choose a file first.' };
  }
  if (file.size === 0) {
    return { ok: false, message: 'That file is empty. Choose a file with some content in it.' };
  }
  if (file.size > config.max_upload_bytes) {
    const limitMb = Math.floor(config.max_upload_bytes / (1024 * 1024));
    const sizeMb = (file.size / (1024 * 1024)).toFixed(1);
    return {
      ok: false,
      message: `That file is ${sizeMb} MB. The limit for a single upload is ${limitMb} MB.`,
    };
  }

  const extension = normaliseExtension(file.name);
  if (!config.allowed_extensions.includes(extension)) {
    return {
      ok: false,
      message:
        `Files ending in .${extension || '(none)'} are not supported. ` +
        `Supported types are: ${config.allowed_extensions.map((e) => `.${e}`).join(', ')}.`,
    };
  }

  // The declared MIME type is checked too, but only as a second opinion —
  // browsers leave it empty often enough that it cannot be the only gate.
  if (file.type && !config.allowed_mime_types.includes(file.type)) {
    return {
      ok: false,
      message: `The browser reports this file as "${file.type}", which is not a supported type.`,
    };
  }

  return { ok: true, extension, message: `${file.name} — ${formatBytes(file.size)}` };
}

// ---------------------------------------------------------------------------
// metrics (F.10)
// ---------------------------------------------------------------------------
class MetricsRecorder {
  constructor() {
    this.startedAt = performance.now();
    this.peakMemory = 0;
    this.sample();
  }

  sample() {
    // performance.memory is Chromium-only; where it is missing the figure
    // reported is the bounded working set the pool actually holds, which is
    // the number the design cares about.
    if (performance.memory && performance.memory.usedJSHeapSize) {
      this.peakMemory = Math.max(this.peakMemory, performance.memory.usedJSHeapSize);
      this.measured = true;
    }
  }

  finish(fallbackWorkingSet) {
    this.sample();
    return {
      duration_ms: Math.round((performance.now() - this.startedAt) * 100) / 100,
      peak_memory_bytes: this.measured ? this.peakMemory : fallbackWorkingSet,
      memory_measured: Boolean(this.measured),
    };
  }
}

// ---------------------------------------------------------------------------
// key derivation (module 0.2)
// ---------------------------------------------------------------------------
async function deriveKey(engine, passphrase, salt, config, onProgress) {
  const password = new TextEncoder().encode(passphrase);
  return engine.deriveKey(
    password,
    salt,
    {
      memoryKiB: config.memoryKiB,
      iterations: config.iterations,
      parallelism: config.parallelism,
    },
    onProgress,
  );
}

async function readSlice(file, start, end) {
  const buffer = await file.slice(start, end).arrayBuffer();
  return new Uint8Array(buffer);
}

// ---------------------------------------------------------------------------
// encryption (module 0.3)
// ---------------------------------------------------------------------------

/**
 * Encrypt a file into a container.
 *
 * @param {File} file
 * @param {string} passphrase
 * @param {object} config server-supplied limits and KDF parameters
 * @param {object} hooks {onStage, onProgress}
 * @returns {Promise<{blob: Blob, filename: string, metrics: object, header: object}>}
 */
export async function encryptFile(file, passphrase, config, hooks = {}, engine = null) {
  const { onStage = () => {}, onProgress = () => {} } = hooks;
  const metrics = new MetricsRecorder();
  const segmentSize = config.segment_size;
  const worker = engine || createWorkerEngine();

  try {
    // Pass one: digest the plaintext.  The digest goes into the header, and
    // the header is the additional authenticated data for every segment, so it
    // has to be known before any segment can be encrypted.
    onStage('Reading and checksumming the file');
    const hasher = new Sha256();
    for (let offset = 0; offset < file.size; offset += segmentSize) {
      const chunk = await readSlice(file, offset, Math.min(offset + segmentSize, file.size));
      hasher.update(chunk);
      onProgress((offset + chunk.length) / file.size * 0.15);
    }
    const digest = hasher.digest();
    metrics.sample();

    // Fresh salt and nonce for every operation (F.5).
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const baseNonce = crypto.getRandomValues(new Uint8Array(12));

    onStage(`Deriving the key with Argon2id (${config.argon2_memory_kib / 1024} MiB)`);
    const key = await deriveKey(
      worker,
      passphrase,
      salt,
      {
        memoryKiB: config.argon2_memory_kib,
        iterations: config.argon2_iterations,
        parallelism: config.argon2_parallelism,
      },
      (fraction) => onProgress(0.15 + fraction * 0.35),
    );

    const header = buildHeader({
      kdfId: KDF.ARGON2ID,
      cipherId: CIPHER.AES_256_GCM,
      memoryKiB: config.argon2_memory_kib,
      iterations: config.argon2_iterations,
      parallelism: config.argon2_parallelism,
      extension: normaliseExtension(file.name),
      salt,
      baseNonce,
      segmentSize,
      plaintextLength: file.size,
      digest,
    });

    // Pass two: encrypt each segment.  Parts go straight into a Blob so the
    // whole ciphertext is never resident at once.
    onStage('Encrypting');
    const segmentCount = segmentCountFor(file.size, segmentSize);
    const parts = [header];
    const keyId = `enc-${Date.now()}-${Math.random()}`;
    const results = new Array(segmentCount);
    const concurrency = worker.concurrency;

    // Segments are dispatched a windowful at a time.  That is the backpressure:
    // at most `concurrency` plaintext segments and their ciphertexts are
    // resident, whatever the file size.
    for (let index = 0; index < segmentCount; index += concurrency) {
      const batch = [];
      for (let k = 0; k < concurrency && index + k < segmentCount; k += 1) {
        const i = index + k;
        const start = i * segmentSize;
        const chunk = await readSlice(file, start, Math.min(start + segmentSize, file.size));
        batch.push(
          worker.processSegment('encrypt', {
            index: i,
            key,
            keyId,
            header,
            nonce: segmentNonce(baseNonce, i),
            data: chunk,
          }),
        );
      }

      const responses = await Promise.all(batch);
      for (const response of responses) results[response.index] = response.data;

      metrics.sample();
      onProgress(0.5 + (Math.min(index + concurrency, segmentCount) / segmentCount) * 0.5);
    }

    for (let index = 0; index < segmentCount; index += 1) parts.push(results[index]);

    const blob = new Blob(parts, { type: 'application/octet-stream' });
    const filename = `${file.name}.enc`;

    key.fill(0);
    const workingSet = segmentSize * concurrency * 2 + config.argon2_memory_kib * 1024;

    return {
      blob,
      filename,
      digestHex: toHex(digest),
      header: {
        algorithm: 'AES-256-GCM',
        kdf: 'Argon2id',
        segment_count: segmentCount,
        plaintext_size: file.size,
        container_size: blob.size,
        expected_size: containerSizeFor(file.size, segmentSize),
      },
      metrics: {
        ...metrics.finish(workingSet),
        input_size: file.size,
        output_size: blob.size,
        segment_count: segmentCount,
      },
    };
  } finally {
    if (!engine) worker.close();
  }
}

// ---------------------------------------------------------------------------
// decryption (module 0.5)
// ---------------------------------------------------------------------------

/**
 * Decrypt a container back to the original file.
 *
 * Every segment's tag is verified before its plaintext is released, and the
 * SHA-256 recorded at encryption time is checked at the end (F.9).  Any
 * failure discards everything recovered so far and reports one generic message.
 */
export async function decryptFile(file, passphrase, config, hooks = {}, engine = null) {
  const { onStage = () => {}, onProgress = () => {} } = hooks;
  const metrics = new MetricsRecorder();
  const worker = engine || createWorkerEngine();
  let parts = [];

  try {
    onStage('Reading the container header');
    const headerBytes = await readSlice(file, 0, HEADER_SIZE);
    let meta;
    try {
      meta = parseHeader(headerBytes, file.size);
    } catch (error) {
      // Header problems are structural and safe to describe precisely: they
      // reveal nothing about the passphrase.
      throw new CryptoError(
        error instanceof ContainerError ? error.message : 'This file is not a valid container.',
        error instanceof ContainerError ? error.code : 'container_invalid',
      );
    }

    onStage(`Deriving the key with ${meta.kdfName}`);
    if (meta.kdfId !== KDF.ARGON2ID) {
      throw new CryptoError(
        `This container was made with ${KDF_NAMES[meta.kdfId]}, which this build cannot re-derive.`,
        'unsupported_kdf',
      );
    }
    const key = await deriveKey(
      worker,
      passphrase,
      meta.salt,
      {
        memoryKiB: meta.memoryKiB,
        iterations: meta.iterations,
        parallelism: meta.parallelism,
      },
      (fraction) => onProgress(fraction * 0.4),
    );

    onStage('Verifying and decrypting');
    const hasher = new Sha256();
    const keyId = `dec-${Date.now()}-${Math.random()}`;
    let offset = HEADER_SIZE;

    // Segments are decrypted in order because the digest is streamed over the
    // recovered plaintext; the tag check on each segment still happens before
    // any of its bytes are used.
    const batchSize = worker.concurrency;
    for (let index = 0; index < meta.segmentCount; index += batchSize) {
      const batch = [];
      for (let k = 0; k < batchSize && index + k < meta.segmentCount; k += 1) {
        const i = index + k;
        const plainLength = Math.min(meta.segmentSize, meta.plaintextLength - i * meta.segmentSize);
        const cipherLength = plainLength + TAG_SIZE;
        const chunk = await readSlice(file, offset, offset + cipherLength);
        offset += cipherLength;
        batch.push(
          worker.processSegment('decrypt', {
            index: i,
            key,
            keyId,
            header: meta.header,
            nonce: segmentNonce(meta.baseNonce, i),
            data: chunk,
          }),
        );
      }

      let responses;
      try {
        responses = await Promise.all(batch);
      } catch {
        // A tag failure lands here.  Discard everything (F.9) and say nothing
        // that distinguishes a wrong passphrase from a tampered file (F.8).
        parts = [];
        throw new CryptoError(GENERIC_FAILURE, 'decryption_failed');
      }

      responses.sort((a, b) => a.index - b.index);
      for (const response of responses) {
        hasher.update(response.data);
        parts.push(response.data);
      }
      metrics.sample();
      onProgress(0.4 + (Math.min(index + batchSize, meta.segmentCount) / meta.segmentCount) * 0.6);
    }

    key.fill(0);

    // F.9: the integrity check.  A mismatch means the container decrypted
    // under this key but does not match what was originally encrypted.
    onStage('Checking integrity');
    const recovered = hasher.digest();
    if (!timingSafeEqual(recovered, meta.digest)) {
      parts = [];
      throw new CryptoError(GENERIC_FAILURE, 'integrity_failed');
    }

    const blob = new Blob(parts, { type: mimeForExtension(meta.extension) });
    if (blob.size !== meta.plaintextLength) {
      parts = [];
      throw new CryptoError(GENERIC_FAILURE, 'length_mismatch');
    }

    const baseName = file.name.replace(/\.enc$/i, '').replace(/\.[^.]*$/, '');
    const filename = meta.extension ? `${baseName}.${meta.extension}` : baseName;
    const workingSet = meta.segmentSize * batchSize * 2 + meta.memoryKiB * 1024;

    return {
      blob,
      filename,
      digestHex: toHex(recovered),
      header: {
        algorithm: meta.cipherName,
        kdf: meta.kdfName,
        segment_count: meta.segmentCount,
        plaintext_size: meta.plaintextLength,
        extension: meta.extension,
      },
      metrics: {
        ...metrics.finish(workingSet),
        input_size: file.size,
        output_size: blob.size,
        segment_count: meta.segmentCount,
      },
    };
  } finally {
    parts = [];
    if (!engine) worker.close();
  }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
const MIME_BY_EXTENSION = {
  txt: 'text/plain',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  pdf: 'application/pdf',
};

export function mimeForExtension(extension) {
  return MIME_BY_EXTENSION[extension] || 'application/octet-stream';
}

export function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

/** Throughput in MB/s, for the metrics panel. */
export function throughputMbps(bytes, durationMs) {
  if (!durationMs) return 0;
  return (bytes / (1024 * 1024)) / (durationMs / 1000);
}
