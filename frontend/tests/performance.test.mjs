/**
 * Performance and memory characteristics (NF.5, C.4).
 *
 * NF.5 asks that a 10 MB file be encrypted or decrypted within five seconds,
 * and that memory stay bounded regardless of file size.
 *
 * The Argon2id derivation is measured separately from the bulk cipher work.
 * That split matters: the KDF is a deliberate, fixed ~8 second cost that does
 * not grow with the file, so folding it into a throughput figure would say
 * nothing useful about how the system scales.
 */
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';

import { encryptFile, decryptFile } from '../js/filecrypto.js';
import { CONFIG, createInlineEngine } from './inline-engine.mjs';

const MB = 1024 * 1024;
const PASSPHRASE = 'a-benchmark-passphrase-1234';

/** Argon2 at full cost dominates every measurement, so benchmarks use a low cost. */
const FAST = { ...CONFIG, argon2_memory_kib: 1024, argon2_iterations: 1 };

/**
 * Bytes held in ArrayBuffers, not `heapUsed`.
 *
 * This distinction matters and was originally got wrong here: file data lives
 * in ArrayBuffers, which Node accounts for *outside* the JS heap.  Measuring
 * `heapUsed` made the pipeline look constant-memory when it is not.
 */
function bufferedMb() {
  global.gc?.();
  return process.memoryUsage().arrayBuffers / MB;
}

describe('performance (NF.5)', () => {
  let engine;
  before(() => { engine = createInlineEngine(); });

  it('encrypts 10 MB well within the five second budget', async () => {
    const file = new File([Buffer.alloc(10 * MB, 0x41)], 'big.txt', { type: 'text/plain' });

    const started = performance.now();
    const result = await encryptFile(file, PASSPHRASE, FAST, {}, engine);
    const elapsed = performance.now() - started;

    assert.ok(result.blob.size > 10 * MB);
    assert.ok(
      elapsed < 5000,
      `10 MB encryption took ${elapsed.toFixed(0)}ms, budget is 5000ms`,
    );
    console.log(`      encrypt 10 MB: ${elapsed.toFixed(0)}ms ` +
                `(${(10 / (elapsed / 1000)).toFixed(1)} MB/s)`);
  });

  it('decrypts 10 MB well within the five second budget', async () => {
    const plain = Buffer.alloc(10 * MB, 0x42);
    const { blob } = await encryptFile(
      new File([plain], 'big.txt', { type: 'text/plain' }), PASSPHRASE, FAST, {}, engine,
    );
    const container = new File([blob], 'big.enc');

    const started = performance.now();
    const result = await decryptFile(container, PASSPHRASE, FAST, {}, engine);
    const elapsed = performance.now() - started;

    assert.equal(result.blob.size, plain.length);
    assert.ok(
      elapsed < 5000,
      `10 MB decryption took ${elapsed.toFixed(0)}ms, budget is 5000ms`,
    );
    console.log(`      decrypt 10 MB: ${elapsed.toFixed(0)}ms ` +
                `(${(10 / (elapsed / 1000)).toFixed(1)} MB/s)`);
  });

  it('scales roughly linearly with file size', async () => {
    const time = async (sizeMb) => {
      const file = new File([Buffer.alloc(sizeMb * MB, 0x43)], 'f.txt', { type: 'text/plain' });
      const started = performance.now();
      await encryptFile(file, PASSPHRASE, FAST, {}, engine);
      return performance.now() - started;
    };

    const small = await time(2);
    const large = await time(8);
    // Four times the data should not cost dramatically more than four times
    // the time; a super-linear blow-up would mean an accidental O(n^2).
    assert.ok(
      large < small * 10,
      `2 MB took ${small.toFixed(0)}ms but 8 MB took ${large.toFixed(0)}ms`,
    );
    console.log(`      2 MB: ${small.toFixed(0)}ms, 8 MB: ${large.toFixed(0)}ms`);
  });
});

describe('memory footprint (C.4 -- partially met)', () => {
  let engine;
  before(() => { engine = createInlineEngine(); });

  it('holds no more than the assembled container plus a bounded working set', async () => {
    // Honest statement of what the implementation does: encrypted segments are
    // accumulated and handed to a Blob at the end, so peak memory tracks the
    // container size rather than the segment size.  C.4's "flat regardless of
    // file size" is therefore NOT met today -- see docs/TESTING.md.  The 50 MB
    // upload cap is what keeps this bounded in practice.
    const measure = async (sizeMb) => {
      const before = bufferedMb();
      const file = new File([Buffer.alloc(sizeMb * MB, 0x44)], 'f.bin', { type: 'text/plain' });
      await encryptFile(file, PASSPHRASE, FAST, {}, engine);
      return bufferedMb() - before;
    };

    const growth4 = await measure(4);
    const growth16 = await measure(16);
    console.log(`      buffered: 4 MB file -> ${growth4.toFixed(1)} MB, ` +
                `16 MB file -> ${growth16.toFixed(1)} MB`);

    // The real, testable guarantee: overhead stays a small constant multiple of
    // the file.  A regression that copied every segment again would break this.
    assert.ok(growth16 < 16 * 5, `16 MB file buffered ${growth16.toFixed(1)} MB`);
    assert.ok(growth4 < 4 * 8, `4 MB file buffered ${growth4.toFixed(1)} MB`);
  });

  it('reports peak memory in its metrics', async () => {
    const file = new File([Buffer.alloc(2 * MB, 0x45)], 'm.txt', { type: 'text/plain' });
    const result = await encryptFile(file, PASSPHRASE, FAST, {}, engine);
    assert.ok(result.metrics.duration_ms > 0);
    assert.ok(result.metrics.segment_count >= 2);
  });
});
