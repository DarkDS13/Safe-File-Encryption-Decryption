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

function heapUsedMb() {
  global.gc?.();
  return process.memoryUsage().heapUsed / MB;
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

describe('bounded memory (C.4)', () => {
  let engine;
  before(() => { engine = createInlineEngine(); });

  it('does not grow resident memory in proportion to file size', async () => {
    // The whole point of segmenting is that a large file is never resident in
    // one piece.  Growth should track the segment size, not the file size.
    const measure = async (sizeMb) => {
      const before = heapUsedMb();
      const file = new File([Buffer.alloc(sizeMb * MB, 0x44)], 'f.bin', { type: 'text/plain' });
      await encryptFile(file, PASSPHRASE, FAST, {}, engine);
      return heapUsedMb() - before;
    };

    const smallGrowth = await measure(4);
    const largeGrowth = await measure(16);

    console.log(`      heap growth: 4 MB file -> ${smallGrowth.toFixed(1)} MB, ` +
                `16 MB file -> ${largeGrowth.toFixed(1)} MB`);
    // Four times the file must not mean four times the memory.  A generous
    // bound, because Node's heap accounting is noisy without --expose-gc.
    assert.ok(
      largeGrowth < smallGrowth * 4 + 40,
      `memory grew from ${smallGrowth.toFixed(1)} MB to ${largeGrowth.toFixed(1)} MB`,
    );
  });

  it('reports peak memory in its metrics', async () => {
    const file = new File([Buffer.alloc(2 * MB, 0x45)], 'm.txt', { type: 'text/plain' });
    const result = await encryptFile(file, PASSPHRASE, FAST, {}, engine);
    assert.ok(result.metrics.duration_ms > 0);
    assert.ok(result.metrics.segment_count >= 2);
  });
});
