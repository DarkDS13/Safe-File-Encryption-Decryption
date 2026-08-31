/**
 * Frontend cryptography test suite.
 *
 * Run with:  node --test frontend/tests/
 *
 * Covers NF.4: for every supported file type, encryption followed by
 * decryption with the correct passphrase returns a file bit-identical to the
 * original.  Also covers the failure paths that must stay indistinguishable
 * (F.8) and the integrity check that must catch tampering (F.9).
 */

import assert from 'node:assert/strict';
import { createHash, webcrypto } from 'node:crypto';
import test, { describe } from 'node:test';

import { Blake2b, blake2b } from '../js/blake2b.js';
import { Sha256, sha256, timingSafeEqual, toHex } from '../js/sha256.js';
import { argon2, ARGON2_D, ARGON2_I, ARGON2_ID } from '../js/argon2.js';
import {
  ContainerError, HEADER_SIZE, buildHeader, containerSizeFor, normaliseExtension, parseHeader,
  segmentNonce,
} from '../js/container.js';
import { decryptFile, encryptFile, validateFile } from '../js/filecrypto.js';
import { createInlineEngine } from './inline-engine.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const fill = (n, v) => new Uint8Array(n).fill(v);
const hex = (b) => Buffer.from(b).toString('hex');

// Test-scale KDF parameters.  The RFC vectors below pin the algorithm itself;
// the round-trip tests only need a key, not an expensive one.
const CONFIG = {
  max_upload_bytes: 50 * 1024 * 1024,
  segment_size: 64 * 1024,
  allowed_extensions: ['txt', 'png', 'jpg', 'jpeg', 'pdf'],
  allowed_mime_types: ['text/plain', 'image/png', 'image/jpeg', 'application/pdf'],
  argon2_memory_kib: 64,
  argon2_iterations: 1,
  argon2_parallelism: 1,
};

// ===========================================================================
describe('SHA-256', () => {
  test('matches the reference implementation', () => {
    for (const input of ['', 'abc', 'a'.repeat(55), 'a'.repeat(56), 'a'.repeat(64), 'x'.repeat(9999)]) {
      assert.equal(
        toHex(sha256(new TextEncoder().encode(input))),
        createHash('sha256').update(input).digest('hex'),
        `digest mismatch for input of length ${input.length}`,
      );
    }
  });

  test('streams identically to a single-shot digest', () => {
    const data = Buffer.from(Array.from({ length: 200000 }, (_, i) => i % 251));
    for (const chunkSize of [1, 7, 64, 4096, 65536]) {
      const hasher = new Sha256();
      for (let i = 0; i < data.length; i += chunkSize) {
        hasher.update(new Uint8Array(data.subarray(i, i + chunkSize)));
      }
      assert.equal(toHex(hasher.digest()), createHash('sha256').update(data).digest('hex'));
    }
  });

  test('constant-time comparison agrees with equality', () => {
    const a = sha256(new TextEncoder().encode('one'));
    const b = sha256(new TextEncoder().encode('one'));
    const c = sha256(new TextEncoder().encode('two'));
    assert.equal(timingSafeEqual(a, b), true);
    assert.equal(timingSafeEqual(a, c), false);
    assert.equal(timingSafeEqual(a, a.slice(0, 31)), false);
  });
});

// ===========================================================================
describe('BLAKE2b', () => {
  test('matches RFC 7693 and the reference implementation', () => {
    assert.equal(
      hex(blake2b(new TextEncoder().encode('abc'), 64)),
      'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1'
        + '7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923',
    );
    for (const input of ['', 'abc', 'a'.repeat(127), 'a'.repeat(128), 'a'.repeat(129)]) {
      assert.equal(
        hex(blake2b(new TextEncoder().encode(input), 64)),
        createHash('blake2b512').update(input).digest('hex'),
      );
    }
  });

  test('supports keyed hashing and short digests', () => {
    const keyed = new Blake2b(32, fill(32, 9)).update(new TextEncoder().encode('abc')).digest();
    assert.equal(keyed.length, 32);
    assert.notEqual(hex(keyed), hex(blake2b(new TextEncoder().encode('abc'), 32)));
  });
});

// ===========================================================================
describe('Argon2 (RFC 9106)', () => {
  const common = {
    password: fill(32, 1), salt: fill(16, 2), secret: fill(8, 3), associatedData: fill(12, 4),
    timeCost: 3, memoryKiB: 32, parallelism: 4, hashLength: 32,
  };

  test('section 5.1 — Argon2d', () => {
    assert.equal(
      hex(argon2({ ...common, type: ARGON2_D })),
      '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
    );
  });

  test('section 5.2 — Argon2i', () => {
    assert.equal(
      hex(argon2({ ...common, type: ARGON2_I })),
      'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
    );
  });

  test('section 5.3 — Argon2id', () => {
    assert.equal(
      hex(argon2({ ...common, type: ARGON2_ID })),
      '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
    );
  });

  test('is deterministic and salt-dependent', () => {
    const base = { password: new TextEncoder().encode('passphrase'), memoryKiB: 64, timeCost: 1, parallelism: 1 };
    const a = argon2({ ...base, salt: fill(16, 1) });
    const b = argon2({ ...base, salt: fill(16, 1) });
    const c = argon2({ ...base, salt: fill(16, 2) });
    assert.equal(hex(a), hex(b), 'same inputs must give the same key');
    assert.notEqual(hex(a), hex(c), 'a different salt must give a different key');
  });

  test('rejects parameters that are out of range', () => {
    const base = { password: new TextEncoder().encode('x'), salt: fill(16, 1) };
    assert.throws(() => argon2({ ...base, salt: fill(4, 1) }), /salt/);
    assert.throws(() => argon2({ ...base, timeCost: 0 }), /timeCost/);
    assert.throws(() => argon2({ ...base, memoryKiB: 2 }), /memoryKiB/);
  });
});

// ===========================================================================
describe('container format', () => {
  const template = {
    memoryKiB: 65536, iterations: 3, parallelism: 1, extension: 'report.pdf',
    salt: fill(16, 1), baseNonce: fill(12, 2), segmentSize: 1048576,
    plaintextLength: 3_000_000, digest: fill(32, 3),
  };

  test('round-trips every header field', () => {
    const header = buildHeader(template);
    assert.equal(header.length, HEADER_SIZE);
    const parsed = parseHeader(header, containerSizeFor(3_000_000, 1048576));
    assert.equal(parsed.extension, 'pdf');
    assert.equal(parsed.memoryKiB, 65536);
    assert.equal(parsed.iterations, 3);
    assert.equal(parsed.plaintextLength, 3_000_000);
    assert.equal(parsed.segmentCount, 3);
    assert.equal(parsed.kdfName, 'Argon2id');
    assert.equal(parsed.cipherName, 'AES-256-GCM');
    assert.equal(hex(parsed.digest), hex(fill(32, 3)));
  });

  test('rejects a file that is not a container', () => {
    assert.throws(
      () => parseHeader(new Uint8Array(200), 200),
      (e) => e instanceof ContainerError && e.code === 'not_a_container',
    );
  });

  test('rejects an unknown format version', () => {
    const header = buildHeader(template);
    header[4] = 99;
    assert.throws(() => parseHeader(header), (e) => e.code === 'unsupported_version');
  });

  test('rejects a container whose length disagrees with its header', () => {
    assert.throws(
      () => parseHeader(buildHeader(template), 500),
      (e) => e.code === 'size_mismatch',
    );
  });

  test('rejects a truncated header', () => {
    assert.throws(() => parseHeader(new Uint8Array(40), 40), /too short/);
  });

  test('gives every segment a distinct nonce', () => {
    const seen = new Set();
    for (let i = 0; i < 1000; i += 1) seen.add(hex(segmentNonce(fill(12, 5), i)));
    assert.equal(seen.size, 1000);
  });

  test('normalises extensions safely', () => {
    assert.equal(normaliseExtension('a/b/report.PDF'), 'pdf');
    assert.equal(normaliseExtension('archive.tar.gz'), 'gz');
    assert.equal(normaliseExtension('no-extension'), 'noextension');
    assert.equal(normaliseExtension('x.' + 'y'.repeat(50)).length, 14);
  });
});

// ===========================================================================
describe('file validation (F.1)', () => {
  const asFile = (name, size, type) => new File([new Uint8Array(size)], name, { type });

  test('accepts every supported type', () => {
    for (const [name, type] of [
      ['a.txt', 'text/plain'], ['b.png', 'image/png'],
      ['c.jpg', 'image/jpeg'], ['d.pdf', 'application/pdf'],
    ]) {
      assert.equal(validateFile(asFile(name, 100, type), CONFIG).ok, true, `${name} was refused`);
    }
  });

  test('refuses an unsupported extension', () => {
    const result = validateFile(asFile('virus.exe', 100, ''), CONFIG);
    assert.equal(result.ok, false);
    assert.match(result.message, /not supported/);
  });

  test('refuses an oversized file and names the limit', () => {
    const result = validateFile(asFile('big.pdf', 60 * 1024 * 1024, 'application/pdf'), CONFIG);
    assert.equal(result.ok, false);
    assert.match(result.message, /50 MB/);
  });

  test('refuses an empty file', () => {
    assert.equal(validateFile(asFile('empty.txt', 0, 'text/plain'), CONFIG).ok, false);
  });

  test('refuses a mismatched MIME type', () => {
    const result = validateFile(asFile('a.txt', 10, 'application/x-msdownload'), CONFIG);
    assert.equal(result.ok, false);
  });
});

// ===========================================================================
describe('encrypt / decrypt round trip (NF.4)', () => {
  const PASSPHRASE = 'a-long-enough-test-passphrase';

  /** Representative content for each supported type, including real magic bytes. */
  const samples = {
    'notes.txt': Buffer.from('The quick brown fox jumps over the lazy dog.\n'.repeat(500)),
    'image.png': Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      Buffer.from(Array.from({ length: 40000 }, (_, i) => (i * 7) % 256)),
    ]),
    'photo.jpg': Buffer.concat([
      Buffer.from([0xff, 0xd8, 0xff, 0xe0]),
      Buffer.from(Array.from({ length: 30000 }, (_, i) => (i * 13) % 256)),
    ]),
    'report.pdf': Buffer.concat([
      Buffer.from('%PDF-1.7\n'),
      Buffer.from(Array.from({ length: 90000 }, (_, i) => (i * 3) % 256)),
    ]),
  };

  for (const [name, content] of Object.entries(samples)) {
    test(`${name} comes back byte for byte`, async () => {
      const engine = createInlineEngine(2);
      const original = new File([content], name);

      const encrypted = await encryptFile(original, PASSPHRASE, CONFIG, {}, engine);
      assert.equal(encrypted.blob.size, encrypted.header.expected_size);
      assert.equal(encrypted.digestHex, createHash('sha256').update(content).digest('hex'));

      // The container must not contain the plaintext anywhere in it.
      const sealed = Buffer.from(await encrypted.blob.arrayBuffer());
      assert.equal(sealed.includes(content.subarray(0, 64)), false, 'plaintext leaked into the container');

      const container = new File([encrypted.blob], encrypted.filename);
      const decrypted = await decryptFile(container, PASSPHRASE, CONFIG, {}, engine);

      const recovered = Buffer.from(await decrypted.blob.arrayBuffer());
      assert.equal(recovered.length, content.length);
      assert.ok(recovered.equals(content), `${name} did not survive the round trip`);
      assert.equal(decrypted.filename, name);
      assert.equal(decrypted.digestHex, encrypted.digestHex);
      engine.close();
    });
  }

  test('a file spanning many segments round-trips', async () => {
    const engine = createInlineEngine(3);
    // 260 KB against a 64 KB segment size: five segments, the last one partial.
    const content = Buffer.from(Array.from({ length: 266_240 }, (_, i) => (i * 31) % 256));
    const encrypted = await encryptFile(new File([content], 'multi.pdf'), PASSPHRASE, CONFIG, {}, engine);
    assert.equal(encrypted.header.segment_count, 5);

    const decrypted = await decryptFile(
      new File([encrypted.blob], encrypted.filename), PASSPHRASE, CONFIG, {}, engine,
    );
    assert.ok(Buffer.from(await decrypted.blob.arrayBuffer()).equals(content));
    engine.close();
  });

  test('a single-byte file round-trips', async () => {
    const engine = createInlineEngine(1);
    const content = Buffer.from([0x42]);
    const encrypted = await encryptFile(new File([content], 'tiny.txt'), PASSPHRASE, CONFIG, {}, engine);
    assert.equal(encrypted.header.segment_count, 1);
    const decrypted = await decryptFile(
      new File([encrypted.blob], encrypted.filename), PASSPHRASE, CONFIG, {}, engine,
    );
    assert.ok(Buffer.from(await decrypted.blob.arrayBuffer()).equals(content));
    engine.close();
  });

  test('a file exactly one segment long round-trips', async () => {
    const engine = createInlineEngine(2);
    const content = Buffer.alloc(CONFIG.segment_size, 0xab);
    const encrypted = await encryptFile(new File([content], 'exact.txt'), PASSPHRASE, CONFIG, {}, engine);
    assert.equal(encrypted.header.segment_count, 1);
    const decrypted = await decryptFile(
      new File([encrypted.blob], encrypted.filename), PASSPHRASE, CONFIG, {}, engine,
    );
    assert.ok(Buffer.from(await decrypted.blob.arrayBuffer()).equals(content));
    engine.close();
  });

  test('the same file encrypted twice gives different ciphertext', async () => {
    const engine = createInlineEngine(2);
    const content = Buffer.from('identical content'.repeat(100));
    const first = await encryptFile(new File([content], 'a.txt'), PASSPHRASE, CONFIG, {}, engine);
    const second = await encryptFile(new File([content], 'a.txt'), PASSPHRASE, CONFIG, {}, engine);
    const a = Buffer.from(await first.blob.arrayBuffer());
    const b = Buffer.from(await second.blob.arrayBuffer());
    assert.equal(a.equals(b), false, 'a fresh salt and nonce must change the ciphertext');
    engine.close();
  });

  test('metrics are recorded for every operation (F.10)', async () => {
    const engine = createInlineEngine(2);
    const stages = [];
    const progress = [];
    const encrypted = await encryptFile(
      new File([Buffer.alloc(100_000, 7)], 'm.txt'), PASSPHRASE, CONFIG,
      { onStage: (s) => stages.push(s), onProgress: (f) => progress.push(f) }, engine,
    );
    assert.ok(encrypted.metrics.duration_ms > 0);
    assert.equal(encrypted.metrics.input_size, 100_000);
    assert.ok(encrypted.metrics.output_size > 100_000);
    assert.ok(encrypted.metrics.peak_memory_bytes > 0);
    assert.equal(encrypted.metrics.segment_count, 2);
    assert.ok(stages.length >= 3, 'the user should be told what stage it is at');
    assert.ok(progress.at(-1) >= 0.99, 'progress should reach completion');
    engine.close();
  });
});

// ===========================================================================
describe('failure paths (F.8, F.9)', () => {
  const PASSPHRASE = 'the-right-passphrase';
  const content = Buffer.from('sensitive material '.repeat(2000));

  async function seal(engine) {
    return encryptFile(new File([content], 'secret.txt'), PASSPHRASE, CONFIG, {}, engine);
  }

  test('the wrong passphrase fails with the generic message', async () => {
    const engine = createInlineEngine(2);
    const encrypted = await seal(engine);
    await assert.rejects(
      decryptFile(new File([encrypted.blob], 'secret.txt.enc'), 'the-wrong-passphrase', CONFIG, {}, engine),
      (error) => {
        assert.equal(error.code, 'decryption_failed');
        assert.match(error.message, /could not be decrypted/);
        return true;
      },
    );
    engine.close();
  });

  test('a tampered ciphertext byte is caught and is indistinguishable from a wrong passphrase', async () => {
    const engine = createInlineEngine(2);
    const encrypted = await seal(engine);
    const bytes = Buffer.from(await encrypted.blob.arrayBuffer());
    bytes[HEADER_SIZE + 100] ^= 0x01;

    let tamperError;
    await assert.rejects(
      decryptFile(new File([bytes], 'secret.txt.enc'), PASSPHRASE, CONFIG, {}, engine),
      (error) => { tamperError = error; return true; },
    );

    let wrongPassError;
    await assert.rejects(
      decryptFile(new File([encrypted.blob], 'secret.txt.enc'), 'not-it-at-all', CONFIG, {}, engine),
      (error) => { wrongPassError = error; return true; },
    );

    // F.8: the two must be reported identically, or the difference is an oracle.
    assert.equal(tamperError.message, wrongPassError.message);
    assert.equal(tamperError.code, wrongPassError.code);
    engine.close();
  });

  test('a tampered authentication tag is caught', async () => {
    const engine = createInlineEngine(2);
    const encrypted = await seal(engine);
    const bytes = Buffer.from(await encrypted.blob.arrayBuffer());
    bytes[bytes.length - 1] ^= 0xff;
    await assert.rejects(
      decryptFile(new File([bytes], 'secret.txt.enc'), PASSPHRASE, CONFIG, {}, engine),
      (error) => error.code === 'decryption_failed',
    );
    engine.close();
  });

  test('altering the stored digest is caught, because the header is authenticated', async () => {
    const engine = createInlineEngine(2);
    const encrypted = await seal(engine);
    const bytes = Buffer.from(await encrypted.blob.arrayBuffer());
    bytes[72] ^= 0xff;   // first byte of the SHA-256 digest field
    await assert.rejects(
      decryptFile(new File([bytes], 'secret.txt.enc'), PASSPHRASE, CONFIG, {}, engine),
      (error) => error.code === 'decryption_failed',
    );
    engine.close();
  });

  test('altering the recorded extension is caught', async () => {
    const engine = createInlineEngine(2);
    const encrypted = await seal(engine);
    const bytes = Buffer.from(await encrypted.blob.arrayBuffer());
    bytes[18] = 'x'.charCodeAt(0);
    await assert.rejects(
      decryptFile(new File([bytes], 'secret.txt.enc'), PASSPHRASE, CONFIG, {}, engine),
      (error) => error.code === 'decryption_failed',
    );
    engine.close();
  });

  test('a truncated container is rejected before any work is done', async () => {
    const engine = createInlineEngine(2);
    const encrypted = await seal(engine);
    const bytes = Buffer.from(await encrypted.blob.arrayBuffer()).subarray(0, 500);
    await assert.rejects(
      decryptFile(new File([bytes], 'secret.txt.enc'), PASSPHRASE, CONFIG, {}, engine),
      (error) => error.code === 'size_mismatch',
    );
    engine.close();
  });

  test('a file that is not a container is rejected clearly', async () => {
    const engine = createInlineEngine(2);
    await assert.rejects(
      decryptFile(new File([Buffer.alloc(5000)], 'random.enc'), PASSPHRASE, CONFIG, {}, engine),
      (error) => error.code === 'not_a_container',
    );
    engine.close();
  });
});
