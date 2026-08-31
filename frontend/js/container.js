/**
 * The encrypted container format (SRS Appendix B, revised for AES-256-GCM).
 *
 * A 104-byte header carries everything needed to reverse the operation, so a
 * container can be decrypted long after the server that produced it is gone,
 * provided the user still has the passphrase.
 *
 *   offset  size  field
 *   ------  ----  ----------------------------------------------------------
 *        0     4  magic bytes, always "ENCV"
 *        4     1  container format version
 *        5     1  KDF identifier
 *        6     1  cipher identifier
 *        7     1  flags (reserved, zero)
 *        8     4  KDF memory cost in KiB (zero when not applicable)
 *       12     4  KDF iteration / time cost
 *       16     1  KDF parallelism
 *       17     1  original extension length
 *       18    14  original extension, zero padded
 *       32    16  KDF salt
 *       48    12  base nonce
 *       60     4  segment size in bytes
 *       64     8  plaintext length in bytes
 *       72    32  SHA-256 digest of the plaintext
 *      104        ciphertext: one AES-GCM segment per 1 MiB of plaintext,
 *                 each followed by its 16-byte authentication tag
 *
 * The whole header is passed as additional authenticated data to every
 * segment, so altering any field — the digest, the segment size, the claimed
 * extension — makes every tag fail.
 *
 * The plaintext digest is stored in the clear.  That is what lets F.9 prove
 * bit-exact recovery, and it also lets anyone holding the container confirm a
 * guessed plaintext.  For the threat model here — protecting documents against
 * someone who does not already know their contents — that trade is accepted,
 * and it is written down rather than hidden.
 */

export const MAGIC = new Uint8Array([0x45, 0x4e, 0x43, 0x56]); // "ENCV"
export const FORMAT_VERSION = 2;
export const HEADER_SIZE = 104;
export const TAG_SIZE = 16;
export const SALT_SIZE = 16;
export const NONCE_SIZE = 12;
export const DIGEST_SIZE = 32;
export const MAX_EXTENSION = 14;

export const KDF = { ARGON2ID: 1, PBKDF2_SHA256: 2 };
export const KDF_NAMES = { 1: 'Argon2id', 2: 'PBKDF2-SHA256' };
export const CIPHER = { AES_256_GCM: 1 };
export const CIPHER_NAMES = { 1: 'AES-256-GCM' };

/** Thrown for anything a user could hit by supplying the wrong file. */
export class ContainerError extends Error {
  constructor(message, code = 'container_invalid') {
    super(message);
    this.name = 'ContainerError';
    this.code = code;
  }
}

/**
 * Build the 104-byte header.
 * @returns {Uint8Array}
 */
export function buildHeader({
  kdfId = KDF.ARGON2ID,
  cipherId = CIPHER.AES_256_GCM,
  memoryKiB = 0,
  iterations = 0,
  parallelism = 1,
  extension = '',
  salt,
  baseNonce,
  segmentSize,
  plaintextLength,
  digest,
}) {
  if (salt.length !== SALT_SIZE) throw new ContainerError('Salt must be 16 bytes.');
  if (baseNonce.length !== NONCE_SIZE) throw new ContainerError('Nonce must be 12 bytes.');
  if (digest.length !== DIGEST_SIZE) throw new ContainerError('Digest must be 32 bytes.');

  const ext = normaliseExtension(extension);
  const header = new Uint8Array(HEADER_SIZE);
  const view = new DataView(header.buffer);

  header.set(MAGIC, 0);
  header[4] = FORMAT_VERSION;
  header[5] = kdfId;
  header[6] = cipherId;
  header[7] = 0;
  view.setUint32(8, memoryKiB, true);
  view.setUint32(12, iterations, true);
  header[16] = parallelism;

  const extBytes = new TextEncoder().encode(ext);
  header[17] = extBytes.length;
  header.set(extBytes, 18);

  header.set(salt, 32);
  header.set(baseNonce, 48);
  view.setUint32(60, segmentSize, true);
  // A 50 MB cap means the high word is always zero, but the field is 64-bit so
  // the format does not need revising if that cap is ever raised.
  view.setUint32(64, plaintextLength >>> 0, true);
  view.setUint32(68, Math.floor(plaintextLength / 4294967296), true);
  header.set(digest, 72);

  return header;
}

/**
 * Parse and bound-check a header (module 0.5).
 *
 * Every length is checked against the actual container size before anything is
 * allocated, so a malformed file is rejected rather than producing a huge
 * allocation or an out-of-range read.
 */
export function parseHeader(bytes, totalSize) {
  if (!(bytes instanceof Uint8Array) || bytes.length < HEADER_SIZE) {
    throw new ContainerError('This file is too short to be an encrypted container.');
  }
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (bytes[i] !== MAGIC[i]) {
      throw new ContainerError(
        'This file was not produced by this application, so it cannot be decrypted here.',
        'not_a_container',
      );
    }
  }

  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = bytes[4];
  if (version !== FORMAT_VERSION) {
    throw new ContainerError(
      `This container uses format version ${version}, which this version of the application cannot read.`,
      'unsupported_version',
    );
  }

  const kdfId = bytes[5];
  if (!KDF_NAMES[kdfId]) {
    throw new ContainerError('This container uses an unknown key-derivation function.', 'unsupported_kdf');
  }
  const cipherId = bytes[6];
  if (!CIPHER_NAMES[cipherId]) {
    throw new ContainerError('This container uses an unknown cipher.', 'unsupported_cipher');
  }

  const extLength = bytes[17];
  if (extLength > MAX_EXTENSION) {
    throw new ContainerError('The container header is malformed.', 'bad_header');
  }
  const extension = new TextDecoder().decode(bytes.subarray(18, 18 + extLength));

  const segmentSize = view.getUint32(60, true);
  if (segmentSize === 0 || segmentSize > 64 * 1024 * 1024) {
    throw new ContainerError('The container header is malformed.', 'bad_header');
  }

  const plaintextLength =
    view.getUint32(64, true) + view.getUint32(68, true) * 4294967296;
  if (!Number.isSafeInteger(plaintextLength) || plaintextLength < 0) {
    throw new ContainerError('The container header is malformed.', 'bad_header');
  }

  const segmentCount = plaintextLength === 0 ? 0 : Math.ceil(plaintextLength / segmentSize);
  const expectedSize = HEADER_SIZE + plaintextLength + segmentCount * TAG_SIZE;
  if (typeof totalSize === 'number' && totalSize !== expectedSize) {
    throw new ContainerError(
      'This container is incomplete or has been altered.',
      'size_mismatch',
    );
  }

  return {
    version,
    kdfId,
    kdfName: KDF_NAMES[kdfId],
    cipherId,
    cipherName: CIPHER_NAMES[cipherId],
    memoryKiB: view.getUint32(8, true),
    iterations: view.getUint32(12, true),
    parallelism: bytes[16] || 1,
    extension,
    salt: bytes.slice(32, 32 + SALT_SIZE),
    baseNonce: bytes.slice(48, 48 + NONCE_SIZE),
    segmentSize,
    plaintextLength,
    digest: bytes.slice(72, 72 + DIGEST_SIZE),
    segmentCount,
    header: bytes.slice(0, HEADER_SIZE),
  };
}

/**
 * Per-segment nonce: the first 8 bytes of the base nonce, then the segment
 * index.  The salt is fresh for every operation, so the key is fresh too and a
 * nonce cannot repeat under one key.
 */
export function segmentNonce(baseNonce, index) {
  const nonce = new Uint8Array(NONCE_SIZE);
  nonce.set(baseNonce.subarray(0, 8), 0);
  new DataView(nonce.buffer).setUint32(8, index, true);
  return nonce;
}

export function normaliseExtension(nameOrExtension) {
  const raw = String(nameOrExtension || '');
  const dot = raw.lastIndexOf('.');
  let ext = dot >= 0 ? raw.slice(dot + 1) : raw;
  ext = ext.toLowerCase().replace(/[^a-z0-9]/g, '');
  return ext.slice(0, MAX_EXTENSION);
}

export function segmentCountFor(plaintextLength, segmentSize) {
  return plaintextLength === 0 ? 0 : Math.ceil(plaintextLength / segmentSize);
}

export function containerSizeFor(plaintextLength, segmentSize) {
  return (
    HEADER_SIZE + plaintextLength + segmentCountFor(plaintextLength, segmentSize) * TAG_SIZE
  );
}
