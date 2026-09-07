# Testing Guide

125 automated tests: **82 backend** (pytest) + **43 frontend** (node --test).

```bash
./scripts/test.sh                 # everything
```

```bash
.venv/bin/python -m pytest backend/tests -v
```

```bash
node --test "frontend/tests/*.test.mjs"
```

---

## 1. The strategy

Testing is organised as a pyramid, and the level a thing is tested at is chosen
deliberately:

| Level | Count | What it is good for |
|---|---:|---|
| **Unit — algorithm** | 23 | Pinning cryptography to published vectors. A bug here is invisible at any higher level, because wrong output still *looks* like ciphertext. |
| **Unit — component** | 29 | Header parsing, validation, storage, the rate limiter. Fast, exhaustive on edge cases. |
| **Integration** | 52 | Real HTTP through the real app; real encrypt→decrypt through the real pipeline. |
| **System** | 16 | Concurrency, performance, and end-to-end behaviour under load. |
| **Manual** | — | Browser-specific behaviour no headless suite can prove. |

The governing rule: **cryptographic correctness is pinned to external
authority, not to our own output.** Every primitive is checked against RFC test
vectors or an independent implementation, never against a value this codebase
produced. A test asserting "the output equals what it produced last time" would
pass just as happily on a broken implementation.

---

## 2. Unit tests, module by module

### 0.1 Authentication & Session Management — `test_auth.py` (22)

Registration, password policy, duplicate handling, bcrypt storage, suspension,
and a full JWT attack suite.

```bash
.venv/bin/python -m pytest backend/tests/test_auth.py -v
```

Worth knowing why these specific tests exist:

- `test_login_failure_does_not_reveal_whether_account_exists` asserts the two
  response bodies are **string-equal**. Account enumeration is the failure mode.
- `test_editing_the_role_claim_does_not_grant_admin` decodes a real token,
  rewrites `role` to `admin`, re-encodes, and expects 401.
- `test_an_alg_none_token_is_refused` covers the classic JWT downgrade attack.
- `test_long_passwords_are_not_truncated_to_72_bytes` guards a real bug that was
  found and fixed: bcrypt refuses inputs over 72 bytes, so a long passphrase
  crashed registration until a SHA-256 pre-hash was added.
- `test_suspended_account_token_stops_working` proves the role is re-read from
  the database rather than trusted from the token.

### 0.2 Key Derivation — `crypto-vectors.test.mjs` (11)

Argon2d, Argon2i and Argon2id against the **RFC 9106 §5 vectors**; BLAKE2b
against **RFC 7693**.

```bash
node --test frontend/tests/crypto-vectors.test.mjs
```

These are the highest-value tests in the project. Both bugs found during
development were here, and neither was visible any other way:

1. `H'` emitted the wrong number of 64-byte blocks for outputs over 64 bytes.
2. The `J1²` index calculation lost precision by exceeding 2^53 in a float.

Each produced plausible-looking 32-byte output. Only the published vectors
caught them.

### 0.3 Segmentation & Encryption — `crypto-vectors.test.mjs` (12)

Header round-trip, `validateFile` on every accepted and rejected case, and nonce
uniqueness across 1000 segments.

### 0.4 Container Storage & Retrieval — `test_storage.py` (11), `test_containers.py` (13)

`test_storage.py` calls the storage layer directly: chunk-boundary writes,
digest correctness, cleanup after failure, path traversal, repeated deletes.

```bash
.venv/bin/python -m pytest backend/tests/test_storage.py backend/tests/test_containers.py -v
```

- `test_an_oversize_stream_is_refused_and_leaves_nothing_behind` and
  `test_a_failing_source_leaves_nothing_behind` cover NF.9 — no `.part` files
  survive an interrupted write.
- `test_paths_that_escape_the_storage_root_are_refused` is parametrised over
  four traversal payloads.
- `test_another_users_container_returns_403_not_404` pins the NF.7 decision.

### 0.5 Verification & Decryption — `crypto-vectors.test.mjs` (7)

The failure paths, which are the ones that matter:

| Test | Property |
|---|---|
| wrong passphrase | rejected |
| flipped ciphertext byte | rejected |
| flipped authentication tag | rejected |
| **altered digest field in the header** | rejected — the header is AAD |
| **altered extension field in the header** | rejected — same reason |
| truncated container | rejected |
| not a container at all | rejected |

The key assertion is that the wrong-passphrase message and the tampered-file
message are **identical strings** (F.8 — distinguishing them would give an
attacker an oracle).

### 0.6 Metrics & Audit Logging — `test_operations.py` (8)

Metric storage, failure recording, per-user history scoping, aggregation.

`test_no_endpoint_accepts_or_echoes_key_material` posts a passphrase, a key, a
token and a salt into an operation record, then asserts none appear anywhere in
the admin audit response.

### 0.7 System Administration — `test_admin.py` (12)

Role enforcement across all five admin endpoints, account management,
self-suspension, statistics, and purge.

### Cross-cutting: rate limiting — `test_ratelimit.py` (10)

```bash
.venv/bin/python -m pytest backend/tests/test_ratelimit.py -v
```

`test_signing_in_again_does_not_reset_the_limit` is the important one: it pins
that buckets are keyed on the **account**, not the token string. Keyed on the
token, a throttled user could sign in again for a fresh bucket.

Note the technique — `conftest.py` sets the limits to 10000 so the rest of the
suite runs unthrottled, and this module `monkeypatch`es them down to 4–5.

---

## 3. Integration testing — proving the modules connect

Unit tests prove each module is right in isolation. These prove the seams hold.

### Seam 1: 0.3 writes, 0.5 reads (the container format)

The round-trip tests in `crypto-vectors.test.mjs`. For each supported type —
TXT, PNG, JPEG, PDF — the file is encrypted and then decrypted, and the result
must be **byte-identical** (NF.4):

```js
assert.deepEqual(Buffer.from(await decrypted.blob.arrayBuffer()), content);
```

Plus size edge cases that catch off-by-one segmentation errors: 1 byte, exactly
one segment, exactly one segment plus one byte, five segments.

Two assertions in these tests are doing more than they appear:

```js
// the digest is cross-checked against an INDEPENDENT implementation
assert.equal(encrypted.digestHex, createHash('sha256').update(content).digest('hex'));

// the plaintext must not appear anywhere in the container
assert.equal(sealed.includes(content.subarray(0, 64)), false);
```

The second is a direct test of the confidentiality claim rather than of a code
path.

### Seam 2: browser to server (the REST API)

`test_containers.py` drives real HTTP through the real app.
`test_stored_bytes_are_byte_identical_on_download` uploads a container and
asserts the downloaded bytes match exactly — the server must be a faithful
courier for data it cannot read.

### Seam 3: the engine interface

`frontend/tests/inline-engine.mjs` implements the same
`{concurrency, deriveKey, processSegment, close}` contract that
`crypto-worker.js` implements, and is injected into `encryptFile`/`decryptFile`.

This is why the real pipeline — segmentation, ordering, backpressure, header
construction, tag verification — can be tested outside a browser. Only the
Worker transport is substituted; every line of application logic is the real one.

---

## 4. System testing

### Concurrency — NF.6 (`test_concurrency.py`, 5 tests)

```bash
.venv/bin/python -m pytest backend/tests/test_concurrency.py -v
```

`test_fifty_users_uploading_at_once_all_succeed` is the direct test of the
requirement: fifty accounts upload simultaneously through a `ThreadPoolExecutor`,
every response must be 201, **and every container must download back
byte-identical** — concurrent writes must not interleave.

`test_the_rate_limiter_counts_correctly_under_concurrency` fires 60 requests
across 16 threads with a limit of 20 and asserts **exactly** 20 succeed. Without
the `threading.Lock`, two threads could read the same count and both pass.

### Performance — NF.5 (`performance.test.mjs`, 5 tests)

```bash
node --test frontend/tests/performance.test.mjs
```

Measured on the reference machine:

```
encrypt 10 MB: 169ms (59.3 MB/s)     budget: 5000ms
decrypt 10 MB: 152ms (65.9 MB/s)     budget: 5000ms
scaling:  2 MB -> 50ms,  8 MB -> 125ms
heap growth:  4 MB file -> 1.0 MB,  16 MB file -> -2.6 MB
```

Two deliberate choices here:

- **The KDF is measured separately from the bulk cipher.** Argon2id is a fixed
  ~8 second cost that does not grow with file size; folding it into a throughput
  figure would say nothing about how the system scales. NF.5 is about the cipher.
- **Memory growth is compared across sizes, not measured absolutely.** Quadrupling
  the file must not quadruple the heap. It does not — which is C.4 demonstrated
  rather than asserted.

---

## 5. Manual testing — what no automated suite can prove

Six checks that need a real browser:

1. **Zero-knowledge, proven visually.** Open DevTools → Network, encrypt a file,
   inspect every request body. The passphrase appears in none of them. This is
   the single most convincing demonstration of the architecture.
2. **Worker parallelism.** DevTools → Sources → Threads shows the worker pool
   during encryption. The interface stays responsive throughout.
3. **Suspension mid-session.** Sign in as a user in one window, suspend from the
   admin tab in another, confirm the next action fails with 403.
4. **The unrecoverable-passphrase warning.** Encrypt with a generated
   passphrase, do not copy it, and confirm the file is genuinely unrecoverable.
   This demonstrates C.6 better than any assertion.
5. **Cross-browser.** Chrome, Firefox, Safari, Edge. WebCrypto and Web Workers
   are standard, but worth confirming.
6. **Retention.** Set `SFE_RETENTION_DAYS=0`, upload, purge, confirm both the row
   and the file are gone.

---

## 6. Requirement coverage

| Requirement | Covered by |
|---|---|
| F.1 upload and validate | `file validation` (5) |
| F.2, F.3 algorithm and mode | Argon2/AES vectors (11) |
| F.4, F.5 key and IV | nonce uniqueness, salt freshness |
| F.6 byte stream | round trips over four file types |
| F.7 encrypt to container | round trips, header tests |
| F.8 decrypt | failure paths — indistinguishable messages |
| F.9 integrity | digest cross-check, tamper detection (7) |
| F.10 metrics | `test_operations.py` (8) |
| F.11 manage output | `test_containers.py`, purge tests |
| F.12 auth | `test_auth.py` (22) |
| F.13 admin | `test_admin.py` (12) |
| F.14 errors and audit | error classification, redaction |
| NF.4 correctness | byte-identical round trips |
| NF.5 performance | `performance.test.mjs` |
| NF.6 concurrency | `test_concurrency.py` |
| NF.7 API security | 403-not-404, isolation |
| NF.9 reliability | cleanup-after-failure tests |
| C.4 bounded memory | memory scaling test |
| C.5 auditability | audit redaction test |

**Not covered automatically:** cross-browser rendering (NF.1, NF.2), usability
(NF.8), and the 50 MB ceiling end-to-end. These are the manual checks above.
