# Requirements traceability

Every requirement from the SRS mapped to the code that implements it and the
test that covers it. Test names are abbreviated; run the suites to see them all.

- `pytest backend/tests -q` — 47 tests
- `node --test "frontend/tests/*.test.mjs"` — 38 tests

## Functional requirements

| Req | Requirement | Implementation | Test |
| --- | --- | --- | --- |
| F.1 | Upload input file; check extension, MIME type and size | `frontend/js/filecrypto.js` → `validateFile` | `file validation (F.1)` — 5 tests |
| F.2 | Select algorithm and key length | AES-256-GCM only; recorded in the container header byte 6 and shown in the UI's "What is actually being used" panel | `container format` → round-trips every header field |
| F.3 | Select mode of operation | GCM only. An authenticated mode is required for F.9, and ECB — which the SRS itself warns about — is deliberately not offered. Padding is not needed: GCM is a stream mode. | `encrypt / decrypt round trip` — partial final segments |
| F.4 | Obtain a secret key: derive from a passphrase with a random 16-byte salt, or generate one and show it once | `frontend/js/argon2.js`; `app.js` → `generatePassphrase`, and the show-once warning panel in `index.html` | `Argon2 (RFC 9106)` — 6 tests |
| F.5 | Validate key and IV; a fresh IV for every operation, never reused | `filecrypto.js` generates a fresh salt and base nonce per operation; `container.js` → `segmentNonce` | `gives every segment a distinct nonce`; `the same file encrypted twice gives different ciphertext` |
| F.6 | Read the file as raw bytes in fixed-size chunks; record the extension | `filecrypto.js` → `readSlice`, segment loops; `container.js` → `normaliseExtension` | round-trip tests for TXT, PNG, JPEG, PDF; `normalises extensions safely` |
| F.7 | Encrypt into a container carrying IV, salt, iteration count, algorithm, mode, extension and digest | `container.js` → `buildHeader`; `filecrypto.js` → `encryptFile`; stored by `routers/containers.py` | `container format`; `test_upload_stores_the_container` |
| F.8 | Decrypt; failure must not distinguish a wrong passphrase from corrupt data | `filecrypto.js` → `decryptFile`, single `GENERIC_FAILURE` message | `a tampered ciphertext byte is caught and is indistinguishable from a wrong passphrase` |
| F.9 | Verify integrity: recompute SHA-256 and compare in constant time; discard on mismatch | `sha256.js` → `Sha256`, `timingSafeEqual`; checked in `decryptFile` | `constant-time comparison agrees with equality`; `altering the stored digest is caught` |
| F.10 | Report elapsed time, peak memory, and input/output sizes | `filecrypto.js` → `MetricsRecorder`; `routers/operations.py` | `metrics are recorded for every operation (F.10)`; `test_recording_an_operation_stores_every_metric` |
| F.11 | Download and delete outputs; remove temporary files on completion or expiry | `routers/containers.py` → `delete_container`; `routers/admin.py` → `purge_expired` | `test_delete_removes_the_stored_bytes`; `test_purge_removes_only_expired_containers` |
| F.12 | Register and authenticate; bcrypt hashes; role authorised on the server | `routers/auth.py`, `security.py` | `test_password_is_stored_only_as_a_bcrypt_hash`; `test_every_admin_endpoint_refuses_an_ordinary_user` |
| F.13 | Administrative functions: list, suspend, reinstate, read the log, view statistics, purge | `routers/admin.py`, `frontend/js/admin.js` | `test_admin.py` — 12 tests |
| F.14 | Handle errors and record every operation with its parameters and outcome, never with its key | `main.py` exception handlers; `audit.py` with central redaction | `test_audit_log_never_records_key_material`; `failures are recorded too` |

## Non-functional requirements

| Req | Requirement | How it is met | Test |
| --- | --- | --- | --- |
| NF.1 | Runs on Windows and Linux without source changes | Pure Python and `pathlib`; every setting is an environment variable | — |
| NF.2 | Reachable from a standard browser with no local installation | Static ES modules served by the same process; no build step | — |
| NF.3 | Keys and passphrases exist only in memory, only for one operation | No schema, model, or route has a field for them; worker memory is zeroed after use (`key.fill(0)`, `password.fill(0)`) | `test_no_endpoint_accepts_or_echoes_key_material` |
| NF.4 | Decryption with the correct passphrase returns a bit-identical file, for every type/algorithm/mode, demonstrated by an automated suite | `encryptFile`/`decryptFile` | `encrypt / decrypt round trip (NF.4)` — 9 tests over TXT, PNG, JPEG, PDF, plus 1-byte, exact-segment, and multi-segment edge cases |
| NF.5 | 10 MB in five seconds; memory bounded regardless of file size | AES-GCM via WebCrypto is far inside the budget; the Argon2id derivation is a separate one-off cost that is not — see README. Memory is bounded by the worker pool window. | `metrics are recorded...`; see README §2 |
| NF.6 | Fifty simultaneous users; large operations must not block others | The heavy work happens on each user's own machine, so the server only ever streams bytes; SQLite runs in WAL mode; storage reads and writes are chunked | — |
| NF.7 | All endpoints authenticated; another user's resource returns 403, not 404, and is logged | `security.py` → `current_user`; `containers.py` → `_owned_or_403` | `test_another_users_container_returns_403_not_404`; `test_refused_access_is_written_to_the_audit_log` |
| NF.8 | Operable without cryptographic knowledge; errors say what to do next | Inline explanations on every option; every error message names the problem and the next step | `refuses an oversized file and names the limit` |
| NF.9 | Malformed uploads and interrupted operations must not crash the server or leave temporary files | Catch-all exception handler; `storage.save_stream` writes to a temporary file and removes it on any failure | `test_oversize_upload_is_rejected` asserts no `.part` files remain |
| NF.10 | The cryptographic core is self-contained with a stable interface | `argon2.js`, `blake2b.js`, `sha256.js`, `container.js` have no DOM or network dependency; the pipeline talks to an injectable engine | the whole frontend suite runs them outside a browser |

## Constraints

| # | Constraint | Status |
| --- | --- | --- |
| C.1 | Standards compliance | AES-256-GCM per NIST SP 800-38D via WebCrypto; Argon2id per RFC 9106, verified against the RFC's own vectors. FIPS 46-3 (DES) does not apply — see README §1. |
| C.2 | 4 GB RAM; AES-NI preferred | WebCrypto uses AES-NI where present and falls back transparently where not |
| C.3 | PyCryptodome as the only crypto provider | **Deliberately not met.** The client-side architecture puts the cipher in the browser; PyCryptodome cannot run there. See README §1. |
| C.4 | Fixed-size chunks; memory flat regardless of file size | 1 MiB segments throughout, with a bounded worker pool applying backpressure |
| C.5 | Every operation logged with algorithm, mode, size, timestamp and outcome; never key material | `audit.py`, with redaction applied centrally so no call site can bypass it |
| C.6 | No key storage, no escrow, no recovery | Structural: there is nowhere to put one. Stated in the interface before encryption begins. |
| C.7 | Correctness over performance | The integrity check is unconditional, and any failure discards everything recovered rather than returning a partial file |

## Design constraints

| Constraint | Status |
| --- | --- |
| At least 4 GB RAM; AES-NI recommended | met |
| Only DES and AES; no asymmetric cryptography | AES only — see README §1. No asymmetric cryptography, key exchange, or signatures. |
| No escrow, no recovery; the interface must say so before encryption | met — stated on the sign-in page and beside the generated-passphrase warning |
| 50 MB single-upload cap | met — enforced in the browser (`validateFile`) and again on the server (`storage.save_stream`) |
