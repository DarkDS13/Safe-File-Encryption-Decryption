# Secure File Encryption and Decryption System

A zero-knowledge web application for encrypting files. Files are encrypted and
decrypted **inside the browser** with AES-256-GCM under a key derived from the
user's passphrase with Argon2id. The server stores sealed containers, manages
accounts, and keeps an audit log. It never receives a passphrase or a key, and
there is no mechanism by which it could decrypt a stored file.

Implementation of the SRS and Design Document by
Devansh Hiren Shah (241IT024), Mantri Samarth Prakash (241IT043),
Rana Jay Mukeshkumar (241IT060) — Department of Information Technology,
NITK Surathkal.

---

## Running it

```bash
./scripts/start.sh
```

Then open <http://localhost:8000>. The script creates a virtual environment and
installs dependencies on first run. Nothing else is needed — one process serves
both the JSON API and the browser client.

To do it by hand:

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r backend/requirements.txt && ./.venv/bin/python backend/run.py
```

### First sign-in

A bootstrap administrator is created on first start:

| Email | Password |
| --- | --- |
| `admin@example.com` | `Admin@12345` |

Change these before any real deployment by setting `SFE_ADMIN_EMAIL` and
`SFE_ADMIN_PASSWORD`. Accounts registered through the sign-up form are ordinary
users; the administrator view is at `/admin`.

---

## Running the tests

```bash
./.venv/bin/python -m pytest backend/tests -q     # 47 backend tests
node --test "frontend/tests/*.test.mjs"           # 38 cryptography tests
```

The frontend suite is the important one for correctness. It pins the
cryptographic primitives against published test vectors — RFC 9106 §5 for
Argon2d/i/id, RFC 7693 for BLAKE2b, and Node's own implementation for SHA-256 —
and then round-trips real TXT, PNG, JPEG and PDF payloads through the shipping
encrypt/decrypt pipeline, asserting byte-identical recovery (NF.4). It also
asserts that a tampered container and a wrong passphrase produce *identical*
error output, which is the property F.8 actually asks for.

The pipeline is testable outside a browser because `encryptFile`/`decryptFile`
take an injectable engine. In the browser that engine is a pool of Web Workers;
in the tests it is `frontend/tests/inline-engine.mjs`, which performs the same
primitive operations inline. The segmentation, ordering, header, and
verification logic under test is the code that ships.

---

## How a file moves through the system

```
  browser                                              server
  ───────                                              ──────
  file  ──▶ validate (type, size)          F.1
        ──▶ stream SHA-256 over segments   F.9
        ──▶ Argon2id(passphrase, salt)     F.4   ─┐ never leaves the browser
        ──▶ build 104-byte header                 │
        ──▶ AES-256-GCM per 1 MiB segment  F.7    │
            (header = AAD for every tag)          │
        ──▶ assemble container            ────────┴──▶ stored as opaque bytes
                                                       against the account   F.7
  decrypt reverses each step, verifying every segment tag before releasing
  its plaintext, then re-checking the SHA-256 from the header.        F.8, F.9
```

### Container format

Every container opens with a 104-byte header carrying everything needed to
reverse the operation, so a file remains decryptable long after the server that
produced it is gone.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | magic bytes, always `ENCV` |
| 4 | 1 | container format version (2) |
| 5 | 1 | KDF identifier (1 = Argon2id) |
| 6 | 1 | cipher identifier (1 = AES-256-GCM) |
| 7 | 1 | flags, reserved |
| 8 | 4 | KDF memory cost, KiB |
| 12 | 4 | KDF iterations |
| 16 | 1 | KDF parallelism |
| 17 | 1 | original extension length |
| 18 | 14 | original extension |
| 32 | 16 | KDF salt |
| 48 | 12 | base nonce |
| 60 | 4 | segment size |
| 64 | 8 | plaintext length |
| 72 | 32 | SHA-256 of the plaintext |
| 104 | … | ciphertext: each 1 MiB segment followed by its 16-byte tag |

The **whole header is the additional authenticated data for every segment**.
Altering any field — the digest, the segment size, the recorded extension —
makes every tag fail. That is stronger than the original SRS Appendix B design,
where the header was unauthenticated.

Per-segment nonces are the first 8 bytes of the base nonce followed by the
segment index. The salt is fresh for every operation, so the key is fresh too
and a nonce cannot repeat under one key.

The plaintext digest is stored in the clear. This is a deliberate trade, carried
over from the SRS and worth restating: it is what lets F.9 prove bit-exact
recovery, and it also lets anyone holding a container confirm a guessed
plaintext. For the threat model assumed here — protecting documents in storage
and transit against someone who does not already know their contents — that is
acceptable. Replacing it with an HMAC over the ciphertext is the natural next
version of the format.

---

## Layout

```
backend/
  app/
    main.py           application, middleware, error handling, static client
    config.py         every setting, overridable by environment variable
    models.py         User, Container, Operation, AuditLog
    schemas.py        request/response bodies
    security.py       bcrypt, JWT, the role dependencies
    storage.py        chunked filesystem storage for containers
    audit.py          audit writes, with central redaction of key material
    ratelimit.py      per-account fixed-window limiting
    routers/          auth, containers, operations, admin
  tests/              47 pytest tests
frontend/
  index.html          user application
  admin.html          administrator application
  js/
    argon2.js         Argon2id (RFC 9106), verified against the RFC vectors
    blake2b.js        BLAKE2b (RFC 7693), the hash Argon2 is built on
    sha256.js         streaming SHA-256, for the integrity check
    container.js      header construction, parsing, and bound-checking
    filecrypto.js     the encrypt/decrypt pipeline (modules 0.3 and 0.5)
    crypto-worker.js  the worker that runs Argon2id and AES-GCM
    workerpool.js     bounded worker pool providing backpressure
    api.js            REST client
    app.js/admin.js   the two page controllers
  tests/              38 Node tests
docs/
  TRACEABILITY.md     every SRS requirement mapped to code and to a test
```

## Modules, as assigned in the design document

| # | Module | Designer | Where it lives |
| --- | --- | --- | --- |
| 0.1 | Authentication & Session Management | Devansh Hiren Shah | `routers/auth.py`, `security.py` |
| 0.2 | Key Derivation | Mantri Samarth Prakash | `js/argon2.js`, `js/blake2b.js` |
| 0.3 | Segmentation & Encryption | Mantri Samarth Prakash | `js/filecrypto.js`, `js/container.js`, `js/workerpool.js` |
| 0.4 | Container Storage & Retrieval | Devansh Hiren Shah | `routers/containers.py`, `storage.py` |
| 0.5 | Verification & Decryption | Rana Jay Mukeshkumar | `js/filecrypto.js` (`decryptFile`), `js/container.js` (`parseHeader`) |
| 0.6 | Metrics & Audit Logging | Rana Jay Mukeshkumar | `routers/operations.py`, `audit.py` |
| 0.7 | System Administration | Devansh Hiren Shah | `routers/admin.py`, `js/admin.js` |

---

## API

All endpoints require a bearer token except `/api/health`, `/api/config`, and
the two auth endpoints. A request for another account's resource returns **403**
and is written to the audit log (NF.7).

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/auth/register` | create an account |
| `POST` | `/api/auth/login` | sign in |
| `GET` | `/api/auth/me` | current account |
| `POST` | `/api/containers` | upload a sealed container |
| `GET` | `/api/containers` | list your own containers |
| `GET` | `/api/containers/{id}/download` | download a container |
| `DELETE` | `/api/containers/{id}` | delete a container and its stored bytes |
| `POST` | `/api/operations` | record the metrics for one operation |
| `GET` | `/api/operations` | your own history |
| `GET` | `/api/operations/summary` | your own aggregate figures |
| `GET` | `/api/admin/users` | list accounts |
| `POST` | `/api/admin/users/{id}/suspend` | suspend an account |
| `POST` | `/api/admin/users/{id}/reinstate` | reinstate an account |
| `GET` | `/api/admin/audit` | global audit log |
| `GET` | `/api/admin/stats` | system statistics |
| `GET` | `/api/admin/containers` | container metadata across accounts |
| `POST` | `/api/admin/purge` | remove containers past retention |

Interactive documentation is at `/docs` while the server is running.

## Configuration

Every setting is an environment variable; the defaults are in
`backend/app/config.py`.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SFE_SECRET_KEY` | random per start | JWT signing key. **Set this in deployment**, or sessions end at every restart. |
| `SFE_DATA_DIR` | `./data` | database and container storage |
| `SFE_MAX_UPLOAD_BYTES` | 52428800 | 50 MB single-upload cap |
| `SFE_SEGMENT_SIZE` | 1048576 | 1 MiB |
| `SFE_RETENTION_DAYS` | 7 | how long containers are kept |
| `SFE_ARGON2_MEMORY_KIB` | 65536 | 64 MiB |
| `SFE_ARGON2_ITERATIONS` | 3 | |
| `SFE_RATE_LIMIT_REQUESTS` | 120 / 60 s | per account |
| `SFE_ADMIN_EMAIL` / `SFE_ADMIN_PASSWORD` | `admin@example.com` / `Admin@12345` | bootstrap administrator |

---

## Two things worth knowing before you demo this

### 1. The SRS and the Design Document describe different systems

The SRS body (§2–3) specifies a **server-side** design: Python and
PyCryptodome, DES and AES, ECB/CBC/CTR, PBKDF2, the server doing the
encryption. The title page (*"using AES-GCM-256"*) and the Design Document §2
specify a **client-side zero-knowledge** design: Argon2id, AES-256-GCM, 1 MiB
segments, a Web Worker pool, and a server that stores opaque containers.

This codebase implements the **Design Document** architecture, because it is the
later document, it matches the project title, and its module decomposition is
what the seven modules and their designer assignments are written against. Every
functional requirement F.1–F.14 is still satisfied — `docs/TRACEABILITY.md` maps
each one to the code and to the test that covers it.

The practical consequences of choosing this architecture:

- There is no DES, and no ECB/CBC/CTR mode selector. AES-256-GCM is the only
  cipher, because an authenticated mode is what makes F.9's tamper detection
  work. The SRS's own §3.1 F.3 warning about ECB is, in effect, resolved by not
  offering ECB at all.
- PyCryptodome is not a dependency (C.3). The cipher comes from the browser's
  WebCrypto — which uses AES-NI where the processor has it, satisfying the
  hardware requirement in §3.2.2 — and Argon2id is implemented in
  `frontend/js/argon2.js`.
- C.6 (no key custody) is enforced structurally rather than by policy. There is
  no field in any schema, model, or API route where a key could be stored.

### 2. Argon2id at the specified cost is slow in pure JavaScript

The design document specifies 64 MiB and 3 iterations. In this implementation
that takes roughly **4–5 seconds in Node and 8–11 seconds in a browser**, per
operation. It runs in a worker with a progress bar, so the interface stays
responsive, but it dominates the wall-clock time of any operation on a small
file.

This is worth stating plainly against NF.5, which budgets five seconds for a
10 MB file: the *encryption* meets that comfortably — AES-GCM through WebCrypto
runs at hundreds of MB/s — but the one-off key derivation does not fit inside
it. The two are separate costs and the metrics panel reports the total.

If a demo needs to be quicker, lower the cost from the server without touching
any code:

```bash
SFE_ARGON2_MEMORY_KIB=19456 SFE_ARGON2_ITERATIONS=2 ./scripts/start.sh
```

That is RFC 9106's second recommended parameter set and takes well under a
second. Containers record their own KDF parameters in the header, so files
encrypted under either setting stay decryptable.

A production deployment would replace `argon2.js` with a compiled WebAssembly
Argon2, which closes most of the gap. The module boundary is already in the
right place for that: only `crypto-worker.js` calls into it.


## Deployment

The application is packaged as a single Docker image serving both the API and
the browser client.

```bash
docker build -t sfe .
docker run -d -p 8000:8000 -e SFE_ENV=production \
  -e SFE_SECRET_KEY="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
  -e SFE_ADMIN_PASSWORD='a-real-password' -v sfe-data:/data sfe
```

Blueprints are included for [Render](render.yaml) and [Fly.io](fly.toml).

**HTTPS is mandatory.** The browser only exposes the Web Crypto API in a secure
context, so the client refuses to run over plain HTTP to anything but
`localhost`. Every hosting option in the guide terminates TLS for you.

Full instructions, configuration reference, and post-deploy checks:
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).
