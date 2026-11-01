# AHS platform — how to edit (the published site is encrypted)

The repo is public, so the platform's pages and files are stored **encrypted**:

- `index.html`, `archive.html`, `dept.html`, `logins.html` are small login pages that carry the real page as ciphertext.
- Every file under `images/` and `reports/` is ciphertext (starts with `AHSE`).
- `challenges.html` and `vendor/` are public and stay plain.

After a correct password the browser keeps the keys (IndexedDB) and `sw.js` + `sec-core.js` decrypt pages,
images and PDFs on the fly. `tools/keyring.json` holds the keys wrapped per password (safe to publish).

## Editing workflow

1. Ask the user for the **owner password** (never write it into a file, commit message or log).
2. `pip install cryptography` if missing, then
   `AHS_PASSWORD='…' python3 tools/ahs_crypt.py unlock` → plain copies appear in `_plain/` (git-ignored).
3. Edit the files in `_plain/` (pages, `_plain/images/…`, `_plain/reports/…`). Add new images/PDFs there too.
4. `AHS_PASSWORD='…' python3 tools/ahs_crypt.py lock` → re-encrypts changed files into the site and runs `check`.
5. Commit and push. Never `git add -f _plain`. The deploy workflow refuses to publish if `check` fails.

Test locally with `python3 -m http.server` (localhost counts as secure, so the service worker runs).

## Passwords

Slots (ids): `owner`, `manager` (open index/archive/dept/assets; `owner` also opens logins.html) and one per
department (`labs`, `radiology`, `pharmacy`, `rehab`, `mental`, `nutrition`: open dept.html + assets).
The pages' own SHA-256 gates (`GATE_USERS` in index/archive, `OWNER_HASH` in logins, `DEPT_HASHES` in dept)
must match. To change a password: update the hash in `_plain/` pages, then
`AHS_PASSWORD='owner pw' AHS_NEW_PASSWORD='new pw' python3 tools/ahs_crypt.py set-slot <id>`, then `lock`.
