#!/usr/bin/env python3
"""Encrypt / decrypt the AHS platform for publishing.

The published site only holds ciphertext. Plain pages and assets live in _plain/
(git-ignored) while you edit them.

  python3 tools/ahs_crypt.py unlock          # decrypt the site into _plain/
  python3 tools/ahs_crypt.py lock            # encrypt _plain/ back into the site
  python3 tools/ahs_crypt.py check           # fail if anything protected is in plain form
  python3 tools/ahs_crypt.py set-slot ID     # add/replace a password slot (asks for the new password)

unlock / lock / set-slot need a password that opens every key (the owner's), taken from
the AHS_PASSWORD environment variable or asked for interactively. It is never stored.

Key design: each key below is a random AES-256-GCM key. Every password that may open it
gets a "slot": the key wrapped with AES-GCM under PBKDF2-SHA256(sha256hex(password), salt).
One salt for the whole keyring, so a login costs one PBKDF2 run and then tries each slot.
"""
import base64, getpass, hashlib, json, os, re, secrets, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAIN = ROOT / '_plain'
KEYRING = ROOT / 'tools' / 'keyring.json'
MANIFEST = ROOT / 'tools' / 'manifest.json'
TEMPLATE = ROOT / 'tools' / 'loader_template.html'

# page -> key that encrypts it
PAGES = {'index.html': 'mgmt', 'archive.html': 'mgmt', 'logins.html': 'owner', 'dept.html': 'dept'}
ASSET_DIRS = ['images', 'reports']
ASSET_KEY = 'assets'
MAGIC = b'AHSE\x01'
PAYLOAD_RE = re.compile(r'<script id="ahs-payload" type="application/octet-stream">([A-Za-z0-9+/=\s]+)</script>')

def AESGCM(key):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _A  # only needed to encrypt/decrypt
    return _A(key)


b64 = lambda b: base64.b64encode(b).decode()
unb64 = lambda s: base64.b64decode(s)


def sha_hex(s):
    return hashlib.sha256(s.encode()).hexdigest()


def kek_for(hash_hex, ring):
    return hashlib.pbkdf2_hmac('sha256', hash_hex.encode(), unb64(ring['salt']), ring['iter'], 32)


def wrap(kek, key_name, raw):
    iv = secrets.token_bytes(12)
    return {'iv': b64(iv), 'ct': b64(AESGCM(kek).encrypt(iv, raw, key_name.encode()))}


def load_ring():
    return json.loads(KEYRING.read_text())


def save_ring(ring):
    KEYRING.write_text(json.dumps(ring, indent=1) + '\n')


def get_password():
    pw = os.environ.get('AHS_PASSWORD')
    return pw if pw is not None else getpass.getpass('Owner password: ')


def unwrap_all(ring, password, need_all=True):
    kek = kek_for(sha_hex(password.strip()), ring)
    keys = {}
    for name, slots in ring['keys'].items():
        for s in slots:
            try:
                keys[name] = AESGCM(kek).decrypt(unb64(s['iv']), unb64(s['ct']), name.encode()); break
            except Exception:
                pass
    missing = [n for n in ring['keys'] if n not in keys]
    if need_all and missing:
        sys.exit('This password does not open: ' + ', '.join(missing) + ' (use the owner password)')
    return keys


def seal(key_name, raw_key, data):
    iv = secrets.token_bytes(12)
    kn = key_name.encode()
    return MAGIC + bytes([len(kn)]) + kn + iv + AESGCM(raw_key).encrypt(iv, data, kn)


def open_blob(blob, keys):
    if not blob.startswith(MAGIC):
        raise ValueError('not encrypted')
    n = blob[len(MAGIC)]
    p = len(MAGIC) + 1
    kn = blob[p:p + n].decode(); p += n
    iv = blob[p:p + 12]; p += 12
    return AESGCM(keys[kn]).decrypt(iv, blob[p:], kn.encode())


def loader_html(page, key_name, blob, ring):
    tpl = TEMPLATE.read_text(encoding='utf-8')
    public_ring = {'iter': ring['iter'], 'salt': ring['salt'], 'keys': ring['keys']}
    return (tpl.replace('__KEYRING__', json.dumps(public_ring, separators=(',', ':')))
               .replace('__PAGE_KEY__', key_name)
               .replace('__PAYLOAD__', b64(blob)))


def page_blob(path):
    m = PAYLOAD_RE.search(path.read_text(encoding='utf-8'))
    return unb64(m.group(1)) if m else None


def asset_files(base):
    for d in ASSET_DIRS:
        for f in sorted((base / d).rglob('*')):
            if f.is_file():
                yield f.relative_to(base).as_posix()


def cmd_unlock():
    ring = load_ring(); keys = unwrap_all(ring, get_password())
    PLAIN.mkdir(exist_ok=True)
    for page in PAGES:
        blob = page_blob(ROOT / page)
        if blob is None:
            sys.exit(page + ' is not encrypted')
        (PLAIN / page).write_bytes(open_blob(blob, keys))
    n = 0
    for rel in asset_files(ROOT):
        out = PLAIN / rel; out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(open_blob((ROOT / rel).read_bytes(), keys)); n += 1
    print(f'Decrypted {len(PAGES)} pages and {n} assets into _plain/')


def cmd_lock():
    ring = load_ring(); keys = unwrap_all(ring, get_password())
    if not PLAIN.exists():
        sys.exit('_plain/ not found: run unlock first')
    man = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    changed = 0
    tpl_h = hashlib.sha256(TEMPLATE.read_bytes() + KEYRING.read_bytes()).hexdigest()
    force_pages = man.get('__loader__') != tpl_h
    man['__loader__'] = tpl_h
    for page, kn in PAGES.items():
        data = (PLAIN / page).read_bytes(); h = hashlib.sha256(data).hexdigest()
        if not force_pages and man.get(page) == h and page_blob(ROOT / page) is not None:
            continue
        (ROOT / page).write_text(loader_html(page, kn, seal(kn, keys[kn], data), ring), encoding='utf-8')
        man[page] = h; changed += 1
    plain_assets = set(asset_files(PLAIN))
    for rel in plain_assets:
        data = (PLAIN / rel).read_bytes(); h = hashlib.sha256(data).hexdigest(); dst = ROOT / rel
        if man.get(rel) == h and dst.exists() and dst.read_bytes().startswith(MAGIC):
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(seal(ASSET_KEY, keys[ASSET_KEY], data)); man[rel] = h; changed += 1
    for rel in list(asset_files(ROOT)):  # assets deleted in _plain/ are deleted from the site
        if rel not in plain_assets:
            (ROOT / rel).unlink(); man.pop(rel, None); changed += 1
    MANIFEST.write_text(json.dumps(man, indent=1, sort_keys=True) + '\n')
    print(f'Encrypted {changed} changed file(s)')
    cmd_check()


def cmd_check():
    bad = [p for p in PAGES if page_blob(ROOT / p) is None]
    bad += [r for r in asset_files(ROOT) if not (ROOT / r).read_bytes().startswith(MAGIC)]
    if (ROOT / '_plain').exists() and os.popen(f'git -C "{ROOT}" ls-files _plain').read().strip():
        bad.append('_plain/ is tracked by git')
    if bad:
        sys.exit('NOT ENCRYPTED: ' + ', '.join(bad))
    print('OK: all protected pages and assets are encrypted')


def cmd_set_slot(slot_id, key_names=None):
    ring = load_ring(); keys = unwrap_all(ring, get_password())
    new_pw = os.environ.get('AHS_NEW_PASSWORD') or getpass.getpass(f'New password for {slot_id}: ')
    kek = kek_for(sha_hex(new_pw.strip()), ring)
    names = key_names or [n for n, slots in ring['keys'].items() if any(s['id'] == slot_id for s in slots)]
    if not names:
        sys.exit(f'{slot_id} has no slots yet: pass the key names, e.g. set-slot {slot_id} dept assets')
    for n in names:
        ring['keys'][n] = [s for s in ring['keys'][n] if s['id'] != slot_id] + [dict(id=slot_id, **wrap(kek, n, keys[n]))]
    save_ring(ring)
    print(f'Slot {slot_id} set on: {", ".join(names)}. Remember to update the page hash too, then run lock.')


def cmd_init(hashes_json):
    """One-time setup from existing SHA-256 password hashes: {"owner": "...", "manager": "...", "labs": "...", ...}"""
    if KEYRING.exists():
        sys.exit('keyring.json already exists')
    hashes = json.loads(Path(hashes_json).read_text())
    ring = {'iter': 600000, 'salt': b64(secrets.token_bytes(16)), 'keys': {}}
    depts = [k for k in hashes if k not in ('owner', 'manager')]
    members = {'mgmt': ['owner', 'manager'], 'owner': ['owner'],
               'dept': ['owner', 'manager'] + depts, 'assets': ['owner', 'manager'] + depts}
    keks = {sid: kek_for(h, ring) for sid, h in hashes.items()}
    for name, ids in members.items():
        raw = secrets.token_bytes(32)
        ring['keys'][name] = [dict(id=i, **wrap(keks[i], name, raw)) for i in ids]
    save_ring(ring)
    print('keyring.json created')


if __name__ == '__main__':
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    {'unlock': cmd_unlock, 'lock': cmd_lock, 'check': cmd_check}.get(a[0], lambda: None)()
    if a[0] == 'set-slot':
        cmd_set_slot(a[1], a[2:] or None)
    elif a[0] == 'init':
        cmd_init(a[1])
    elif a[0] not in ('unlock', 'lock', 'check'):
        sys.exit(__doc__)
