## 0.1.4 (2026-06-11)

### Fix

- Latin-1 gpg version parsing, nil-safe version checks, NODATA status (Linux compat)
- resolve gpg to absolute path in test probe so gated suites run under Xcode
- ownertrust via import-ownertrust, quick-add/delete subkeys, nested subkey/keygrip and search parsing
- embedded signatures by default, report generated keys, verify trust, validate passphrase before launch
- enable real gpg-agent in tests (short socket path, valid agent.conf)

## 0.1.3 (2026-05-28)

### Fix

- serialize test suites to unblock swift test under bump

## 0.1.2 (2026-05-28)

## 0.1.1 (2025-10-11)

### Fix

- make encoding mutable and add extraArgs

## 0.1.0 (2025-10-10)
