# Linux and Windows CA storage design — 2026-09-18

Draft for implementation acceptance. The owner explicitly selected Linux and Windows. The backend, persistence, migration and fail-closed contract below is proposed for acceptance with the K track in the existing plan; no implementation occurred in planning.

Amended 2026-10-29 on the owner's instruction: customer names, customer infrastructure identifiers and references to unpublished files replaced; the design is unchanged.

## Scope and backend contract

Use Linux Secret Service with encrypted D-Bus sessions through dbus-secret-service 4.0.1 with crypto-rust. Require an unlocked default collection, check item lock state, and use a zero-second prompt timeout; never unlock/create a collection in production. The high-level keyring Linux adapter is unsuitable because it attempts unlocking. Use Windows Credential Manager GENERIC credentials via windows-sys 0.61.2 with CRED_PERSIST_LOCAL_MACHINE. Do not use the reviewed keyring Windows adapter because it fixes persistence to ENTERPRISE. macOS behavior remains unchanged. Unsupported systems and unavailable/locked/ambiguous/corrupt native storage deny startup; no plaintext fallback or opt-in is added.

This is CA secure storage, not general Windows feature parity. Linux needs an available user-session Secret Service; WSL/headless installations without it cannot start securely. The same-user attacker remains outside the existing boundary.

## Identity and persistence

A public random 128-bit account ID lives in .ca-storage-id beside the public ca.crt. The native entry contains a bounded versioned binary record with certificate and key PEM; secret-bearing types have no Debug/Display/Serialize and use zeroizing buffers. Windows records are at most 2560 bytes; use the same cap on Linux. Directory lock file .ca-storage.lock remains on disk and an OS exclusive lock serializes cooperating processes. Busy means deny/retry by caller, not an unbounded wait.

Migration must validate the existing key/certificate pair, store the native record, read it back and validate it, preserve the public identity, and only then remove ca.key.pem. Every failure preserves recoverable state and denies startup. A missing key behind an established certificate must never trigger silent CA replacement. Native record recovery may restore a missing public certificate. Corrupt or mismatched state is an error requiring explicit repair. No automatic pruning in this change; no deletion of other entries. Native test fixtures clean up their own exact account only.

## Validation and evidence

Use deterministic closure-injected storage failures and full migration state-table tests. Add real Secret Service and Windows Credential Manager integration, two-process locking tests, Windows persistence inspection, pre-migration trust/TLS validation and binary child-launch/denial tests. CI must execute native tests on both systems. Secret values may not appear in output, assertions, errors or process arguments.

Run zs-verify with a synthetic positive workload on supported scanner platforms and report incomplete vectors. The verifier scans an upstream credential, so it cannot by itself prove the CA storage mechanism. Preserve PRODUCT claims and document platform coverage limits rather than calling unavailable checks passing.

## Owners and release limits

[SECURITY](../SECURITY.md) owns trust/storage limits; [ARCHITECTURE](../ARCHITECTURE.md) owns modules; [DECISIONS](../DECISIONS.md) owns machine-local persistence. Removing a legacy key file does not remove backup/snapshot copies. Windows currently has no Unix 0600 enforcement from the existing restrict helper. Update owners from native evidence after implementation, not before it.

Exact tasks K1–K6 are in the implementation plan (not published).
