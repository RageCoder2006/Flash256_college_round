# Security of the platform

Loopback-only services; per-role bearer tokens (constant-time compare, failed-token throttle); security headers; request limits and timeouts;
hash-chained audit log of state-changing requests (`avhsol auditlog`); Ed25519-signed, hash-chained traces; databases reject anonymous access;
credentials in a mode-600 file outside git; non-root containers with capabilities dropped; secrets redacted before storage; attacker text escaped on render.

Known limits: the sandbox shares the host kernel (use a microVM/gVisor for hostile agents); no TLS on the database ports; single-user token model;
the offline embedder matches wording not meaning.
