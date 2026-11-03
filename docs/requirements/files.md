# Large files

### REQ-FILE-001: Encrypted chunked blobs

- **Priority:** must | **Phase:** 7 | **Status:** proposed | **Verify:** test | **Source:** design §Large files

Files must be encrypted with a random key, split into hashed chunks, and
referenced by a `file-ref` object that travels through the normal change flow.

### REQ-FILE-002: Fetch from any peer

- **Priority:** must | **Phase:** 7 | **Status:** proposed | **Verify:** test | **Source:** design §Large files

Chunks must be verifiable against their hash so any peer can serve them;
devices may fetch lazily or eagerly.
