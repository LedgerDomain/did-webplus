# did-webplus-vdr-lib

Library implementing the reference VDR for `did:webplus`.  This crate is intended to house all VDR code that isn't `main.rs` and binary-specific things (e.g. docker files).  This way, an intra-process VDR can be spun up and used in integration tests.
