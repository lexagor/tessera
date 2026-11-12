# Fuzzing

Structural fuzz targets for the broker's parsing/signing/hashing boundaries. Uses
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (requires nightly).

```bash
cargo install cargo-fuzz
cd apps/broker
cargo +nightly fuzz run canonical
cargo +nightly fuzz run cel
cargo +nightly fuzz run merkle
cargo +nightly fuzz run rlp
cargo +nightly fuzz run receipt

# list / coverage
cargo +nightly fuzz list
cargo +nightly fuzz coverage canonical
```

Targets:

| Target | Property |
|---|---|
| `canonical` | canonical JSON is idempotent |
| `cel` | CEL evaluation never panics |
| `merkle` | every inclusion proof verifies |
| `rlp` | RLP length prefixes follow the spec |
| `receipt` | receipt parse + payload hash + recovery never panic |

Corpus/artifacts/crashes under `fuzz/` are gitignored.
