# kryoto-messaging

The end-to-end encryption behind Kryoto chat. Desktop links it natively; the web client runs the
same code as WebAssembly. No cryptography is written anywhere else.

**Kryoto** · Rust · MIT · [All repos](https://github.com/Kryoto-Dev)

## Quick start

```bash
cargo test --workspace
```

The SQLCipher store builds OpenSSL from source and needs a full Perl (Strawberry Perl on Windows).
Without one, test against plain SQLite (not encrypted, refuses release builds):

```bash
cargo test -p km-store-sqlcipher --no-default-features --features plain-sqlite-dev
```

## Layout

| Crate | What it is |
|---|---|
| `km-proto` | wire formats (protobuf via `prost`) |
| `km-core` | keys, cross-signing, Olm sessions, sealed envelopes, safety numbers. No I/O |
| `km-store-sqlcipher` | Desktop's encrypted database for that state |
| `km-wasm` | the web client's binding (`wasm-bindgen`) |

Every primitive comes from a reviewed library: vodozemac (Olm / Double Ratchet), RFC 9180 HPKE,
Ed25519, XChaCha20-Poly1305 and SQLCipher.

## Checks

```bash
cargo test --workspace
cargo test -p km-core --target wasm32-unknown-unknown --test wasm   # inside WebAssembly (Node)
```

The WebAssembly test and build need `rustup target add wasm32-unknown-unknown` and
`cargo install wasm-bindgen-cli --version <the version in Cargo.lock>`. Desktop's
`pnpm web:wasm` builds the module.

## Security

Please do not open a public issue. Email hello@kryo.to with "security" in the subject.

## License

[MIT](LICENSE).
