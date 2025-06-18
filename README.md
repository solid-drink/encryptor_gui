# Encryptor GUI

Encryptor GUI is a lightweight Rust desktop app for hashing and encrypting/decrypting text using:

- MD5
- SHA256
- AES-256-CBC (with custom Key & IV)

## Features

- Simple, modern GUI with `eframe` (egui)
- MD5 & SHA256 hashing
- AES-256 encryption/decryption
- Manual input for Key (32 bytes) and IV (16 bytes)
- Copy output to clipboard

## Installation

### Requirements
- Rust (latest stable)

### Steps
```bash
git clone https://github.com/solid-drink/encryptor_gui.git
cd encryptor_gui
cargo run
```

To build release:
```bash
cargo build --release
```

## Usage

1. Type or paste your input text
2. Select a method (MD5, SHA256, AES Encrypt, AES Decrypt)
3. For AES, input 32-byte key and 16-byte IV
4. Click `Proses`
5. Copy output using `📋 Copy` button

## Dependencies

- eframe / egui
- aes
- block-modes
- sha2
- md5
- hex

## Notes

- AES uses CBC mode with PKCS7 padding
- Key/IV must match required byte lengths

## License

MIT

---

Made with ❤️ by [@solid-drink](https://github.com/solid-drink)

