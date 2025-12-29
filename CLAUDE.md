# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a certificate generation and management tool built with Python. The project uses the `cryptography` library to generate X.509 certificates with various configurations including Root CAs, Intermediate CAs, and leaf certificates (CN). It also supports CSR signing and CRL generation.

## Development Commands

### Setup
```bash
uv sync
```

### Linting
```bash
uv run ruff check .
uv run ruff check --fix .
```

### Testing
```bash
# Run all tests
uv run pytest

# Run with verbose output
uv run pytest -v

# Run specific test file
uv run pytest tests/test_key_types.py

# Run specific test class
uv run pytest tests/test_cert_ops.py::TestCertGenBasic

# Run specific test
uv run pytest tests/test_cert_ops.py::TestCertGenBasic::test_generate_root_ca

# Run with coverage
uv run pytest --cov=cert_gen --cov-report=term-missing

# Run with HTML coverage report
uv run pytest --cov=cert_gen --cov-report=html

# Run with memory profiling
uv run pytest --memray

# Run performance benchmarks
uv run pytest --codspeed
```

### Run Example
```bash
uv run python -m cert_gen.cert_ops
```

## Architecture

### Core Module: `cert_gen/`

**`cert_ops.py`** - Main certificate operations class (`CertGen`)
- Generates certificates with customizable parameters (key type, key length, signing algorithm, validity periods)
- Manages certificate chains (Root → Intermediate → Leaf)
- Handles CSR signing and CRL generation
- Uses cryptography library's x509 module

**`cert_extensions.py`** - Extension definitions dictionary (`EXTENSIONS`)
- Defines three certificate types: "Root", "Intermediate", "Leaf"
- Each type has specific x509 extensions (BasicConstraints, KeyUsage, ExtendedKeyUsage)
- Extension configurations are stored as TypedDict with extension objects and criticality flags

### Test Suite: `tests/`

```
tests/
├── conftest.py           # Shared fixtures (cert_gen, temp_dir, cert_gen_with_root, etc.)
├── test_cert_ops.py      # Core certificate operations (init, validation, validity)
├── test_key_types.py     # All key types (Ed25519, Ed448, ECDSA, RSA, DSA)
├── test_cert_chain.py    # Certificate chain creation and hierarchy
├── test_cert_extensions.py # Extension configuration validation
└── test_csr_crl.py       # CSR signing and CRL generation
```

### Key Types

The library supports multiple cryptographic key types:

| Key Type | Algorithm | Key Size | Notes |
|----------|-----------|----------|-------|
| `ed25519` | Ed25519 (Curve25519) | Fixed 256-bit | **Default**, modern, fast |
| `ed448` | Ed448 (Curve448) | Fixed 448-bit | Higher security margin |
| `ecdsa` | ECDSA (SECP256R1) | Fixed 256-bit | Wide compatibility |
| `rsa` | RSA | 1024-4096 bit | Legacy, configurable size |
| `dsa` | DSA | 1024-4096 bit | Legacy, configurable size |

EdDSA keys (Ed25519/Ed448) use `None` as the hash algorithm parameter since they have built-in hashing.

### Certificate Hierarchy

The system enforces a strict certificate hierarchy:
1. **Root CA** (`cert_category="RootCA"`): Self-signed, stored in `self.rootca`
2. **Intermediate CA** (`cert_category="IntCA"`): Signed by Root CA, stored in `self.intca`
3. **Leaf/CN** (`cert_category="CN"`): Signed by Intermediate CA (if present) or Root CA

Only one Root CA and one Intermediate CA can exist per `CertGen` instance.

### Validity Periods
- Root CA: 10 years
- Intermediate CA: 5 years
- Leaf certificates: 825 days

### Extension System

Extensions are defined in `EXTENSIONS` dictionary:
```python
"CategoryName": {
    "type": "Root" | "Intermediate" | "Leaf",
    "parameters": [
        {"extension": x509.ExtensionObject, "critical": bool}
    ]
}
```

## Implementation Notes

### Key Serialization
All private keys are serialized using PKCS8 format (`PrivateFormat.PKCS8`) for compatibility with EdDSA keys. TraditionalOpenSSL format does not support Ed25519/Ed448.

### EdDSA Signing
When signing with Ed25519 or Ed448 keys, pass `None` as the hash algorithm:
```python
# For EdDSA keys
cert = builder.sign(private_key=key, algorithm=None)

# For RSA/DSA/ECDSA keys
cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
```

### File Handling
- Default output directory: `/tmp/` (configurable via `basedir` parameter)
- Certificate files: `.crt` extension
- Private keys: `.pem` extension
- CRL files: `.crl` extension

### Type Annotations
The codebase uses Python type hints throughout:
- Type aliases: `KeyType`, `HashAlgo`, `CertCategory`, `FormType`, `PathLike`
- TypedDict classes in `cert_extensions.py`: `ExtensionConfig`, `CertTypeConfig`
