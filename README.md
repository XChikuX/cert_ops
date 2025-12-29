# Cert Ops

A Python library for generating X.509 certificates with support for modern elliptic curve cryptography.

## Features

- **Multiple Key Types**: Ed25519 (default), Ed448, ECDSA, RSA, and DSA
- **Certificate Hierarchy**: Root CA, Intermediate CA, and leaf certificates
- **Certificate Chains**: Build and export full certificate chains
- **CSR Signing**: Sign Certificate Signing Requests
- **CRL Generation**: Generate Certificate Revocation Lists

## Installation

```bash
# Using uv (recommended)
uv sync

# Or using pip
pip install -e .
```

## Quick Start

```python
from cert_gen.cert_ops import CertGen

# Create certificate generator
cg = CertGen()

# Generate a Root CA (Ed25519 by default)
root_cert, root_key = cg.cert_gen("MyRootCA", cert_category="RootCA")

# Generate an Intermediate CA
int_cert, int_key = cg.cert_gen("MyIntCA", cert_category="IntCA")

# Generate a leaf certificate
leaf_cert, leaf_key = cg.cert_gen("myserver.example.com", cert_category="CN")

# Create certificate chain
chain = cg.create_cert_chain(root_cert, cn_path=leaf_cert, int_path=int_cert)
```

## Key Types

```python
# Ed25519 (Curve25519) - Default, recommended
cg.cert_gen("cert", key_type="ed25519")

# Ed448 (Curve448)
cg.cert_gen("cert", key_type="ed448")

# ECDSA (SECP256R1)
cg.cert_gen("cert", key_type="ecdsa")

# RSA
cg.cert_gen("cert", key_type="rsa", key_length=4096)

# DSA
cg.cert_gen("cert", key_type="dsa", key_length=2048)
```

## Development

### Setup

```bash
# Clone and setup
git clone <repository>
cd cert_ops

# Install dependencies
uv sync
```

### Linting

```bash
# Check for issues
uv run ruff check .

# Auto-fix issues
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

# Run with coverage report
uv run pytest --cov=cert_gen --cov-report=term-missing

# Run with HTML coverage report
uv run pytest --cov=cert_gen --cov-report=html

# Run with memory profiling (requires pytest-memray)
uv run pytest --memray

# Run performance benchmarks (requires pytest-codspeed)
uv run pytest --codspeed
```

### Test Structure

```
tests/
├── conftest.py           # Shared fixtures
├── test_cert_ops.py      # Core certificate operations
├── test_key_types.py     # Key type support (Ed25519, ECDSA, etc.)
├── test_cert_chain.py    # Certificate chain operations
├── test_cert_extensions.py # Extension configurations
└── test_csr_crl.py       # CSR signing and CRL generation
```

## License

Apache 2.0
