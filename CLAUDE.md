# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a certificate generation and management tool built with Python. The project uses the `cryptography` library (via pyOpenSSL) to generate X.509 certificates with various configurations including Root CAs, Intermediate CAs, and leaf certificates (CN). It also supports CSR signing and CRL generation.

## Development Environment

### Setup
```bash
# Install dependencies using uv (project uses uv for package management)
uv sync

# Activate virtual environment
source .venv/bin/activate
```

### Linting
```bash
# Run ruff for linting
ruff check .

# Auto-fix issues
ruff check --fix .
```

### Testing
The project includes a runnable example in the `__main__` block of `cert_gen/cert_ops.py`:
```bash
python -m cert_gen.cert_ops
```

## Architecture

### Core Module: `cert_gen/`

The package is structured around two main files:

**`cert_ops.py`** - Main certificate operations class (`CertGen`)
- Generates certificates with customizable parameters (key length, signing algorithm, validity periods)
- Manages certificate chains (Root → Intermediate → Leaf)
- Handles CSR signing and CRL generation
- Uses cryptography library's x509 module (migrated from legacy pyOpenSSL)

**`cert_extensions.py`** - Extension definitions dictionary (`EXTENSIONS`)
- Defines three certificate types: "Root", "Intermediate", "Leaf"
- Each type has specific x509 extensions (BasicConstraints, KeyUsage, ExtendedKeyUsage)
- Extension configurations are stored as dictionaries with extension objects and criticality flags

### Certificate Hierarchy

The system enforces a strict certificate hierarchy:
1. **Root CA** (`cert_category="RootCA"`): Self-signed, stored in `self.rootca`
2. **Intermediate CA** (`cert_category="IntCA"`): Signed by Root CA, stored in `self.intca`
3. **Leaf/CN** (`cert_category="CN"`): Signed by either Intermediate CA (if present) or Root CA

Only one Root CA and one Intermediate CA can exist per `CertGen` instance. The signing logic automatically selects the appropriate issuer for leaf certificates.

### Key Design Patterns

**Serial Number Management**: The `__allocate_serial_number()` method maintains a counter for certificate serial numbers. Each certificate gets a unique serial number within a `CertGen` instance.

**Certificate Chain Creation**: The `create_cert_chain()` method assembles PEM-formatted certificate chains by concatenating CN → IntCA → RootCA in the correct order for TLS/SSL usage.

**Validity Periods**: Different certificate types have different default validity periods:
- Root CA: 10 years (configurable via `self.validityEndInSeconds`)
- Intermediate CA: 5 years (half of root validity)
- Leaf certificates: 825 days (Apple's certificate lifetime requirement)

### Extension System

Extensions are defined in `EXTENSIONS` dictionary with this structure:
```python
"CategoryName": {
    "type": "Root" | "Intermediate" | "Leaf",
    "parameters": [
        {
            "extension": x509.ExtensionObject,
            "critical": bool
        }
    ]
}
```

To add new certificate types, add entries to this dictionary following the same pattern.

## Important Implementation Notes

### cryptography Library Migration
The code uses the modern `cryptography` library's x509 module, not the legacy pyOpenSSL API (despite the pyOpenSSL dependency). When working with certificates:
- Use `cryptography.x509` for certificate operations
- Use `cryptography.hazmat.primitives` for key generation and hashing
- Private keys are generated without encryption (`NoEncryption()`)

### File Handling
- Default output directory: `/tmp/` (configurable via `basedir` parameter)
- Certificate files use `.crt` extension
- Private keys use `.pem` extension
- The `obj2pem()` method handles serialization to PEM format

### Timezone Handling
All datetime objects must be timezone-aware (UTC). The code uses `timezone.utc` for all timestamp operations:
```python
datetime.now(timezone.utc)
```

### Hash Algorithm Mapping
Hash algorithms are specified as strings ("sha1", "sha224", "sha256", "sha384", "sha512") and mapped to `cryptography.hazmat.primitives.hashes` objects internally.
