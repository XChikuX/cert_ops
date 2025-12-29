"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Generator

import pytest

from cert_gen.cert_ops import CertGen


@pytest.fixture
def cert_gen() -> CertGen:
    """Create a fresh CertGen instance."""
    return CertGen()


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test outputs."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def cert_gen_with_root(temp_dir: Path) -> tuple[CertGen, Path, Path]:
    """Create a CertGen instance with a Root CA already generated."""
    cg = CertGen()
    cert_path, key_path = cg.cert_gen(
        "TestRootCA",
        cert_category="RootCA",
        basedir=temp_dir
    )
    return cg, cert_path, key_path


@pytest.fixture
def cert_gen_with_chain(temp_dir: Path) -> tuple[CertGen, dict[str, tuple[Path, Path]]]:
    """Create a CertGen instance with full certificate chain (Root -> Int -> Leaf)."""
    cg = CertGen()
    certs: dict[str, tuple[Path, Path]] = {}

    # Generate Root CA
    certs["root"] = cg.cert_gen(
        "TestRootCA",
        cert_category="RootCA",
        basedir=temp_dir
    )

    # Generate Intermediate CA
    certs["int"] = cg.cert_gen(
        "TestIntCA",
        cert_category="IntCA",
        basedir=temp_dir
    )

    # Generate Leaf certificate
    certs["leaf"] = cg.cert_gen(
        "TestLeaf",
        cert_category="CN",
        basedir=temp_dir
    )

    return cg, certs


@pytest.fixture(params=["ed25519", "ed448", "ecdsa", "rsa", "dsa"])
def key_type(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture for all supported key types."""
    return request.param


@pytest.fixture(params=["sha256", "sha384", "sha512"])
def hash_algo(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture for supported hash algorithms.

    Note: SHA1 and SHA224 are excluded as SHA1 is no longer supported
    for signatures in modern cryptography versions.
    """
    return request.param


@pytest.fixture(params=["RootCA", "IntCA", "CN"])
def cert_category(request: pytest.FixtureRequest) -> str:
    """Parametrized fixture for certificate categories."""
    return request.param
