"""Tests for different key type support."""

from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448

from cert_gen.cert_ops import CertGen


class TestEd25519Keys:
    """Tests for Ed25519 (Curve25519) key support."""

    def test_generate_ed25519_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating Root CA with Ed25519 key."""
        cert_path, key_path = cert_gen.cert_gen(
            "Ed25519Root",
            key_type="ed25519",
            cert_category="RootCA",
            basedir=temp_dir
        )

        # Verify key type
        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, ed25519.Ed25519PrivateKey)

    def test_ed25519_is_default(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that Ed25519 is the default key type."""
        cert_path, key_path = cert_gen.cert_gen(
            "DefaultKey",
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, ed25519.Ed25519PrivateKey)

    def test_ed25519_ignores_key_length(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test that Ed25519 ignores key_length parameter (fixed size)."""
        cert_path, key_path = cert_gen.cert_gen(
            "Ed25519Fixed",
            key_type="ed25519",
            key_length=2048,  # Should be ignored
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, ed25519.Ed25519PrivateKey)

    def test_ed25519_full_chain(self, temp_dir: Path) -> None:
        """Test full certificate chain with Ed25519 keys."""
        cg = CertGen()

        # Generate full chain
        root_cert, root_key = cg.cert_gen("Root", key_type="ed25519", cert_category="RootCA", basedir=temp_dir)
        int_cert, int_key = cg.cert_gen("Int", key_type="ed25519", cert_category="IntCA", basedir=temp_dir)
        leaf_cert, leaf_key = cg.cert_gen("Leaf", key_type="ed25519", cert_category="CN", basedir=temp_dir)

        # Verify all keys are Ed25519
        for key_path in [root_key, int_key, leaf_key]:
            with open(key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            assert isinstance(key, ed25519.Ed25519PrivateKey)


class TestEd448Keys:
    """Tests for Ed448 (Curve448) key support."""

    def test_generate_ed448_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating Root CA with Ed448 key."""
        cert_path, key_path = cert_gen.cert_gen(
            "Ed448Root",
            key_type="ed448",
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, ed448.Ed448PrivateKey)

    def test_ed448_full_chain(self, temp_dir: Path) -> None:
        """Test full certificate chain with Ed448 keys."""
        cg = CertGen()

        root_cert, root_key = cg.cert_gen("Root", key_type="ed448", cert_category="RootCA", basedir=temp_dir)
        int_cert, int_key = cg.cert_gen("Int", key_type="ed448", cert_category="IntCA", basedir=temp_dir)
        leaf_cert, leaf_key = cg.cert_gen("Leaf", key_type="ed448", cert_category="CN", basedir=temp_dir)

        for key_path in [root_key, int_key, leaf_key]:
            with open(key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            assert isinstance(key, ed448.Ed448PrivateKey)


class TestECDSAKeys:
    """Tests for ECDSA key support."""

    def test_generate_ecdsa_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating Root CA with ECDSA key."""
        cert_path, key_path = cert_gen.cert_gen(
            "ECDSARoot",
            key_type="ecdsa",
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)

    def test_ecdsa_full_chain(self, temp_dir: Path) -> None:
        """Test full certificate chain with ECDSA keys."""
        cg = CertGen()

        root_cert, root_key = cg.cert_gen("Root", key_type="ecdsa", cert_category="RootCA", basedir=temp_dir)
        int_cert, int_key = cg.cert_gen("Int", key_type="ecdsa", cert_category="IntCA", basedir=temp_dir)
        leaf_cert, leaf_key = cg.cert_gen("Leaf", key_type="ecdsa", cert_category="CN", basedir=temp_dir)

        for key_path in [root_key, int_key, leaf_key]:
            with open(key_path, "rb") as f:
                key = serialization.load_pem_private_key(f.read(), password=None)
            assert isinstance(key, ec.EllipticCurvePrivateKey)


class TestRSAKeys:
    """Tests for RSA key support."""

    def test_generate_rsa_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating Root CA with RSA key."""
        cert_path, key_path = cert_gen.cert_gen(
            "RSARoot",
            key_type="rsa",
            key_length=2048,
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    @pytest.mark.parametrize("key_length", [1024, 2048, 4096])
    def test_rsa_key_lengths(self, cert_gen: CertGen, temp_dir: Path, key_length: int) -> None:
        """Test different RSA key lengths."""
        cert_path, key_path = cert_gen.cert_gen(
            f"RSA{key_length}",
            key_type="rsa",
            key_length=key_length,
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == key_length


class TestDSAKeys:
    """Tests for DSA key support."""

    def test_generate_dsa_root_ca(self, cert_gen: CertGen, temp_dir: Path) -> None:
        """Test generating Root CA with DSA key."""
        cert_path, key_path = cert_gen.cert_gen(
            "DSARoot",
            key_type="dsa",
            key_length=2048,
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert isinstance(key, dsa.DSAPrivateKey)
        assert key.key_size == 2048


class TestMixedKeyChains:
    """Tests for certificate chains with mixed key types."""

    def test_ed25519_root_rsa_leaf(self, temp_dir: Path) -> None:
        """Test Ed25519 Root CA signing RSA leaf certificate."""
        cg = CertGen()

        root_cert, root_key = cg.cert_gen("Root", key_type="ed25519", cert_category="RootCA", basedir=temp_dir)
        leaf_cert, leaf_key = cg.cert_gen("Leaf", key_type="rsa", cert_category="CN", basedir=temp_dir)

        # Verify root is Ed25519
        with open(root_key, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(key, ed25519.Ed25519PrivateKey)

        # Verify leaf is RSA
        with open(leaf_key, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(key, rsa.RSAPrivateKey)

    def test_rsa_root_ecdsa_int_ed25519_leaf(self, temp_dir: Path) -> None:
        """Test mixed key types across full chain."""
        cg = CertGen()

        root_cert, root_key = cg.cert_gen("Root", key_type="rsa", key_length=2048, cert_category="RootCA", basedir=temp_dir)
        int_cert, int_key = cg.cert_gen("Int", key_type="ecdsa", cert_category="IntCA", basedir=temp_dir)
        leaf_cert, leaf_key = cg.cert_gen("Leaf", key_type="ed25519", cert_category="CN", basedir=temp_dir)

        # Verify each key type
        with open(root_key, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(key, rsa.RSAPrivateKey)

        with open(int_key, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(key, ec.EllipticCurvePrivateKey)

        with open(leaf_key, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert isinstance(key, ed25519.Ed25519PrivateKey)


class TestAllKeyTypesParametrized:
    """Parametrized tests for all key types."""

    def test_all_key_types_generate_valid_certs(
        self, cert_gen: CertGen, temp_dir: Path, key_type: str
    ) -> None:
        """Test that all key types generate valid certificates."""
        cert_path, key_path = cert_gen.cert_gen(
            f"Test{key_type}",
            key_type=key_type,
            cert_category="RootCA",
            basedir=temp_dir
        )

        # Verify certificate exists and is valid
        assert cert_path.exists()
        assert key_path.exists()

        with open(cert_path, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read())

        assert cert is not None
        assert cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value == f"Test{key_type}"

    def test_all_key_types_load_private_key(
        self, cert_gen: CertGen, temp_dir: Path, key_type: str
    ) -> None:
        """Test that all key types produce loadable private keys."""
        _, key_path = cert_gen.cert_gen(
            f"Test{key_type}",
            key_type=key_type,
            cert_category="RootCA",
            basedir=temp_dir
        )

        with open(key_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)

        assert key is not None
